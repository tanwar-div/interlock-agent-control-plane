"""Durable incident orchestration.

An incident is a state machine, not a conversation. Each phase is executed as a
separate agent run and is bracketed by a durable checkpoint in Firestore, so
the unit of recovery is the phase: if the process handling an incident dies —
a Cloud Run instance is recycled, a deploy rolls, a region blips — a later
process reads the checkpoint and continues from the last completed phase rather
than starting again or, worse, re-applying a change that already landed.

The state machine also constrains the agents. A phase cannot be skipped and the
model cannot invent a transition, because transitions are performed by this
module and not by anything the model emits.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from typing import Any

from google.adk.apps._configs import EventsCompactionConfig, ResumabilityConfig
from google.adk.apps.app import App
from google.adk.runners import Runner
from google.adk.sessions import BaseSessionService, InMemorySessionService
from google.genai import types

from interlock.armor.guard import get_guard
from interlock.common.config import get_settings
from interlock.common.models import (
    Alert,
    ApprovalRequest,
    AuditVerdict,
    Checkpoint,
    Incident,
    IncidentState,
    LedgerEventType,
    new_id,
    utcnow,
)
from interlock.common.store import DocumentStore, get_store
from interlock.identity.registry import AgentRegistry
from interlock.ledger.ledger import Ledger
from interlock.memory.service import (
    KIND_FAULT,
    KIND_REMEDIATION,
    IncidentMemory,
    InterlockMemoryService,
)
from interlock.policy.engine import PolicyEngine
from interlock.runtime.governed import action_types_for
from interlock.runtime.plugin import InterlockPlugin
from interlock.workers.agents import FLEET_SPEC

logger = logging.getLogger(__name__)

APP_NAME = "interlock"

# Consecutive failures of one phase before the incident is abandoned rather
# than retried indefinitely.
_MAX_PHASE_FAILURES = 3

# Errors worth waiting out rather than giving up on. Quota exhaustion, upstream
# unavailability and deadline overruns say "not now"; a schema violation or a
# missing permission says "not ever". Spending the same three-strike budget on
# both means a busy afternoon looks identical to a broken deployment.
_RETRYABLE_MARKERS = (
    "429", "RESOURCE_EXHAUSTED", "quota",
    "503", "UNAVAILABLE", "504", "DEADLINE_EXCEEDED",
    "InternalServerError", "500 INTERNAL",
)


def _is_retryable(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}"
    return any(marker.lower() in text.lower() for marker in _RETRYABLE_MARKERS)


def _parse(value: Any) -> dt.datetime:
    """Parse a stored ISO timestamp, treating anything unreadable as very old."""
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    try:
        parsed = dt.datetime.fromisoformat(str(value))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
    except (TypeError, ValueError):
        return dt.datetime.min.replace(tzinfo=dt.UTC)

# Which agent runs in which state, and where the machine goes next.
_PHASE_AGENT = {
    IncidentState.TRIAGING: "triage",
    IncidentState.INVESTIGATING: "investigator",
    IncidentState.PLANNING: "remediation",
    IncidentState.VERIFYING: "auditor",
}

_NEXT_STATE = {
    IncidentState.RECEIVED: IncidentState.TRIAGING,
    IncidentState.TRIAGING: IncidentState.INVESTIGATING,
    IncidentState.INVESTIGATING: IncidentState.PLANNING,
    IncidentState.PLANNING: IncidentState.VERIFYING,
    IncidentState.VERIFYING: IncidentState.RESOLVED,
}


class OrchestratorError(RuntimeError):
    pass


class IncidentOrchestrator:
    def __init__(
        self,
        *,
        store: DocumentStore | None = None,
        session_service: BaseSessionService | None = None,
    ) -> None:
        self._settings = get_settings()
        self._store = store or get_store()
        self._ledger = Ledger(self._store)
        self._registry = AgentRegistry(self._store)
        self._policy = PolicyEngine()
        self._guard = get_guard()
        self._sessions = session_service or self._build_session_service()
        self._memory = IncidentMemory(self._store)
        self._memory_service = InterlockMemoryService(self._memory)
        self._agent_keys: dict[str, str] = {}
        self._cards: dict[str, Any] = {}
        self._agents: dict[str, Any] = {}
        self._apps: dict[str, App] = {}
        self._plugin: InterlockPlugin | None = None
        self._ready = False

    def _build_session_service(self) -> BaseSessionService:
        url = getattr(self._settings, "session_db_url", "")
        if url:
            try:
                from google.adk.sessions import DatabaseSessionService

                logger.info("using DatabaseSessionService for ADK sessions")
                return DatabaseSessionService(db_url=url)
            except Exception as exc:
                logger.warning("could not open session database (%s); using in-memory sessions", exc)
        # Phase-level durability lives in Firestore, so in-memory ADK sessions
        # are sufficient: a resumed run rebuilds its session from the
        # checkpoint rather than replaying a stored transcript.
        return InMemorySessionService()

    # -- setup -------------------------------------------------------------

    async def ensure_ready(self) -> None:
        """Register fleet identities and construct agents. Idempotent."""
        if self._ready:
            return
        for spec in FLEET_SPEC:
            tool_names = [t.__name__ for t in spec["tools"]]
            card, private_pem = await self._registry.register(
                name=spec["name"],
                namespace="sre",
                display_name=spec["display_name"],
                allowed_tools=action_types_for(tool_names),
                max_severity=spec["max_severity"],
            )
            self._cards[spec["name"]] = card
            self._agent_keys[card.spiffe_id] = private_pem
            self._agents[spec["name"]] = spec["builder"]()

        self._plugin = InterlockPlugin(
            registry=self._registry,
            agent_keys=self._agent_keys,
            ledger=self._ledger,
            policy=self._policy,
            guard=self._guard,
            store=self._store,
        )
        # Each agent is wrapped in an ADK App so that compaction and
        # resumability are properties of the deployment rather than something
        # each phase has to remember to do.
        compaction = (
            EventsCompactionConfig(
                compaction_interval=self._settings.compaction_interval,
                overlap_size=self._settings.compaction_overlap,
            )
            if self._settings.compaction_enabled
            else None
        )
        for spec in FLEET_SPEC:
            key = spec["name"]
            self._apps[key] = App(
                name=f"{APP_NAME}-{key}",
                root_agent=self._agents[key],
                plugins=[self._plugin],
                events_compaction_config=compaction,
                resumability_config=ResumabilityConfig(is_resumable=self._settings.adk_resumable),
            )

        self._ready = True
        logger.info(
            "fleet ready: %s (compaction=%s, resumable=%s)",
            ", ".join(self._cards),
            "every %d events" % self._settings.compaction_interval
            if self._settings.compaction_enabled else "off",
            self._settings.adk_resumable,
        )

    # -- persistence -------------------------------------------------------

    async def _save(self, incident: Incident) -> None:
        incident.updated_at = utcnow()
        incident.revision += 1
        await self._store.put(
            self._settings.collection_incidents,
            incident.incident_id,
            incident.model_dump(mode="json"),
        )

    async def get_incident(self, incident_id: str) -> Incident | None:
        raw = await self._store.get(self._settings.collection_incidents, incident_id)
        return Incident.model_validate(raw) if raw else None

    async def _checkpoint(self, incident: Incident, payload: dict[str, Any]) -> Checkpoint:
        checkpoint = Checkpoint(
            incident_id=incident.incident_id,
            state=incident.state,
            revision=incident.revision,
            session_id=incident.session_id,
            payload=payload,
        )
        await self._store.put(
            self._settings.collection_checkpoints,
            checkpoint.checkpoint_id,
            checkpoint.model_dump(mode="json"),
        )
        await self._ledger.append(
            incident_id=incident.incident_id,
            event_type=LedgerEventType.CHECKPOINT_WRITTEN,
            actor="interlock/orchestrator",
            payload={
                "checkpoint_id": checkpoint.checkpoint_id,
                "state": incident.state.value,
                "revision": incident.revision,
            },
        )
        return checkpoint

    async def latest_checkpoint(self, incident_id: str) -> Checkpoint | None:
        rows = await self._store.query(
            self._settings.collection_checkpoints,
            where=[("incident_id", "==", incident_id)],
        )
        if not rows:
            return None
        rows.sort(key=lambda r: (int(r.get("revision", 0)), str(r.get("created_at", ""))))
        return Checkpoint.model_validate(rows[-1])

    # -- concurrency -------------------------------------------------------

    async def _acquire_lease(self, incident_id: str, *, ttl_seconds: int = 600) -> str | None:
        """Claim exclusive right to advance an incident.

        Pub/Sub is at-least-once, so the same advance message can arrive at two
        instances at once. Without this, both would run the same phase and the
        remediation could be applied twice. The lease is taken inside a
        transaction so exactly one caller wins.

        Returns the lease token on success, or None if someone else holds it.
        """
        token = new_id("lease")
        now = utcnow()
        collection = self._settings.collection_incidents

        def _txn(view: Any) -> str | None:
            raw = view.get(collection, incident_id)
            if raw is None:
                return None
            held_until = raw.get("lease_until")
            if held_until and _parse(held_until) > now:
                return None
            raw["lease_until"] = (now + dt.timedelta(seconds=ttl_seconds)).isoformat()
            raw["lease_owner"] = token
            view.put(collection, incident_id, raw)
            return token

        return await self._store.transact(_txn)

    async def _release_lease(self, incident_id: str, token: str) -> None:
        collection = self._settings.collection_incidents

        def _txn(view: Any) -> None:
            raw = view.get(collection, incident_id)
            # Only clear a lease we still hold; a lease that already expired and
            # was reclaimed by someone else must not be cleared from under them.
            if raw is not None and raw.get("lease_owner") == token:
                raw["lease_until"] = None
                raw["lease_owner"] = ""
                view.put(collection, incident_id, raw)

        await self._store.transact(_txn)

    # -- lifecycle ---------------------------------------------------------

    async def open_incident(self, alert: Alert) -> Incident:
        await self.ensure_ready()
        incident = Incident(alert=alert, state=IncidentState.RECEIVED)
        incident.session_id = f"sess_{incident.incident_id}"
        await self._save(incident)
        await self._ledger.append(
            incident_id=incident.incident_id,
            event_type=LedgerEventType.INCIDENT_OPENED,
            actor="interlock/orchestrator",
            payload={
                "alert_id": alert.alert_id,
                "title": alert.title,
                "resource": alert.resource_name,
                "severity": alert.severity,
                "source": alert.source,
            },
        )
        logger.info("opened incident %s for alert '%s'", incident.incident_id, alert.title)
        return incident

    async def _transition(self, incident: Incident, new_state: IncidentState, note: str = "") -> None:
        previous = incident.state
        incident.state = new_state
        if new_state.terminal:
            incident.closed_at = utcnow()
        await self._save(incident)
        await self._ledger.append(
            incident_id=incident.incident_id,
            event_type=LedgerEventType.STATE_TRANSITION,
            actor="interlock/orchestrator",
            payload={"from": previous.value, "to": new_state.value, "note": note},
        )

    # -- agent execution ---------------------------------------------------

    async def _run_agent(
        self, *, agent_key: str, incident: Incident, brief: str, session_suffix: str
    ) -> str:
        """Run one agent to completion and return its final text output."""
        assert self._plugin is not None
        card = self._cards[agent_key]

        # Unique per attempt: a redelivered or retried phase must not collide
        # with the session its predecessor created.
        session_id = f"{incident.session_id}_{session_suffix}_{incident.revision}_{uuid.uuid4().hex[:6]}"
        initial_state = {
            "incident_id": incident.incident_id,
            "actor_spiffe": card.spiffe_id,
            "incident_state": incident.state.value,
        }
        app_name = self._apps[agent_key].name
        await self._sessions.create_session(
            app_name=app_name,
            user_id=incident.incident_id,
            session_id=session_id,
            state=initial_state,
        )

        runner = Runner(
            app=self._apps[agent_key],
            session_service=self._sessions,
            memory_service=self._memory_service,
        )

        message = types.Content(role="user", parts=[types.Part(text=brief)])
        chunks: list[str] = []
        try:
            async for event in runner.run_async(
                user_id=incident.incident_id, session_id=session_id, new_message=message
            ):
                content = getattr(event, "content", None)
                if content and getattr(content, "parts", None):
                    for part in content.parts:
                        text = getattr(part, "text", None)
                        if text:
                            chunks.append(text)
        except Exception as exc:
            logger.exception("agent %s failed", agent_key)
            await self._ledger.append(
                incident_id=incident.incident_id,
                event_type=LedgerEventType.ACTION_FAILED,
                actor=card.spiffe_id,
                payload={"phase": agent_key, "error": str(exc)[:900]},
            )

            if await self.record_phase_failure(incident, agent_key, exc):
                return ""
            raise

        # Read back terminal intent the tools may have written into state.
        session = await self._sessions.get_session(
            app_name=app_name, user_id=incident.incident_id, session_id=session_id
        )
        if session is not None:
            state = dict(session.state or {})
            if state.get("terminal_intent"):
                incident.resolution = state.get("resolution", incident.resolution)
                incident.escalation_reason = state.get(
                    "escalation_reason", incident.escalation_reason
                )
                incident.findings = incident.findings or []
                await self._store.patch(
                    self._settings.collection_incidents,
                    incident.incident_id,
                    {
                        "resolution": incident.resolution,
                        "escalation_reason": incident.escalation_reason,
                        "terminal_intent": state["terminal_intent"],
                    },
                )
        return "\n".join(chunks).strip()

    async def record_phase_failure(
        self, incident: Incident, agent_key: str, exc: Exception
    ) -> bool:
        """Count a phase failure; abandon the incident once they stop being news.

        Retrying is the right response to a transient fault and the wrong one to
        a deterministic fault. Returns True when the incident has been given up
        on, in which case the caller must not re-raise.
        """
        if _is_retryable(exc):
            # Let Pub/Sub redeliver with its own backoff, and let the sweeper
            # pick the incident up if delivery is exhausted. Nothing is durably
            # lost: the phase has not been marked as having failed.
            logger.warning(
                "phase %s hit a transient fault (%s); leaving it for redelivery",
                agent_key, str(exc)[:120],
            )
            return False

        raw = await self._store.get(
            self._settings.collection_incidents, incident.incident_id
        ) or {}
        failures = dict(raw.get("phase_failures") or {})
        failures[agent_key] = int(failures.get(agent_key, 0)) + 1
        await self._store.patch(
            self._settings.collection_incidents,
            incident.incident_id,
            {"phase_failures": failures},
        )
        if failures[agent_key] < _MAX_PHASE_FAILURES:
            return False

        incident.escalation_reason = (
            f"The {agent_key} phase failed {failures[agent_key]} times in a row and was "
            f"abandoned. Last error: {str(exc)[:400]}"
        )
        await self._transition(
            incident, IncidentState.FAILED, f"{agent_key} phase failed repeatedly"
        )
        await self._close(incident)
        return True

    # -- briefs ------------------------------------------------------------

    async def _brief(self, incident: Incident, phase: IncidentState) -> str:
        alert = incident.alert
        recall = await self._memory.recall_brief(service=alert.resource_name)
        header = (
            f"INCIDENT {incident.incident_id}\n"
            f"Alert: {alert.title}\n"
            f"Severity: {alert.severity}\n"
            f"Resource: {alert.resource_type} {alert.resource_name}\n"
            f"Description: {alert.description}\n"
        )
        findings = "\n".join(f"- {f}" for f in incident.findings) or "- (none yet)"

        memory_block = f"\n{recall}\n" if recall else ""

        if phase is IncidentState.TRIAGING:
            return header + memory_block + "\nTriage this alert."
        if phase is IncidentState.INVESTIGATING:
            return (
                header
                + memory_block
                + f"\nTriage findings so far:\n{findings}\n\n"
                "Investigate and establish what is actually happening."
            )
        if phase is IncidentState.PLANNING:
            return (
                header
                + memory_block
                + f"\nInvestigation findings:\n{findings}\n\n"
                "Decide on and carry out the smallest safe remediation, or escalate."
            )
        if phase is IncidentState.VERIFYING:
            return (
                f"INCIDENT {incident.incident_id}\n"
                f"Service under audit: {alert.resource_name}\n\n"
                f"CLAIM MADE BY THE REMEDIATION AGENT:\n{incident.resolution or '(no claim recorded)'}\n\n"
                "Determine from the live system whether this claim is true. "
                "Respond with the JSON object described in your instructions."
            )
        return header

    # -- the state machine -------------------------------------------------

    async def advance(self, incident_id: str) -> Incident:
        """Execute exactly one phase and checkpoint the result."""
        await self.ensure_ready()
        incident = await self.get_incident(incident_id)
        if incident is None:
            raise OrchestratorError(f"unknown incident {incident_id}")
        if incident.state.terminal:
            return incident
        if incident.state is IncidentState.AWAITING_APPROVAL:
            return incident

        lease = await self._acquire_lease(incident_id)
        if lease is None:
            logger.info("incident %s is already being advanced elsewhere; skipping", incident_id)
            return incident

        try:
            return await self._advance_locked(incident_id, incident)
        finally:
            await self._release_lease(incident_id, lease)

    async def _advance_locked(self, incident_id: str, incident: Incident) -> Incident:
        if incident.state is IncidentState.RECEIVED:
            await self._transition(incident, IncidentState.TRIAGING, "beginning triage")

        phase = incident.state
        agent_key = _PHASE_AGENT.get(phase)
        if agent_key is None:
            raise OrchestratorError(f"no agent is defined for state {phase.value}")

        await self._checkpoint(incident, {"phase": phase.value, "stage": "start"})

        output = await self._run_agent(
            agent_key=agent_key,
            incident=incident,
            brief=await self._brief(incident, phase),
            session_suffix=phase.value.lower(),
        )

        # The phase may have abandoned the incident rather than raising.
        refreshed = await self.get_incident(incident_id)
        if refreshed is not None and refreshed.state.terminal:
            return refreshed

        # Re-read: tools mutate the incident document underneath us.
        incident = await self.get_incident(incident_id) or incident

        if phase is IncidentState.VERIFYING:
            verdict = self._parse_audit(output, incident)
            await self._store.put(
                "audits", f"{incident_id}__{incident.revision}", verdict.model_dump(mode="json")
            )
            await self._ledger.append(
                incident_id=incident_id,
                event_type=LedgerEventType.AUDIT_VERDICT,
                actor="spiffe://%s/ns/sre/agent/auditor" % self._settings.trust_domain,
                payload=verdict.model_dump(mode="json"),
            )
            if verdict.confirmed:
                await self._transition(incident, IncidentState.RESOLVED, "audit confirmed recovery")
            else:
                incident.escalation_reason = (
                    "Independent audit did not confirm the claimed remediation: "
                    + "; ".join(verdict.discrepancies or [verdict.narrative])[:600]
                )
                await self._transition(
                    incident, IncidentState.ESCALATED, "audit rejected the remediation claim"
                )
            await self._checkpoint(incident, {"phase": phase.value, "stage": "complete"})
            await self._close(incident)
            return incident

        # A tool may have parked an approval, which stops autonomous progress.
        incident = await self.get_incident(incident_id) or incident
        if incident.pending_approval_id:
            await self._transition(
                incident,
                IncidentState.AWAITING_APPROVAL,
                f"awaiting approval {incident.pending_approval_id}",
            )
            await self._checkpoint(incident, {"phase": phase.value, "stage": "awaiting_approval"})
            return incident

        raw = await self._store.get(self._settings.collection_incidents, incident_id) or {}
        intent = raw.get("terminal_intent")
        if intent == "ESCALATED":
            await self._transition(incident, IncidentState.ESCALATED, "agent escalated")
            await self._close(incident)
            return incident
        if intent == "RESOLVED" and phase is IncidentState.PLANNING:
            # A claim of success is not success. Verification is mandatory.
            await self._transition(
                incident, IncidentState.VERIFYING, "remediation claimed; sending for audit"
            )
            await self._checkpoint(incident, {"phase": phase.value, "stage": "complete"})
            return incident

        next_state = _NEXT_STATE.get(phase)
        if next_state is None:
            raise OrchestratorError(f"no transition defined from {phase.value}")
        await self._transition(incident, next_state, f"{phase.value.lower()} complete")
        await self._checkpoint(incident, {"phase": phase.value, "stage": "complete"})
        return incident

    def _parse_audit(self, output: str, incident: Incident) -> AuditVerdict:
        auditor = f"spiffe://{self._settings.trust_domain}/ns/sre/agent/auditor"
        text = (output or "").strip()
        if "```" in text:
            segments = [s for s in text.split("```") if "{" in s]
            if segments:
                text = segments[0].replace("json", "", 1).strip()
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                data = json.loads(text[start : end + 1])
                return AuditVerdict(
                    proposal_id=incident.incident_id,
                    confirmed=bool(data.get("confirmed", False)),
                    observed_state=data.get("observed_state") or {},
                    discrepancies=[str(d) for d in (data.get("discrepancies") or [])],
                    confidence=float(data.get("confidence", 0.0)),
                    narrative=str(data.get("narrative", ""))[:2000],
                    auditor=auditor,
                )
            except (ValueError, TypeError) as exc:
                logger.warning("could not parse auditor JSON: %s", exc)

        # An unparseable verdict is not a pass. Treat it as unconfirmed.
        return AuditVerdict(
            proposal_id=incident.incident_id,
            confirmed=False,
            discrepancies=["auditor did not return a parseable verdict"],
            confidence=0.0,
            narrative=text[:2000],
            auditor=auditor,
        )

    async def _learn(self, incident: Incident) -> None:
        """Turn a finished incident into recall for the next one."""
        service = incident.alert.resource_name
        if not service:
            return

        # What the fault looked like. Findings are the agent's own evidence,
        # so they are the most reusable signal we have.
        for finding in incident.findings[:3]:
            await self._memory.remember(
                service=service, kind=KIND_FAULT, summary=finding[:400],
                incident_id=incident.incident_id,
            )

        if incident.state is IncidentState.RESOLVED and incident.resolution:
            await self._memory.remember(
                service=service, kind=KIND_REMEDIATION,
                summary=f"Resolved: {incident.resolution[:350]}",
                incident_id=incident.incident_id, weight=2.0,
            )
        elif incident.state is IncidentState.ESCALATED and incident.escalation_reason:
            # Deliberately short and hedged. A long verbatim escalation reads
            # like a standing fact about the service on the next incident,
            # which is exactly how a fleet talks itself out of retrying.
            await self._memory.remember(
                service=service, kind=KIND_REMEDIATION,
                summary=(
                    "A previous incident could not be resolved autonomously and was "
                    f"escalated. At that time: {incident.escalation_reason[:180]}"
                ),
                incident_id=incident.incident_id, weight=1.0,
            )

    async def _close(self, incident: Incident) -> None:
        await self._learn(incident)
        report = await self._ledger.verify_chain(incident.incident_id)
        head = await self._ledger.head(incident.incident_id)
        await self._store.patch(
            self._settings.collection_incidents,
            incident.incident_id,
            {"ledger_head": (head or {}).get("hash", ""), "closed_at": utcnow().isoformat()},
        )
        await self._ledger.append(
            incident_id=incident.incident_id,
            event_type=LedgerEventType.INCIDENT_CLOSED,
            actor="interlock/orchestrator",
            payload={
                "final_state": incident.state.value,
                "actions_taken": incident.actions_taken,
                "chain_valid": report.valid,
                "entries": report.entries_checked,
            },
        )

    async def run_to_completion(self, incident_id: str, *, max_phases: int = 8) -> Incident:
        """Drive the machine until it is terminal, blocked, or the cap is hit."""
        incident = await self.get_incident(incident_id)
        if incident is None:
            raise OrchestratorError(f"unknown incident {incident_id}")
        for _ in range(max_phases):
            if incident.state.terminal or incident.state is IncidentState.AWAITING_APPROVAL:
                break
            incident = await self.advance(incident_id)
        return incident

    async def resume(self, incident_id: str) -> Incident:
        """Continue an incident that a previous process left unfinished."""
        await self.ensure_ready()
        incident = await self.get_incident(incident_id)
        if incident is None:
            raise OrchestratorError(f"unknown incident {incident_id}")
        checkpoint = await self.latest_checkpoint(incident_id)
        await self._ledger.append(
            incident_id=incident_id,
            event_type=LedgerEventType.RUN_RESUMED,
            actor="interlock/orchestrator",
            payload={
                "resumed_in_state": incident.state.value,
                "from_checkpoint": checkpoint.checkpoint_id if checkpoint else None,
                "revision": incident.revision,
            },
        )
        logger.info("resuming %s from state %s", incident_id, incident.state.value)
        return await self.run_to_completion(incident_id)

    # -- the sweeper -------------------------------------------------------

    async def sweep(self) -> dict[str, Any]:
        """Wake dormant work. Driven by Cloud Scheduler, not by a human.

        An agent that only acts when someone calls it is a chatbot with extra
        steps. This is the heartbeat that makes the fleet autonomous: it finds
        incidents that stalled because a process died without leaving a retry,
        and approvals nobody answered, and moves both forward.
        """
        await self.ensure_ready()
        now = utcnow()
        resumed: list[str] = []
        expired: list[str] = []
        stall_after = dt.timedelta(seconds=self._settings.sweep_stalled_after_seconds)
        max_age = dt.timedelta(seconds=self._settings.incident_max_duration_seconds)

        # 1. Approvals nobody answered in time. An unanswered approval is a
        #    refusal, not a licence to proceed.
        pending = await self._store.query(
            self._settings.collection_approvals, where=[("resolved", "==", False)]
        )
        for raw in pending:
            expires_at = raw.get("expires_at")
            if not expires_at or _parse(expires_at) > now:
                continue
            try:
                await self.resolve_approval(
                    raw["approval_id"], approved=False, resolved_by="interlock/sweeper",
                    justification=(
                        "No human answered within the approval window, so the request "
                        "expired closed."
                    ),
                )
                expired.append(raw["approval_id"])
            except OrchestratorError as exc:
                logger.warning("could not expire approval %s: %s", raw.get("approval_id"), exc)

        # 2. Incidents that stopped making progress.
        incidents = await self._store.query(self._settings.collection_incidents)
        for raw in incidents:
            state = raw.get("state", "")
            if state in ("RESOLVED", "ESCALATED", "FAILED", "AWAITING_APPROVAL"):
                continue
            updated = _parse(raw.get("updated_at"))
            incident_id = raw.get("incident_id", "")
            if not incident_id:
                continue

            # Give up on incidents that have run far too long rather than
            # letting them consume budget indefinitely.
            if now - _parse(raw.get("opened_at")) > max_age:
                incident = await self.get_incident(incident_id)
                if incident:
                    incident.escalation_reason = (
                        "Incident exceeded its maximum duration without reaching a "
                        "conclusion and was escalated by the sweeper."
                    )
                    await self._transition(incident, IncidentState.ESCALATED, "exceeded max duration")
                    await self._close(incident)
                    expired.append(incident_id)
                continue

            if now - updated < stall_after:
                continue

            logger.info("sweeper resuming stalled incident %s (state=%s)", incident_id, state)
            try:
                await self.resume(incident_id)
                resumed.append(incident_id)
            except Exception as exc:
                logger.exception("could not resume %s: %s", incident_id, exc)

        result = {
            "swept_at": now.isoformat(),
            "incidents_resumed": resumed,
            "approvals_expired": expired,
            "incidents_examined": len(incidents),
        }
        if resumed or expired:
            logger.info("sweep: resumed %d, expired %d", len(resumed), len(expired))
        return result

    # -- approvals ---------------------------------------------------------

    async def resolve_approval(
        self, approval_id: str, *, approved: bool, resolved_by: str, justification: str = ""
    ) -> Incident:
        raw = await self._store.get(self._settings.collection_approvals, approval_id)
        if raw is None:
            raise OrchestratorError(f"unknown approval {approval_id}")
        approval = ApprovalRequest.model_validate(raw)
        if approval.resolved:
            raise OrchestratorError(f"approval {approval_id} is already resolved")

        approval.resolved = True
        approval.approved = approved
        approval.resolved_by = resolved_by
        approval.resolved_at = utcnow()
        approval.justification = justification
        await self._store.put(
            self._settings.collection_approvals, approval_id, approval.model_dump(mode="json")
        )
        await self._ledger.append(
            incident_id=approval.incident_id,
            event_type=LedgerEventType.APPROVAL_RESOLVED,
            actor=resolved_by,
            payload={
                "approval_id": approval_id,
                "approved": approved,
                "justification": justification,
                "action_type": approval.proposal.action_type,
                "target": approval.proposal.target,
            },
        )

        incident = await self.get_incident(approval.incident_id)
        if incident is None:
            raise OrchestratorError("incident vanished while resolving approval")

        # Record the human's decision so the fleet does not relitigate it on the
        # next incident for this service.
        await self._memory.remember_governance_outcome(
            service=incident.alert.resource_name,
            incident_id=incident.incident_id,
            action_type=approval.proposal.action_type,
            approved=approved,
            resolved_by=resolved_by,
            justification=justification,
        )

        await self._store.patch(
            self._settings.collection_incidents,
            incident.incident_id,
            {"pending_approval_id": None},
        )
        incident.pending_approval_id = None

        if approved:
            # Return to planning so the agent can act with the approval granted.
            await self._transition(
                incident, IncidentState.PLANNING, f"approval {approval_id} granted by {resolved_by}"
            )
        else:
            incident.escalation_reason = (
                f"A human denied the proposed {approval.proposal.action_type} on "
                f"{approval.proposal.target}: {justification or 'no justification given'}"
            )
            await self._transition(
                incident, IncidentState.ESCALATED, f"approval {approval_id} denied by {resolved_by}"
            )
            await self._close(incident)
        return incident
