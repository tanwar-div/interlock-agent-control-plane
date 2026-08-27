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

import asyncio
import json
import logging
from typing import Any

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
    utcnow,
)
from interlock.common.store import DocumentStore, get_store
from interlock.identity.registry import AgentRegistry
from interlock.ledger.ledger import Ledger
from interlock.policy.engine import PolicyEngine
from interlock.runtime.governed import action_types_for
from interlock.runtime.plugin import InterlockPlugin
from interlock.workers.agents import FLEET_SPEC

logger = logging.getLogger(__name__)

APP_NAME = "interlock"

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
        self._agent_keys: dict[str, str] = {}
        self._cards: dict[str, Any] = {}
        self._agents: dict[str, Any] = {}
        self._plugin: InterlockPlugin | None = None
        self._ready = False

    def _build_session_service(self) -> BaseSessionService:
        url = getattr(self._settings, "session_db_url", "")
        if url:
            try:
                from google.adk.sessions import DatabaseSessionService

                logger.info("using DatabaseSessionService for ADK sessions")
                return DatabaseSessionService(db_url=url)
            except Exception as exc:  # noqa: BLE001
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
        self._ready = True
        logger.info("fleet ready: %s", ", ".join(self._cards))

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
            order_by="revision",
            descending=True,
            limit=1,
        )
        return Checkpoint.model_validate(rows[0]) if rows else None

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
        agent = self._agents[agent_key]
        card = self._cards[agent_key]

        session_id = f"{incident.session_id}_{session_suffix}"
        initial_state = {
            "incident_id": incident.incident_id,
            "actor_spiffe": card.spiffe_id,
            "incident_state": incident.state.value,
        }
        await self._sessions.create_session(
            app_name=APP_NAME,
            user_id=incident.incident_id,
            session_id=session_id,
            state=initial_state,
        )

        runner = Runner(
            app_name=APP_NAME,
            agent=agent,
            session_service=self._sessions,
            plugins=[self._plugin],
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
        except Exception as exc:  # noqa: BLE001
            logger.exception("agent %s failed", agent_key)
            await self._ledger.append(
                incident_id=incident.incident_id,
                event_type=LedgerEventType.ACTION_FAILED,
                actor=card.spiffe_id,
                payload={"phase": agent_key, "error": str(exc)[:900]},
            )
            raise

        # Read back terminal intent the tools may have written into state.
        session = await self._sessions.get_session(
            app_name=APP_NAME, user_id=incident.incident_id, session_id=session_id
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

    # -- briefs ------------------------------------------------------------

    def _brief(self, incident: Incident, phase: IncidentState) -> str:
        alert = incident.alert
        header = (
            f"INCIDENT {incident.incident_id}\n"
            f"Alert: {alert.title}\n"
            f"Severity: {alert.severity}\n"
            f"Resource: {alert.resource_type} {alert.resource_name}\n"
            f"Description: {alert.description}\n"
        )
        findings = "\n".join(f"- {f}" for f in incident.findings) or "- (none yet)"

        if phase is IncidentState.TRIAGING:
            return header + "\nTriage this alert."
        if phase is IncidentState.INVESTIGATING:
            return (
                header
                + f"\nTriage findings so far:\n{findings}\n\n"
                "Investigate and establish what is actually happening."
            )
        if phase is IncidentState.PLANNING:
            return (
                header
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
            brief=self._brief(incident, phase),
            session_suffix=phase.value.lower(),
        )

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

    async def _close(self, incident: Incident) -> None:
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
