"""Interlock control plane API.

Every mutating path is dispatched asynchronously: an alert opens an incident and
enqueues the first phase, and each phase enqueues the next. No request holds a
connection while an agent thinks, so an incident can span hours on
scale-to-zero infrastructure.

When Pub/Sub is not configured the same handlers run in a local background task,
so the whole system works end to end on a laptop.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from interlock.blastradius.catalog import ACTION_CATALOG
from interlock.blastradius.scorer import score_proposal_with_model
from interlock.common import pubsub
from interlock.common.config import get_settings
from interlock.common.models import (
    ActionProposal,
    Alert,
    IncidentState,
    Severity,
)
from interlock.common.store import get_store
from interlock.common.telemetry import (
    configure_logging,
    configure_telemetry,
    instrument_fastapi,
)
from interlock.gateway import auth
from interlock.identity.registry import AgentRegistry
from interlock.ledger.ledger import Ledger
from interlock.memory.service import IncidentMemory
from interlock.policy.engine import PolicyEngine
from interlock.runtime.orchestrator import IncidentOrchestrator

logger = logging.getLogger(__name__)

configure_logging()
configure_telemetry("interlock-gateway")

app = FastAPI(
    title="Interlock",
    version="1.0.0",
    description="Oversight and containment control plane for autonomous agents.",
)
instrument_fastapi(app)
# Deny-by-default authorization. A no-op unless the public read-only face is
# switched on, so the private deployment behaves exactly as it did before.
auth.install(app)

settings = get_settings()
orchestrator = IncidentOrchestrator()
ledger = Ledger()
registry = AgentRegistry()
policy = PolicyEngine()

CONSOLE_DIR = Path(__file__).resolve().parent.parent / "console" / "static"

# Strong references to in-flight background work. Without these the event loop
# holds only a weak reference and may collect a running task.
_BACKGROUND_TASKS: set[asyncio.Task] = set()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AlertIn(BaseModel):
    title: str
    description: str = ""
    resource_name: str = ""
    resource_type: str = "cloud_run_revision"
    severity: str = "WARNING"
    source: str = "manual"
    labels: dict[str, str] = Field(default_factory=dict)


class ApprovalIn(BaseModel):
    approved: bool
    resolved_by: str = "operator"
    justification: str = ""


class SimulateIn(BaseModel):
    action_type: str
    target: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    agent: str = "remediation"


# ---------------------------------------------------------------------------
# Phase dispatch
# ---------------------------------------------------------------------------


async def _dispatch_phase(incident_id: str, background: BackgroundTasks | None) -> str:
    """Enqueue the next phase, via Pub/Sub when available."""
    message_id = pubsub.publish(
        settings.topic_actions, {"incident_id": incident_id, "op": "advance"}, kind="advance"
    )
    if message_id:
        return "pubsub"
    # Local / no-Pub/Sub path: drive it in-process instead.
    if background is not None:
        background.add_task(_advance_until_blocked, incident_id)
    else:
        # Hold a reference: a task with no live reference can be collected
        # mid-flight, which would silently abandon an incident.
        task = asyncio.create_task(_advance_until_blocked(incident_id))
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)
    return "background"


async def _advance_until_blocked(incident_id: str) -> None:
    try:
        await orchestrator.run_to_completion(incident_id)
    except Exception:
        logger.exception("orchestration failed for %s", incident_id)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


# Cloud Run's frontend intercepts /healthz and answers 404 with an HTML page
# before the request reaches the container, even though FastAPI registers the
# route. /health is served as the reachable alias; /readyz is the one to point
# a probe at, since it also proves the fleet registered.
@app.get("/health")
@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {"status": "ok", "service": "interlock-gateway", "version": "1.0.0"}


@app.get("/readyz")
async def readyz() -> dict[str, Any]:
    await orchestrator.ensure_ready()
    cards = await registry.list_cards()
    return {
        "status": "ready",
        "project": settings.project_id or "(unset)",
        "reasoning_model": settings.reasoning_model,
        "guard_model": settings.guard_model,
        "agents_registered": len(cards),
        "catalogued_actions": len(ACTION_CATALOG),
    }


# ---------------------------------------------------------------------------
# Alerts and incidents
# ---------------------------------------------------------------------------


@app.post("/v1/alerts", status_code=202)
async def create_alert(payload: AlertIn, background: BackgroundTasks) -> dict[str, Any]:
    await orchestrator.ensure_ready()
    incident = await orchestrator.open_incident(Alert(**payload.model_dump()))
    transport = await _dispatch_phase(incident.incident_id, background)
    return {
        "incident_id": incident.incident_id,
        "state": incident.state.value,
        "dispatched_via": transport,
    }


@app.post("/v1/pubsub/alerts", status_code=204)
async def pubsub_alert(request: Request, background: BackgroundTasks) -> Response:
    """Push endpoint for Cloud Monitoring notifications."""
    body = await request.json()
    payload, _ = pubsub.decode_push(body)
    if not payload:
        return Response(status_code=204)

    normalised = pubsub.parse_monitoring_alert(payload)
    await orchestrator.ensure_ready()
    incident = await orchestrator.open_incident(Alert(**{
        k: v for k, v in normalised.items() if k in Alert.model_fields
    }))
    await _dispatch_phase(incident.incident_id, background)
    return Response(status_code=204)


@app.post("/v1/pubsub/advance", status_code=204)
async def pubsub_advance(request: Request) -> Response:
    """Push endpoint that executes exactly one phase.

    Acknowledging only after the phase is durably checkpointed means a crash
    mid-phase results in redelivery, not a lost incident.
    """
    body = await request.json()
    payload, _ = pubsub.decode_push(body)
    incident_id = payload.get("incident_id")
    if not incident_id:
        return Response(status_code=204)

    incident = await orchestrator.advance(incident_id)
    if not incident.state.terminal and incident.state is not IncidentState.AWAITING_APPROVAL:
        pubsub.publish(settings.topic_actions, {"incident_id": incident_id, "op": "advance"})
    return Response(status_code=204)


@app.get("/v1/incidents")
async def list_incidents(limit: int = 50) -> dict[str, Any]:
    rows = await get_store().query(
        settings.collection_incidents, order_by="opened_at", descending=True, limit=limit
    )
    return {
        "count": len(rows),
        "incidents": [
            {
                "incident_id": r.get("incident_id"),
                "title": (r.get("alert") or {}).get("title", ""),
                "resource": (r.get("alert") or {}).get("resource_name", ""),
                "state": r.get("state"),
                "opened_at": r.get("opened_at"),
                "closed_at": r.get("closed_at"),
                "actions_taken": r.get("actions_taken", 0),
                "pending_approval_id": r.get("pending_approval_id"),
                "findings": len(r.get("findings") or []),
            }
            for r in rows
        ],
    }


@app.get("/v1/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    incident = await orchestrator.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="unknown incident")
    entries = await ledger.entries(incident_id)
    proposals = await get_store().query("proposals", where=[("incident_id", "==", incident_id)])
    audits = await get_store().query("audits", where=[("proposal_id", "==", incident_id)])
    return {
        "incident": incident.model_dump(mode="json"),
        "ledger": [e.model_dump(mode="json") for e in entries],
        "proposals": proposals,
        "audits": audits,
    }


@app.get("/v1/incidents/{incident_id}/ledger")
async def get_ledger(incident_id: str) -> dict[str, Any]:
    report = await ledger.verify_chain(incident_id)
    entries = await ledger.entries(incident_id)
    return {
        "verification": report.to_dict(),
        "entries": [e.model_dump(mode="json") for e in entries],
    }


@app.get("/v1/incidents/{incident_id}/evidence")
async def export_evidence(incident_id: str) -> dict[str, Any]:
    """Portable, independently verifiable evidence bundle."""
    return await ledger.export_chain(incident_id)


@app.post("/v1/incidents/{incident_id}/resume")
async def resume_incident(incident_id: str, background: BackgroundTasks) -> dict[str, Any]:
    incident = await orchestrator.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="unknown incident")
    checkpoint = await orchestrator.latest_checkpoint(incident_id)
    background.add_task(_advance_until_blocked, incident_id)
    return {
        "incident_id": incident_id,
        "resumed_from_state": incident.state.value,
        "checkpoint": checkpoint.checkpoint_id if checkpoint else None,
        "revision": incident.revision,
    }


# ---------------------------------------------------------------------------
# The heartbeat
# ---------------------------------------------------------------------------


@app.post("/v1/sweep")
async def sweep() -> dict[str, Any]:
    """Wake dormant work: resume stalled incidents, expire unanswered approvals.

    Cloud Scheduler calls this on a fixed cadence. It is what makes the fleet
    autonomous rather than merely reactive — progress does not depend on anyone
    being awake to ask for it.
    """
    return await orchestrator.sweep()


@app.post("/v1/pubsub/sweep", status_code=204)
async def pubsub_sweep(request: Request) -> Response:
    try:
        await request.json()
    except Exception:
        pass
    await orchestrator.sweep()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------


@app.get("/v1/memory")
async def list_memory(service: str = "", limit: int = 100) -> dict[str, Any]:
    """What the fleet has learned, and from which incidents."""
    memory = IncidentMemory()
    rows = (
        await memory.recall(service=service, limit=limit)
        if service
        else await memory.all_memories(limit=limit)
    )
    return {"count": len(rows), "service": service or "(all)", "memories": rows}


@app.delete("/v1/memory")
async def forget(service: str) -> dict[str, Any]:
    """Erase what the fleet has learned about a service.

    Needed when the environment has changed so fundamentally that prior
    observations are misleading rather than merely stale.
    """
    removed = await IncidentMemory().forget_service(service)
    return {"service": service, "memories_removed": removed}


@app.get("/v1/memory/brief")
async def memory_brief(service: str) -> dict[str, Any]:
    """The exact recall block injected into an agent's brief for this service."""
    return {"service": service, "brief": await IncidentMemory().recall_brief(service=service)}


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------


@app.get("/v1/approvals")
async def list_approvals(pending_only: bool = True) -> dict[str, Any]:
    where = [("resolved", "==", False)] if pending_only else []
    rows = await get_store().query(settings.collection_approvals, where=where)
    rows.sort(key=lambda r: r.get("requested_at") or "", reverse=True)
    return {"count": len(rows), "approvals": rows}


@app.post("/v1/approvals/{approval_id}/decide")
async def decide_approval(
    approval_id: str, payload: ApprovalIn, background: BackgroundTasks
) -> dict[str, Any]:
    try:
        incident = await orchestrator.resolve_approval(
            approval_id,
            approved=payload.approved,
            resolved_by=payload.resolved_by,
            justification=payload.justification,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if payload.approved and not incident.state.terminal:
        await _dispatch_phase(incident.incident_id, background)
    return {
        "approval_id": approval_id,
        "approved": payload.approved,
        "incident_state": incident.state.value,
    }


# ---------------------------------------------------------------------------
# Governance introspection
# ---------------------------------------------------------------------------


@app.get("/v1/agents")
async def list_agents() -> dict[str, Any]:
    await orchestrator.ensure_ready()
    cards = await registry.list_cards()
    return {
        "count": len(cards),
        "agents": [
            {
                **card.model_dump(mode="json"),
                "card_signature_valid": registry.verify_card(card),
            }
            for card in cards
        ],
    }


@app.get("/v1/catalog")
async def get_catalog() -> dict[str, Any]:
    return {
        "count": len(ACTION_CATALOG),
        "actions": [
            {
                "action_type": spec.action_type,
                "description": spec.description,
                "reversibility": spec.reversibility.value,
                "scope": spec.scope,
                "data_risk": spec.data_risk,
                "availability_risk": spec.availability_risk,
                "privilege_risk": spec.privilege_risk,
                "base_cost_usd": spec.base_cost_usd,
                "undoable": spec.undoable,
            }
            for spec in sorted(ACTION_CATALOG.values(), key=lambda s: s.action_type)
        ],
    }


@app.post("/v1/simulate")
async def simulate(payload: SimulateIn) -> dict[str, Any]:
    """Score a hypothetical action without executing anything.

    This is the governance plane's read-only face: it answers "what would
    happen if an agent asked for this?" against the exact same scorer and
    policy engine that run in production.
    """
    await orchestrator.ensure_ready()
    spiffe = f"spiffe://{settings.trust_domain}/ns/sre/agent/{payload.agent}"
    card = await registry.get_by_spiffe(spiffe)

    proposal = ActionProposal(
        incident_id="simulation",
        actor=spiffe,
        action_type=payload.action_type,
        target=payload.target or payload.parameters.get("service", "unspecified"),
        parameters=payload.parameters,
    )
    radius = await score_proposal_with_model(
        proposal, budget_remaining_usd=settings.incident_budget_usd
    )
    decision = policy.evaluate(proposal=proposal, blast_radius=radius, card=card, incident=None)
    return {
        "proposal": proposal.model_dump(mode="json"),
        "blast_radius": radius.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
        "agent": {
            "spiffe_id": spiffe,
            "known": card is not None,
            "max_severity": card.max_severity.value if card else None,
            "entitled": bool(card and payload.action_type in card.allowed_tools),
        },
    }


@app.get("/v1/policy")
async def describe_policy() -> dict[str, Any]:
    from interlock.policy.engine import DEFAULT_RULES

    return {
        "budget_usd": settings.incident_budget_usd,
        "max_actions_per_incident": settings.max_actions_per_incident,
        "approval_timeout_seconds": settings.approval_timeout_seconds,
        "severity_levels": [s.value for s in Severity],
        "rules": [{"name": r.name, "description": r.description} for r in DEFAULT_RULES],
    }


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

if CONSOLE_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(CONSOLE_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def console() -> FileResponse:
        return FileResponse(str(CONSOLE_DIR / "index.html"))
