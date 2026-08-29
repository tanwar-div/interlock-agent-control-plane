"""The heartbeat: progress must not depend on anyone being awake."""
from __future__ import annotations

import datetime as dt

import pytest

from interlock.common.models import (
    ActionProposal,
    ApprovalRequest,
    Decision,
    IncidentState,
    PolicyDecision,
    utcnow,
)
from tests.test_orchestrator import StubOrchestrator, _open


@pytest.mark.asyncio
async def test_sweeper_resumes_an_incident_whose_process_died(clean_store):
    orch = StubOrchestrator()
    incident = await _open(orch)
    await orch.advance(incident.incident_id)   # triage; then the process "dies"

    # Backdate the incident so it looks stalled.
    raw = await clean_store.get("incidents", incident.incident_id)
    raw["updated_at"] = (utcnow() - dt.timedelta(hours=1)).isoformat()
    await clean_store.put("incidents", incident.incident_id, raw)

    result = await StubOrchestrator().sweep()
    assert incident.incident_id in result["incidents_resumed"]


@pytest.mark.asyncio
async def test_sweeper_leaves_fresh_incidents_alone(clean_store):
    orch = StubOrchestrator()
    incident = await _open(orch)
    await orch.advance(incident.incident_id)
    result = await StubOrchestrator().sweep()
    assert incident.incident_id not in result["incidents_resumed"]


@pytest.mark.asyncio
async def test_unanswered_approval_expires_closed(clean_store):
    """Silence is a refusal, never a licence to proceed."""
    orch = StubOrchestrator()
    incident = await _open(orch)
    proposal = ActionProposal(
        incident_id=incident.incident_id,
        actor="spiffe://interlock.internal/ns/sre/agent/remediation",
        action_type="storage.buckets.setIamPolicy", target="checkout-api",
    )
    approval = ApprovalRequest(
        incident_id=incident.incident_id, proposal=proposal,
        decision=PolicyDecision(decision=Decision.REQUIRE_APPROVAL, reasons=["access change"]),
        expires_at=utcnow() - dt.timedelta(minutes=5),
    )
    await clean_store.put("approvals", approval.approval_id, approval.model_dump(mode="json"))

    result = await StubOrchestrator().sweep()
    assert approval.approval_id in result["approvals_expired"]

    stored = await clean_store.get("approvals", approval.approval_id)
    assert stored["resolved"] is True and stored["approved"] is False

    final = await orch.get_incident(incident.incident_id)
    assert final.state is IncidentState.ESCALATED


@pytest.mark.asyncio
async def test_sweeper_ignores_approvals_still_within_their_window(clean_store):
    orch = StubOrchestrator()
    incident = await _open(orch)
    approval = ApprovalRequest(
        incident_id=incident.incident_id,
        proposal=ActionProposal(
            incident_id=incident.incident_id, actor="spiffe://x",
            action_type="run.services.rollback", target="checkout-api",
        ),
        decision=PolicyDecision(decision=Decision.REQUIRE_APPROVAL),
        expires_at=utcnow() + dt.timedelta(hours=1),
    )
    await clean_store.put("approvals", approval.approval_id, approval.model_dump(mode="json"))
    result = await StubOrchestrator().sweep()
    assert approval.approval_id not in result["approvals_expired"]


@pytest.mark.asyncio
async def test_expired_approval_is_remembered_as_precedent(clean_store):
    from interlock.memory.service import IncidentMemory

    orch = StubOrchestrator()
    incident = await _open(orch)
    approval = ApprovalRequest(
        incident_id=incident.incident_id,
        proposal=ActionProposal(
            incident_id=incident.incident_id, actor="spiffe://x",
            action_type="compute.instances.insert", target="checkout-api",
        ),
        decision=PolicyDecision(decision=Decision.REQUIRE_APPROVAL),
        expires_at=utcnow() - dt.timedelta(minutes=1),
    )
    await clean_store.put("approvals", approval.approval_id, approval.model_dump(mode="json"))
    await StubOrchestrator().sweep()

    rows = await IncidentMemory().recall(service="checkout-api")
    assert any("compute.instances.insert" in r["summary"] for r in rows)
