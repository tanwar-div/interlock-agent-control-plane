"""State machine, durability and approval tests.

The agent runs themselves are replaced with a recorded stub so these tests
exercise the orchestration guarantees — transitions, checkpoints, resumption,
approval handling — without depending on a model.
"""
from __future__ import annotations

import pytest

from interlock.common.models import Alert, IncidentState, Severity, utcnow
from interlock.ledger.ledger import Ledger
from interlock.runtime.orchestrator import IncidentOrchestrator


class StubOrchestrator(IncidentOrchestrator):
    """Orchestrator whose agent phases are scripted rather than modelled."""

    def __init__(self, *, outputs=None, on_phase=None, **kw):
        super().__init__(**kw)
        self.outputs = outputs or {}
        self.on_phase = on_phase or {}
        self.phases_run: list[str] = []

    async def _run_agent(self, *, agent_key, incident, brief, session_suffix):
        self.phases_run.append(agent_key)
        hook = self.on_phase.get(agent_key)
        if hook is not None:
            # Route hook failures through the production failure path so tests
            # exercise the real behaviour rather than the stub's.
            try:
                await hook(self, incident)
            except Exception as exc:
                if await self.record_phase_failure(incident, agent_key, exc):
                    return ""
                raise
        return self.outputs.get(agent_key, "")


async def _open(orch):
    return await orch.open_incident(
        Alert(
            title="Cloud Run 5xx rate above threshold",
            description="checkout-api returning 503",
            resource_name="checkout-api",
            severity="ERROR",
        )
    )


@pytest.mark.asyncio
async def test_incident_walks_the_full_state_machine(clean_store):
    async def claim_resolved(orch, incident):
        await orch._store.patch(
            "incidents", incident.incident_id,
            {"terminal_intent": "RESOLVED", "resolution": "rolled back to v41"},
        )

    orch = StubOrchestrator(
        outputs={"auditor": '{"confirmed": true, "confidence": 0.9, "observed_state": {"revision":"v41"}, "discrepancies": [], "narrative": "traffic is on v41 and errors stopped"}'},
        on_phase={"remediation": claim_resolved},
    )
    incident = await _open(orch)
    final = await orch.run_to_completion(incident.incident_id)

    assert orch.phases_run == ["triage", "investigator", "remediation", "auditor"]
    assert final.state is IncidentState.RESOLVED


@pytest.mark.asyncio
async def test_a_claim_of_success_still_goes_to_audit(clean_store):
    """The remediation agent cannot close its own incident."""
    async def claim_resolved(orch, incident):
        await orch._store.patch(
            "incidents", incident.incident_id,
            {"terminal_intent": "RESOLVED", "resolution": "definitely fixed, trust me"},
        )

    orch = StubOrchestrator(
        outputs={"auditor": '{"confirmed": false, "confidence": 0.8, "observed_state": {}, "discrepancies": ["service is still serving v42"], "narrative": "the claimed rollback did not happen"}'},
        on_phase={"remediation": claim_resolved},
    )
    incident = await _open(orch)
    final = await orch.run_to_completion(incident.incident_id)

    assert "auditor" in orch.phases_run
    assert final.state is IncidentState.ESCALATED
    assert "did not confirm" in final.escalation_reason


@pytest.mark.asyncio
async def test_unparseable_audit_is_not_treated_as_a_pass(clean_store):
    async def claim_resolved(orch, incident):
        await orch._store.patch(
            "incidents", incident.incident_id, {"terminal_intent": "RESOLVED", "resolution": "fixed"}
        )

    orch = StubOrchestrator(
        outputs={"auditor": "Yeah looks fine to me!"},
        on_phase={"remediation": claim_resolved},
    )
    incident = await _open(orch)
    final = await orch.run_to_completion(incident.incident_id)
    assert final.state is IncidentState.ESCALATED


@pytest.mark.asyncio
async def test_checkpoints_are_written_for_every_phase(clean_store):
    orch = StubOrchestrator()
    incident = await _open(orch)
    await orch.advance(incident.incident_id)
    checkpoint = await orch.latest_checkpoint(incident.incident_id)
    assert checkpoint is not None
    assert checkpoint.incident_id == incident.incident_id


@pytest.mark.asyncio
async def test_incident_resumes_in_a_new_process_after_a_crash(clean_store):
    """The durability claim: a second orchestrator finishes what the first started."""
    async def claim_resolved(orch, incident):
        await orch._store.patch(
            "incidents", incident.incident_id, {"terminal_intent": "RESOLVED", "resolution": "rolled back"}
        )

    first = StubOrchestrator()
    incident = await _open(first)
    await first.advance(incident.incident_id)   # triage
    await first.advance(incident.incident_id)   # investigation
    mid = await first.get_incident(incident.incident_id)
    assert mid.state is IncidentState.PLANNING

    # The process handling this incident dies here. A completely separate
    # orchestrator instance picks it up from durable state.
    second = StubOrchestrator(
        outputs={"auditor": '{"confirmed": true, "confidence": 0.95, "observed_state": {}, "discrepancies": [], "narrative": "recovered"}'},
        on_phase={"remediation": claim_resolved},
    )
    final = await second.resume(incident.incident_id)

    assert final.state is IncidentState.RESOLVED
    # The second process did not redo work the first had already completed.
    assert "triage" not in second.phases_run
    assert "investigator" not in second.phases_run
    assert second.phases_run == ["remediation", "auditor"]

    entries = await Ledger().entries(incident.incident_id)
    assert any(e.event_type.value == "RUN_RESUMED" for e in entries)


@pytest.mark.asyncio
async def test_denied_approval_escalates_and_stops(clean_store):
    from interlock.common.models import (
        ActionProposal,
        ApprovalRequest,
        Decision,
        PolicyDecision,
    )

    orch = StubOrchestrator()
    incident = await _open(orch)
    proposal = ActionProposal(
        incident_id=incident.incident_id, actor="spiffe://interlock.internal/ns/sre/agent/remediation",
        action_type="storage.buckets.setIamPolicy", target="uploads",
    )
    approval = ApprovalRequest(
        incident_id=incident.incident_id, proposal=proposal,
        decision=PolicyDecision(decision=Decision.REQUIRE_APPROVAL, reasons=["access change"]),
    )
    await clean_store.put("approvals", approval.approval_id, approval.model_dump(mode="json"))

    final = await orch.resolve_approval(
        approval.approval_id, approved=False, resolved_by="oncall@example.com",
        justification="not an acceptable remedy for an availability fault",
    )
    assert final.state is IncidentState.ESCALATED
    assert "denied" in final.escalation_reason.lower() or "denied" in final.escalation_reason


@pytest.mark.asyncio
async def test_ledger_chain_stays_valid_across_a_whole_incident(clean_store):
    async def claim_resolved(orch, incident):
        await orch._store.patch(
            "incidents", incident.incident_id, {"terminal_intent": "RESOLVED", "resolution": "ok"}
        )

    orch = StubOrchestrator(
        outputs={"auditor": '{"confirmed": true, "confidence": 0.9, "observed_state": {}, "discrepancies": [], "narrative": "ok"}'},
        on_phase={"remediation": claim_resolved},
    )
    incident = await _open(orch)
    await orch.run_to_completion(incident.incident_id)
    report = await Ledger().verify_chain(incident.incident_id)
    assert report.valid, report.problems
    assert report.entries_checked > 10


@pytest.mark.asyncio
async def test_fleet_registers_with_least_privilege(clean_store):
    orch = StubOrchestrator()
    await orch.ensure_ready()
    from interlock.identity.registry import AgentRegistry

    cards = {c.display_name: c for c in await AgentRegistry().list_cards()}
    investigator = cards["Investigation Agent"]
    remediation = cards["Remediation Agent"]

    # The investigator must not be able to change anything.
    assert investigator.max_severity is Severity.LOW
    assert "run.services.rollback" not in investigator.allowed_tools
    # The auditor must not be able to change anything either.
    assert cards["Independent Auditor"].max_severity is Severity.LOW
    # Remediation can act, but cannot reach catastrophic actions.
    assert remediation.max_severity is Severity.HIGH
    assert "run.services.rollback" in remediation.allowed_tools


@pytest.mark.asyncio
async def test_only_one_worker_may_advance_an_incident(clean_store):
    """Pub/Sub is at-least-once; a redelivered phase must not run twice."""
    orch = StubOrchestrator()
    incident = await _open(orch)

    token = await orch._acquire_lease(incident.incident_id)
    assert token is not None
    # A second worker arriving while the first holds the lease is turned away.
    assert await orch._acquire_lease(incident.incident_id) is None

    await orch._release_lease(incident.incident_id, token)
    assert await orch._acquire_lease(incident.incident_id) is not None


@pytest.mark.asyncio
async def test_concurrent_advances_run_the_phase_once(clean_store):
    import asyncio

    orch = StubOrchestrator()
    incident = await _open(orch)
    await asyncio.gather(*(orch.advance(incident.incident_id) for _ in range(4)))
    # Four simultaneous deliveries, one execution of the triage phase.
    assert orch.phases_run.count("triage") == 1


@pytest.mark.asyncio
async def test_an_expired_lease_can_be_reclaimed(clean_store):
    """A worker that dies holding a lease must not block the incident forever."""
    import datetime as dt

    orch = StubOrchestrator()
    incident = await _open(orch)
    await orch._acquire_lease(incident.incident_id, ttl_seconds=1)

    raw = await clean_store.get("incidents", incident.incident_id)
    raw["lease_until"] = (utcnow() - dt.timedelta(seconds=5)).isoformat()
    await clean_store.put("incidents", incident.incident_id, raw)

    assert await orch._acquire_lease(incident.incident_id) is not None


@pytest.mark.asyncio
async def test_a_permanently_failing_phase_is_abandoned_not_retried_forever(clean_store):
    """Retrying suits a transient fault and wastes redeliveries on a deterministic one."""
    orch = StubOrchestrator()
    incident = await _open(orch)

    async def boom(self, incident_arg):
        raise RuntimeError("deterministic configuration fault")

    orch.on_phase = {"triage": boom}

    failures = 0
    for _ in range(5):
        try:
            await orch.advance(incident.incident_id)
        except RuntimeError:
            failures += 1
        current = await orch.get_incident(incident.incident_id)
        if current.state.terminal:
            break

    final = await orch.get_incident(incident.incident_id)
    assert final.state is IncidentState.FAILED
    assert "failed 3 times in a row" in final.escalation_reason
    # It gave up rather than retrying indefinitely.
    assert failures == 2


@pytest.mark.asyncio
async def test_transient_faults_do_not_exhaust_the_failure_budget(clean_store):
    """Quota exhaustion says 'not now'; a schema error says 'not ever'.
    Spending the same budget on both makes a busy afternoon look like a bug."""
    orch = StubOrchestrator()
    incident = await _open(orch)

    async def rate_limited(orch_, incident_):
        raise RuntimeError("429 RESOURCE_EXHAUSTED. Resource exhausted, please try again later")

    orch.on_phase = {"triage": rate_limited}

    for _ in range(6):
        try:
            await orch.advance(incident.incident_id)
        except RuntimeError:
            pass

    final = await orch.get_incident(incident.incident_id)
    # Still retryable after six transient faults, rather than abandoned.
    assert final.state is not IncidentState.FAILED
    raw = await clean_store.get("incidents", incident.incident_id)
    assert not (raw.get("phase_failures") or {})
