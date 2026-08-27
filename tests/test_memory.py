"""Cross-incident memory: the fleet must not relitigate settled decisions."""
from __future__ import annotations

import pytest

from interlock.memory.service import (
    KIND_FAULT,
    KIND_GOVERNANCE,
    KIND_REMEDIATION,
    IncidentMemory,
)


@pytest.mark.asyncio
async def test_repeated_observations_reinforce_rather_than_duplicate(clean_store):
    memory = IncidentMemory()
    for incident in ("inc_1", "inc_2", "inc_3"):
        await memory.remember(
            service="checkout-api", kind=KIND_FAULT,
            summary="503s begin within 2 minutes of a new revision", incident_id=incident,
        )
    rows = await memory.recall(service="checkout-api")
    assert len(rows) == 1
    assert rows[0]["occurrences"] == 3
    assert set(rows[0]["incidents"]) == {"inc_1", "inc_2", "inc_3"}


@pytest.mark.asyncio
async def test_human_decisions_outrank_everything_else(clean_store):
    memory = IncidentMemory()
    await memory.remember(service="api", kind=KIND_FAULT, summary="fault detail")
    await memory.remember(service="api", kind=KIND_REMEDIATION, summary="rollback worked")
    await memory.remember_governance_outcome(
        service="api", incident_id="inc_9", action_type="storage.buckets.setIamPolicy",
        approved=False, resolved_by="oncall@example.com",
        justification="widening access is not a remedy for an availability fault",
    )
    rows = await memory.recall(service="api")
    assert rows[0]["kind"] == KIND_GOVERNANCE
    assert rows[0]["detail"]["approved"] is False


@pytest.mark.asyncio
async def test_memory_is_scoped_per_service(clean_store):
    memory = IncidentMemory()
    await memory.remember(service="checkout-api", kind=KIND_FAULT, summary="checkout fault")
    await memory.remember(service="billing-api", kind=KIND_FAULT, summary="billing fault")
    assert len(await memory.recall(service="checkout-api")) == 1
    assert (await memory.recall(service="billing-api"))[0]["summary"] == "billing fault"
    assert await memory.recall(service="unknown-service") == []


@pytest.mark.asyncio
async def test_stale_memories_are_not_recalled(clean_store):
    memory = IncidentMemory()
    record = await memory.remember(service="api", kind=KIND_FAULT, summary="ancient history")
    record["last_seen"] = "2020-01-01T00:00:00+00:00"
    await clean_store.put("memories", record["memory_id"], record)
    assert await memory.recall(service="api") == []


@pytest.mark.asyncio
async def test_brief_instructs_the_agent_to_treat_denials_as_precedent(clean_store):
    memory = IncidentMemory()
    await memory.remember_governance_outcome(
        service="api", incident_id="i", action_type="compute.instances.insert",
        approved=False, resolved_by="oncall", justification="no evidence capacity is the problem",
    )
    brief = await memory.recall_brief(service="api")
    assert "binding precedent" in brief
    assert "compute.instances.insert" in brief
    assert "no evidence capacity is the problem" in brief


@pytest.mark.asyncio
async def test_empty_recall_produces_no_brief(clean_store):
    assert await IncidentMemory().recall_brief(service="never-seen") == ""


@pytest.mark.asyncio
async def test_incident_outcomes_become_memory(clean_store):
    """Closing an incident must leave the fleet better informed."""
    from tests.test_orchestrator import StubOrchestrator, _open

    async def claim_resolved(orch, incident):
        await orch._store.patch(
            "incidents", incident.incident_id,
            {"terminal_intent": "RESOLVED", "resolution": "rolled back to v41"},
        )

    orch = StubOrchestrator(
        outputs={"auditor": '{"confirmed": true, "confidence": 0.9, "observed_state": {}, "discrepancies": [], "narrative": "ok"}'},
        on_phase={"remediation": claim_resolved},
    )
    incident = await _open(orch)
    await orch.run_to_completion(incident.incident_id)

    rows = await IncidentMemory().recall(service="checkout-api")
    assert any(r["kind"] == KIND_REMEDIATION and "rolled back to v41" in r["summary"] for r in rows)
