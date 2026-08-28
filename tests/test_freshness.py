"""Point-of-action revalidation against live state."""
from __future__ import annotations

import pytest

from interlock.common.models import ActionProposal
from interlock.runtime import freshness


def _proposal(action_type="run.services.rollback", **params):
    return ActionProposal(
        incident_id="inc", actor="spiffe://x", action_type=action_type,
        target=params.get("service", "checkout-api"), parameters=params,
    )


@pytest.mark.asyncio
async def test_unchecked_actions_pass_through():
    verdict = await freshness.revalidate(_proposal("logging.entries.list"))
    assert verdict.stale is False


@pytest.mark.asyncio
async def test_missing_target_revision_is_stale(monkeypatch):
    async def fake_state(service): return {"traffic": [{"revision": "v42", "percent": 100}]}
    async def fake_revs(service): return {"revisions": [{"name": "v42", "ready": "CONDITION_SUCCEEDED"}]}
    monkeypatch.setattr(freshness, "_service_state", fake_state)
    monkeypatch.setattr(freshness, "_revisions", fake_revs)

    verdict = await freshness.revalidate(_proposal(service="checkout-api", revision="v41"))
    assert verdict.stale is True
    assert "no longer exists" in verdict.detail


@pytest.mark.asyncio
async def test_unhealthy_target_revision_is_stale(monkeypatch):
    async def fake_state(service): return {"traffic": [{"revision": "v42", "percent": 100}]}
    async def fake_revs(service):
        return {"revisions": [{"name": "v41", "healthy": False, "ready": "CONDITION_FAILED"},
                              {"name": "v42", "healthy": True, "ready": "CONDITION_SUCCEEDED"}]}
    monkeypatch.setattr(freshness, "_service_state", fake_state)
    monkeypatch.setattr(freshness, "_revisions", fake_revs)

    verdict = await freshness.revalidate(_proposal(service="checkout-api", revision="v41"))
    assert verdict.stale is True
    assert "not healthy" in verdict.detail


@pytest.mark.asyncio
async def test_already_applied_change_is_stale(monkeypatch):
    async def fake_state(service): return {"traffic": [{"revision": "v41", "percent": 100}]}
    async def fake_revs(service): return {"revisions": [{"name": "v41", "ready": "CONDITION_SUCCEEDED"}]}
    monkeypatch.setattr(freshness, "_service_state", fake_state)
    monkeypatch.setattr(freshness, "_revisions", fake_revs)

    verdict = await freshness.revalidate(_proposal(service="checkout-api", revision="v41"))
    assert verdict.stale is True
    assert "already serving" in verdict.detail


@pytest.mark.asyncio
async def test_valid_rollback_is_fresh(monkeypatch):
    async def fake_state(service): return {"traffic": [{"revision": "v42", "percent": 100}]}
    async def fake_revs(service):
        return {"revisions": [{"name": "v41", "healthy": True, "serving_traffic": False,
                               "ready": "CONDITION_SUCCEEDED"},
                              {"name": "v42", "healthy": True, "serving_traffic": True,
                               "ready": "CONDITION_SUCCEEDED"}]}
    monkeypatch.setattr(freshness, "_service_state", fake_state)
    monkeypatch.setattr(freshness, "_revisions", fake_revs)

    verdict = await freshness.revalidate(_proposal(service="checkout-api", revision="v41"))
    assert verdict.stale is False


@pytest.mark.asyncio
async def test_unreachable_api_degrades_rather_than_blocking(monkeypatch):
    """Freshness must not become an outage amplifier."""
    async def boom(service): raise RuntimeError("Cloud Run API unreachable")
    monkeypatch.setattr(freshness, "_service_state", boom)
    monkeypatch.setattr(freshness, "_revisions", boom)

    verdict = await freshness.revalidate(_proposal(service="checkout-api", revision="v41"))
    assert verdict.stale is False
    assert verdict.degraded is True


@pytest.mark.asyncio
async def test_a_scaled_to_zero_revision_is_still_a_valid_rollback_target(monkeypatch):
    """Cloud Run reports Active=False for any revision with no instances running.
    That is its resting state, not a fault, and must not block a rollback."""
    async def fake_state(service): return {"traffic": [{"revision": "v42", "percent": 100}]}
    async def fake_revs(service):
        return {"revisions": [
            {"name": "v41", "healthy": True, "serving_traffic": False,
             "raw_conditions": {"Ready": "CONDITION_SUCCEEDED", "Active": "CONDITION_FAILED"}},
            {"name": "v42", "healthy": True, "serving_traffic": True},
        ]}
    monkeypatch.setattr(freshness, "_service_state", fake_state)
    monkeypatch.setattr(freshness, "_revisions", fake_revs)

    verdict = await freshness.revalidate(_proposal(service="checkout-api", revision="v41"))
    assert verdict.stale is False
