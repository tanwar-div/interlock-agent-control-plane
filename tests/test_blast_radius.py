"""The scorer is the last line of defence, so it is tested as one."""
from __future__ import annotations

from interlock.blastradius.scorer import score_proposal
from interlock.common.models import ActionProposal, Reversibility, Severity


def _proposal(action_type: str, target: str = "svc", **params) -> ActionProposal:
    return ActionProposal(
        incident_id="inc_test", actor="spiffe://test", action_type=action_type,
        target=target, parameters=params,
    )


def test_read_only_actions_are_negligible():
    assert score_proposal(_proposal("logging.entries.list")).severity is Severity.NEGLIGIBLE


def test_rollback_is_safe_enough_to_automate():
    result = score_proposal(_proposal("run.services.rollback", service="api", revision="v1"))
    assert result.severity <= Severity.LOW
    assert result.reversibility is Reversibility.REVERSIBLE


def test_unknown_action_fails_closed():
    result = score_proposal(_proposal("totally.made.up.action"))
    assert result.unknown_action is True
    assert result.severity is Severity.CATASTROPHIC
    assert result.score == 100.0


def test_public_principal_maximises_privilege_risk():
    result = score_proposal(
        _proposal("storage.buckets.setIamPolicy", bucket="b", member="allUsers", role="roles/storage.objectViewer")
    )
    assert result.privilege_risk == 4
    assert result.severity is Severity.CATASTROPHIC
    assert any("public principal" in f for f in result.factors)


def test_irreversible_data_destruction_is_catastrophic():
    result = score_proposal(_proposal("sql.instances.delete", instance="prod-db"))
    assert result.reversibility is Reversibility.IRREVERSIBLE
    assert result.data_risk == 4
    assert result.severity is Severity.CATASTROPHIC


def test_cost_is_projected_and_bounded_by_budget():
    result = score_proposal(
        _proposal("compute.instances.insert", machine_type="n2-standard-64", count=5),
        budget_remaining_usd=25.0,
    )
    assert result.cost_ceiling_usd > 300
    assert result.severity is Severity.CATASTROPHIC
    assert any("exceeds remaining incident budget" in f for f in result.factors)


def test_production_target_raises_scope():
    dev = score_proposal(_proposal("sql.instances.restart", target="dev-db", instance="dev-db"))
    prod = score_proposal(_proposal("sql.instances.restart", target="prod-db", instance="prod-db"))
    assert prod.score > dev.score


def test_wildcard_target_maximises_scope():
    assert score_proposal(_proposal("storage.objects.delete", target="*", bucket="b")).scope == 4


def test_force_flag_removes_reversibility():
    result = score_proposal(_proposal("run.services.update_env", service="api", force=True))
    assert result.reversibility is Reversibility.IRREVERSIBLE


def test_scoring_is_deterministic():
    p = _proposal("run.services.update_traffic", service="api", revision="v2")
    assert score_proposal(p).model_dump() == score_proposal(p).model_dump()
