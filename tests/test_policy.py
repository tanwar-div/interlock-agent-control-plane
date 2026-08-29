from __future__ import annotations

from interlock.blastradius.scorer import score_proposal
from interlock.common.models import (
    ActionProposal,
    AgentCard,
    Alert,
    Decision,
    GuardCategory,
    GuardVerdict,
    Incident,
    Severity,
)
from interlock.policy.engine import PolicyEngine


def _card(tools: list[str], ceiling: Severity = Severity.HIGH) -> AgentCard:
    return AgentCard(
        agent_id="a", display_name="Remediation",
        spiffe_id="spiffe://interlock.internal/ns/sre/agent/remediation",
        namespace="sre", public_key_pem="x", allowed_tools=tools, max_severity=ceiling,
    )


def _evaluate(action_type, *, tools=None, ceiling=Severity.HIGH, guard=None,
              incident=None, **params):
    proposal = ActionProposal(
        incident_id="inc", actor="spiffe://interlock.internal/ns/sre/agent/remediation",
        action_type=action_type, target=params.get("service") or params.get("instance") or "svc",
        parameters=params,
    )
    radius = score_proposal(proposal, budget_remaining_usd=25.0)
    card = _card(tools if tools is not None else [action_type], ceiling)
    return PolicyEngine().evaluate(
        proposal=proposal, blast_radius=radius, card=card, guard=guard,
        incident=incident or Incident(alert=Alert(title="t")),
    )


def test_safe_action_is_allowed():
    assert _evaluate("run.services.rollback", service="api", revision="v1").decision is Decision.ALLOW


def test_action_absent_from_card_is_denied():
    decision = _evaluate("run.services.rollback", tools=["logging.entries.list"], service="api")
    assert decision.decision is Decision.DENY
    assert "identity.capability" in decision.matched_rules


def test_blocked_guard_denies_regardless_of_severity():
    decision = _evaluate(
        "run.services.rollback", service="api", revision="v1",
        guard=GuardVerdict(blocked=True, categories=[GuardCategory.PROMPT_INJECTION]),
    )
    assert decision.decision is Decision.DENY
    assert "guard.blocked" in decision.matched_rules


def test_irreversible_data_loss_is_never_autonomous():
    decision = _evaluate("sql.instances.delete", instance="prod-db")
    assert decision.decision is Decision.DENY
    assert "safety.irreversible_data_loss" in decision.matched_rules


def test_privilege_change_requires_a_human():
    decision = _evaluate(
        "storage.buckets.setIamPolicy", bucket="b",
        member="serviceAccount:x@y.iam.gserviceaccount.com", role="roles/storage.objectViewer",
    )
    assert decision.decision in (Decision.REQUIRE_APPROVAL, Decision.DENY)
    assert "safety.privilege_change" in decision.matched_rules


def test_runaway_action_loop_is_halted():
    incident = Incident(alert=Alert(title="t"), actions_taken=25)
    decision = _evaluate("run.services.rollback", incident=incident, service="api", revision="v1")
    assert decision.decision is Decision.DENY
    assert "budget.action_count" in decision.matched_rules


def test_overspend_is_caught():
    decision = _evaluate("compute.instances.insert", machine_type="n2-standard-64", count=5)
    assert decision.decision is Decision.DENY
    assert "budget.spend" in decision.matched_rules


def test_severity_ceiling_on_the_identity_card_binds():
    decision = _evaluate("sql.instances.restart", ceiling=Severity.LOW, instance="prod-db")
    assert decision.decision is Decision.DENY
    assert "identity.severity_ceiling" in decision.matched_rules


def test_every_decision_explains_itself():
    decision = _evaluate("sql.instances.delete", instance="prod-db")
    assert decision.reasons and len(decision.reasons) == len(decision.matched_rules)
