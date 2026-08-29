"""Policy evaluation.

The engine turns four independent signals — who is asking (identity), what the
action could destroy (blast radius), whether the surrounding content is hostile
(guard), and what the incident has already spent (budget) — into one of three
outcomes: ALLOW, REQUIRE_APPROVAL, DENY.

Rules are ordered and explicit. Every rule that fires is named in the decision,
so a reviewer can always answer "why was this allowed?" without re-running
anything. The first rule to produce DENY wins; otherwise the most restrictive
outcome across all matching rules is returned.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from interlock.common.config import get_settings
from interlock.common.models import (
    ActionProposal,
    AgentCard,
    BlastRadius,
    Decision,
    GuardVerdict,
    Incident,
    PolicyDecision,
    Reversibility,
    Severity,
)

logger = logging.getLogger(__name__)


@dataclass
class PolicyContext:
    proposal: ActionProposal
    card: AgentCard | None
    blast_radius: BlastRadius
    guard: GuardVerdict | None
    incident: Incident | None
    budget_limit_usd: float
    max_actions: int


@dataclass
class Rule:
    name: str
    description: str
    evaluate: Callable[[PolicyContext], tuple[Decision, str] | None]


def _severity_at_least(ctx: PolicyContext, level: Severity) -> bool:
    return ctx.blast_radius.severity >= level


# ---------------------------------------------------------------------------
# Rule definitions, in evaluation order
# ---------------------------------------------------------------------------


def _rule_guard(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if ctx.guard and ctx.guard.blocked:
        categories = ", ".join(c.value for c in ctx.guard.categories) or "unclassified"
        return Decision.DENY, (
            f"content inspection blocked this action ({categories}). "
            "An action derived from manipulated or sensitive content is never executed."
        )
    return None


def _rule_unknown_action(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if ctx.blast_radius.unknown_action:
        return Decision.DENY, (
            f"action type '{ctx.proposal.action_type}' is not in the action catalogue; "
            "uncatalogued capabilities are denied rather than assumed safe"
        )
    return None


def _rule_identity(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if ctx.card is None:
        return Decision.DENY, "proposing agent could not be authenticated"
    if ctx.card.revoked:
        return Decision.DENY, f"agent {ctx.card.spiffe_id} has been revoked"
    return None


def _rule_capability(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if ctx.card and ctx.proposal.action_type not in ctx.card.allowed_tools:
        return Decision.DENY, (
            f"agent {ctx.card.spiffe_id} is not entitled to '{ctx.proposal.action_type}'"
        )
    return None


def _rule_agent_ceiling(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if ctx.card and ctx.blast_radius.severity > ctx.card.max_severity:
        return Decision.DENY, (
            f"action scores {ctx.blast_radius.severity.value} which exceeds the "
            f"{ctx.card.max_severity.value} ceiling on this agent's identity card"
        )
    return None


def _rule_irreversible_data_loss(ctx: PolicyContext) -> tuple[Decision, str] | None:
    br = ctx.blast_radius
    if br.reversibility is Reversibility.IRREVERSIBLE and br.data_risk >= 3:
        return Decision.DENY, (
            "irreversible action with high data-loss risk is never executed autonomously; "
            "it must be performed by a human with the incident context in hand"
        )
    return None


def _rule_action_budget(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if ctx.incident and ctx.incident.actions_taken >= ctx.max_actions:
        return Decision.DENY, (
            f"incident has already executed {ctx.incident.actions_taken} actions, "
            f"reaching the ceiling of {ctx.max_actions}; halting to prevent a runaway loop"
        )
    return None


def _rule_spend_budget(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if not ctx.incident:
        return None
    remaining = ctx.budget_limit_usd - ctx.incident.spend_usd
    projected = ctx.blast_radius.cost_ceiling_usd
    if projected <= 0:
        return None
    if projected > remaining:
        return Decision.REQUIRE_APPROVAL, (
            f"projected cost ${projected:,.2f} exceeds the ${remaining:,.2f} remaining "
            f"of this incident's ${ctx.budget_limit_usd:,.2f} budget"
        )
    return None


# Threshold 3, not 4: the catalogue assigns 3 to operations that alter an IAM
# policy at all. Granting one named service account access is still a change to
# who can reach the data, and is not a decision an agent should make alone.
# Only a fully public grant reaches 4, and that is a difference of degree.
_PRIVILEGE_REVIEW_THRESHOLD = 3


def _rule_privilege_change(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if ctx.blast_radius.privilege_risk >= _PRIVILEGE_REVIEW_THRESHOLD:
        return Decision.REQUIRE_APPROVAL, (
            "action changes who can access a resource; access changes always require "
            "a human decision"
        )
    return None


def _rule_severity_gate(ctx: PolicyContext) -> tuple[Decision, str] | None:
    severity = ctx.blast_radius.severity
    if severity <= Severity.LOW:
        return Decision.ALLOW, f"blast radius is {severity.value}; safe to execute autonomously"
    if severity is Severity.MODERATE:
        return Decision.REQUIRE_APPROVAL, (
            f"blast radius is {severity.value}; a human confirms before execution"
        )
    if severity is Severity.HIGH:
        return Decision.REQUIRE_APPROVAL, (
            f"blast radius is {severity.value}; execution is held pending explicit approval"
        )
    return Decision.DENY, (
        f"blast radius is {severity.value}; the action is refused outright and escalated"
    )


def _rule_degraded_guard(ctx: PolicyContext) -> tuple[Decision, str] | None:
    if ctx.guard and ctx.guard.degraded and _severity_at_least(ctx, Severity.MODERATE):
        return Decision.REQUIRE_APPROVAL, (
            "content inspection ran in a degraded mode; a non-trivial action is not "
            "executed on unverified input"
        )
    return None


# Ordered most-specific first, so that the leading reason on a decision is the
# most informative one a reviewer could be given. Evaluation does not stop at
# the first DENY: every rule that fires is recorded, because "this was denied
# for four independent reasons" is materially different evidence from "this was
# denied for one".
DEFAULT_RULES: list[Rule] = [
    Rule("guard.blocked", "Deny when content inspection flags the surrounding content", _rule_guard),
    Rule("catalogue.unknown", "Deny uncatalogued action types", _rule_unknown_action),
    Rule("identity.unauthenticated", "Deny unauthenticated or revoked agents", _rule_identity),
    Rule("identity.capability", "Deny tools absent from the agent card", _rule_capability),
    Rule("safety.irreversible_data_loss", "Never auto-execute irreversible data destruction", _rule_irreversible_data_loss),
    Rule("budget.action_count", "Halt runaway action loops", _rule_action_budget),
    Rule("budget.spend", "Hold actions that would exceed the incident budget", _rule_spend_budget),
    Rule("safety.privilege_change", "Access changes require a human", _rule_privilege_change),
    Rule("identity.severity_ceiling", "Deny actions above the agent's severity ceiling", _rule_agent_ceiling),
    Rule("guard.degraded", "Hold non-trivial actions when inspection degraded", _rule_degraded_guard),
    Rule("severity.gate", "Route on blast-radius severity", _rule_severity_gate),
]

_RESTRICTIVENESS = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.DENY: 2}


class PolicyEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = rules or DEFAULT_RULES
        self._settings = get_settings()

    def evaluate(
        self,
        *,
        proposal: ActionProposal,
        blast_radius: BlastRadius,
        card: AgentCard | None = None,
        guard: GuardVerdict | None = None,
        incident: Incident | None = None,
    ) -> PolicyDecision:
        ctx = PolicyContext(
            proposal=proposal,
            card=card,
            blast_radius=blast_radius,
            guard=guard,
            incident=incident,
            budget_limit_usd=self._settings.incident_budget_usd,
            max_actions=self._settings.max_actions_per_incident,
        )

        outcome = Decision.ALLOW
        reasons: list[str] = []
        matched: list[str] = []

        for rule in self._rules:
            try:
                result = rule.evaluate(ctx)
            except Exception as exc:
                logger.exception("policy rule %s raised", rule.name)
                matched.append(rule.name)
                reasons.append(f"rule '{rule.name}' failed to evaluate ({exc}); failing closed")
                outcome = Decision.DENY
                continue

            if result is None:
                continue

            decision, reason = result
            matched.append(rule.name)
            reasons.append(reason)

            if _RESTRICTIVENESS[decision] > _RESTRICTIVENESS[outcome]:
                outcome = decision

        if not matched:
            # No rule expressed an opinion. Default to requiring a human rather
            # than to permitting.
            outcome = Decision.REQUIRE_APPROVAL
            reasons.append("no policy rule matched; defaulting to human review")

        return PolicyDecision(
            decision=outcome,
            reasons=reasons,
            matched_rules=matched,
            requires_approval_from="sre-oncall" if outcome is Decision.REQUIRE_APPROVAL else None,
            blast_radius=blast_radius,
            guard=guard,
        )
