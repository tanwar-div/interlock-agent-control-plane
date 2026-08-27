"""Deterministic blast-radius scoring.

Nothing in this module calls a language model. Given the same proposal it
always returns the same score, and every point of that score is attributable to
a named factor. That property is what allows the governance plane to be trusted
even when the reasoning plane has been manipulated.

Design rules:
  1. The catalogue supplies a floor. Parameters may raise risk, never lower it.
  2. An unrecognised action type scores CATASTROPHIC. Fail closed, always.
  3. Every adjustment appends a human-readable factor string.
"""
from __future__ import annotations

import re
from typing import Any

from interlock.blastradius.catalog import ActionSpec, lookup
from interlock.common.models import ActionProposal, BlastRadius, Reversibility, Severity

# Principals that expose a resource to the entire internet.
_PUBLIC_PRINCIPALS = {"allusers", "allauthenticatedusers"}

# Substrings that mark a target as production.
_PROD_MARKERS = ("prod", "production", "live", "customer")

# Roles that confer broad control.
_DANGEROUS_ROLES = (
    "roles/owner",
    "roles/editor",
    "roles/iam.securityadmin",
    "roles/iam.serviceaccountadmin",
    "roles/resourcemanager.projectiamadmin",
    "roles/storage.admin",
)

_CIDR_ANY = ("0.0.0.0/0", "::/0")

# Rough per-hour on-demand prices used to project a cost ceiling. These are
# intentionally conservative over-estimates: the scorer's job is to bound the
# worst case, not to bill accurately.
_MACHINE_HOURLY_USD = {
    "e2-micro": 0.010, "e2-small": 0.021, "e2-medium": 0.042,
    "n2-standard-2": 0.097, "n2-standard-4": 0.194, "n2-standard-8": 0.389,
    "n2-standard-16": 0.778, "n2-standard-32": 1.556, "n2-standard-64": 3.113,
    "c3-highcpu-88": 3.700, "m3-ultramem-128": 30.000,
}
_DEFAULT_HOURLY_USD = 0.50
_COST_PROJECTION_HOURS = 24.0

# Weights for the composite score. Data loss dominates because it is the only
# dimension that cannot be bought back.
_WEIGHTS = {"data_risk": 0.32, "availability_risk": 0.26, "privilege_risk": 0.26, "scope": 0.16}

_REVERSIBILITY_MULTIPLIER = {
    Reversibility.REVERSIBLE: 1.0,
    Reversibility.RECOVERABLE: 1.25,
    Reversibility.IRREVERSIBLE: 1.6,
}

_SEVERITY_THRESHOLDS = (
    (Severity.NEGLIGIBLE, 0.0),
    (Severity.LOW, 12.0),
    (Severity.MODERATE, 32.0),
    (Severity.HIGH, 55.0),
    (Severity.CATASTROPHIC, 78.0),
)


def _flatten(value: Any) -> str:
    """Lower-cased flattened text of an arbitrary parameter tree."""
    if isinstance(value, dict):
        return " ".join(f"{k} {_flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(v) for v in value)
    return str(value)


def _as_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _severity_for(score: float) -> Severity:
    result = Severity.NEGLIGIBLE
    for severity, threshold in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            result = severity
    return result


def _project_cost(spec: ActionSpec, params: dict[str, Any], factors: list[str]) -> float:
    """Bound the worst-case 24h cost this action could commit us to."""
    cost = spec.base_cost_usd

    count = _as_int(params.get("count") or params.get("instance_count") or params.get("replicas")) or 1
    machine = str(params.get("machine_type") or params.get("machine") or "").strip().lower()

    if spec.action_type == "compute.instances.insert":
        hourly = _MACHINE_HOURLY_USD.get(machine, _DEFAULT_HOURLY_USD)
        cost = hourly * count * _COST_PROJECTION_HOURS
        factors.append(
            f"cost projection: {count} x {machine or 'unknown machine'} "
            f"@ ${hourly:.3f}/h over {_COST_PROJECTION_HOURS:.0f}h = ${cost:,.2f}"
        )

    if spec.action_type == "run.services.update_scaling":
        max_instances = _as_int(params.get("max_instances")) or 0
        if max_instances:
            # Cloud Run bills per instance-hour while serving; bound the ceiling.
            projected = 0.09 * max_instances * _COST_PROJECTION_HOURS
            cost = max(cost, projected)
            factors.append(
                f"cost projection: max_instances={max_instances} bounds 24h spend at ${projected:,.2f}"
            )

    return round(cost, 2)


def score_proposal(
    proposal: ActionProposal,
    *,
    budget_remaining_usd: float | None = None,
) -> BlastRadius:
    """Score a proposal. Pure function of its inputs."""
    factors: list[str] = []
    spec = lookup(proposal.action_type)

    if spec is None:
        # Fail closed. An action we have never characterised is assumed to be
        # the worst thing it could possibly be.
        return BlastRadius(
            reversibility=Reversibility.IRREVERSIBLE,
            scope=4, data_risk=4, availability_risk=4, privilege_risk=4,
            cost_ceiling_usd=0.0,
            severity=Severity.CATASTROPHIC,
            score=100.0,
            factors=[
                f"action type '{proposal.action_type}' is not in the action catalogue",
                "unknown actions are scored as maximum risk (fail-closed)",
            ],
            unknown_action=True,
        )

    scope = spec.scope
    data_risk = spec.data_risk
    availability_risk = spec.availability_risk
    privilege_risk = spec.privilege_risk
    reversibility = spec.reversibility
    factors.append(f"catalogue baseline for '{spec.action_type}': {spec.description}")

    params = proposal.parameters or {}
    blob = f"{_flatten(params)} {proposal.target}".lower()

    # --- Parameter-sensitive escalations ---------------------------------
    if any(p in blob for p in _PUBLIC_PRINCIPALS):
        privilege_risk = 4
        data_risk = max(data_risk, 3)
        scope = max(scope, 4)
        factors.append("grants access to a public principal (allUsers/allAuthenticatedUsers)")

    for role in _DANGEROUS_ROLES:
        if role in blob:
            privilege_risk = 4
            factors.append(f"binds a highly privileged role: {role}")
            break

    if any(c in blob for c in _CIDR_ANY):
        privilege_risk = max(privilege_risk, 4)
        scope = max(scope, 4)
        factors.append("network rule is open to the entire internet (0.0.0.0/0)")

    target_blob = f"{proposal.target} {_flatten(params.get('labels', {}))}".lower()
    if any(m in target_blob for m in _PROD_MARKERS):
        scope = min(4, scope + 1)
        availability_risk = min(4, availability_risk + 1)
        factors.append("target is identified as a production resource")

    # Wildcards multiply the number of affected resources.
    if re.search(r"[*?]|\ball\b", str(proposal.target).lower()):
        scope = 4
        factors.append("target expression is a wildcard, affecting many resources")

    count = _as_int(params.get("count") or params.get("instance_count") or params.get("replicas"))
    if count and count > 3:
        scope = min(4, max(scope, 2 + (count > 10) + (count > 50)))
        factors.append(f"action affects {count} resources")

    if params.get("force") or params.get("cascade"):
        data_risk = min(4, data_risk + 1)
        reversibility = Reversibility.IRREVERSIBLE
        factors.append("force/cascade flag set, removing normal safety checks")

    if spec.action_type == "sql.instances.delete" and not params.get("final_backup"):
        factors.append("instance deletion requested without a final backup")

    # --- Cost -------------------------------------------------------------
    cost_ceiling = _project_cost(spec, params, factors)

    # --- Composite --------------------------------------------------------
    weighted = (
        _WEIGHTS["data_risk"] * data_risk
        + _WEIGHTS["availability_risk"] * availability_risk
        + _WEIGHTS["privilege_risk"] * privilege_risk
        + _WEIGHTS["scope"] * scope
    )
    multiplier = _REVERSIBILITY_MULTIPLIER[reversibility]
    score = min(100.0, (weighted / 4.0) * 100.0 * multiplier)
    if multiplier > 1.0:
        factors.append(f"{reversibility.value.lower()} action: risk multiplied by {multiplier}")

    severity = _severity_for(score)

    # Spending more than the incident has left is a governance failure
    # regardless of how technically safe the action is.
    if budget_remaining_usd is not None and cost_ceiling > budget_remaining_usd:
        severity = Severity.CATASTROPHIC if cost_ceiling > budget_remaining_usd * 4 else Severity.HIGH
        factors.append(
            f"projected cost ${cost_ceiling:,.2f} exceeds remaining incident budget "
            f"${budget_remaining_usd:,.2f}"
        )

    return BlastRadius(
        reversibility=reversibility,
        scope=scope,
        data_risk=data_risk,
        availability_risk=availability_risk,
        privilege_risk=privilege_risk,
        cost_ceiling_usd=cost_ceiling,
        severity=severity,
        score=round(score, 2),
        factors=factors,
        unknown_action=False,
    )
