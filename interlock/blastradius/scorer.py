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
from interlock.common.config import get_settings
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

    return compose(
        reversibility=reversibility,
        dimensions={
            "data_risk": data_risk,
            "availability_risk": availability_risk,
            "privilege_risk": privilege_risk,
            "scope": scope,
        },
        cost_ceiling=cost_ceiling,
        factors=factors,
        budget_remaining_usd=budget_remaining_usd,
        scored_by="deterministic",
    )


def catalogue_floor(spec: ActionSpec) -> dict[str, int]:
    """The human-set baseline for an action, before any argument is considered."""
    return {
        "data_risk": spec.data_risk,
        "availability_risk": spec.availability_risk,
        "privilege_risk": spec.privilege_risk,
        "scope": spec.scope,
    }


def compose(
    *,
    reversibility: Reversibility,
    dimensions: dict[str, int],
    cost_ceiling: float,
    factors: list[str],
    budget_remaining_usd: float | None = None,
    scored_by: str = "deterministic",
    model_assessment: dict[str, Any] | None = None,
) -> BlastRadius:
    """Turn four dimensions plus a reversibility into a severity.

    Shared by both scoring paths so that a model-derived score and a
    heuristic-derived score are always combined the same way, and are therefore
    directly comparable.
    """
    weighted = sum(_WEIGHTS[name] * dimensions[name] for name in _WEIGHTS)
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
        scope=dimensions["scope"],
        data_risk=dimensions["data_risk"],
        availability_risk=dimensions["availability_risk"],
        privilege_risk=dimensions["privilege_risk"],
        cost_ceiling_usd=cost_ceiling,
        severity=severity,
        score=round(score, 2),
        factors=factors,
        unknown_action=False,
        scored_by=scored_by,
        model_assessment=model_assessment,
    )


async def score_proposal_with_model(
    proposal: ActionProposal,
    *,
    budget_remaining_usd: float | None = None,
) -> BlastRadius:
    """Score an action, preferring a model assessment over the heuristics.

    The model sees only the action type, its description, the target and the
    literal arguments. It never sees the proposing agent's reasoning, and each
    assessment is an independent request with no memory of any other.

    Two invariants survive regardless of what the model returns:

      * **The catalogue is a floor.** Each dimension is raised to at least the
        human-set baseline for that action. The model can decide an operation is
        more dangerous than the catalogue says; it cannot decide it is safer.
      * **Reversibility is never asked.** Whether an action can be undone is
        fixed by a human and is not a judgement a model is invited to make.

    If the model is unavailable for any reason — rate limited, timed out, or
    returning something unparseable — the deterministic scorer runs instead. A
    missing model costs sophistication, never safety.
    """
    settings = get_settings()
    spec = lookup(proposal.action_type)

    # An uncatalogued action has no floor to clamp against and no description to
    # assess. It fails closed without consulting anything.
    if spec is None or not settings.model_scoring_enabled:
        return score_proposal(proposal, budget_remaining_usd=budget_remaining_usd)

    from interlock.blastradius.model_scorer import get_model_scorer

    assessment = await get_model_scorer().assess(proposal, spec)
    if assessment is None:
        result = score_proposal(proposal, budget_remaining_usd=budget_remaining_usd)
        result.factors.append(
            "model assessment unavailable; scored by deterministic heuristics instead"
        )
        result.scored_by = "deterministic-fallback"
        return result

    # The heuristics are the floor, not merely the catalogue. Live testing
    # showed the assessor under-scoring well-understood dangers — it scored a
    # grant to allUsers as affecting two resources rather than the whole
    # internet — while correctly catching risks no pattern could express, such
    # as 1000 instances exhausting a downstream connection pool. Taking the
    # larger of the two on every dimension keeps what each is good at: the
    # model can add danger it alone perceives, and can subtract none.
    deterministic = score_proposal(proposal, budget_remaining_usd=budget_remaining_usd)
    floor = {
        "data_risk": max(spec.data_risk, deterministic.data_risk),
        "availability_risk": max(spec.availability_risk, deterministic.availability_risk),
        "privilege_risk": max(spec.privilege_risk, deterministic.privilege_risk),
        "scope": max(spec.scope, deterministic.scope),
    }
    proposed = {
        "data_risk": assessment.data_risk,
        "availability_risk": assessment.availability_risk,
        "privilege_risk": assessment.privilege_risk,
        "scope": assessment.scope,
    }
    dimensions = {name: max(floor[name], proposed[name]) for name in floor}
    clamped = [name for name in floor if proposed[name] < floor[name]]

    factors = [
        f"assessed by {assessment.model} from the action and its arguments alone",
    ]
    # Reversibility can still be tightened by the heuristics, e.g. a force flag.
    reversibility = deterministic.reversibility
    if assessment.reason:
        factors.append(f"assessor: {assessment.reason}")
    for name in ("data_risk", "availability_risk", "privilege_risk", "scope"):
        if proposed[name] > floor[name]:
            factors.append(
                f"{name} raised from the catalogue baseline of {floor[name]} to "
                f"{proposed[name]} on the strength of the arguments"
            )
    if clamped:
        factors.append(
            "the assessor scored "
            + ", ".join(f"{n} below the deterministic baseline" for n in clamped)
            + "; the higher baseline was applied instead"
        )

    cost_factors: list[str] = []
    cost_ceiling = _project_cost(spec, proposal.parameters or {}, cost_factors)
    factors.extend(cost_factors)

    return compose(
        reversibility=reversibility,
        dimensions=dimensions,
        cost_ceiling=cost_ceiling,
        factors=factors,
        budget_remaining_usd=budget_remaining_usd,
        scored_by="model+floor" if clamped else "model",
        model_assessment={
            **assessment.as_dict(),
            "deterministic_score": deterministic.score,
            "deterministic_severity": deterministic.severity.value,
        },
    )
