"""Point-of-action revalidation.

An agent decides what to do using evidence it gathered minutes ago. In that
gap the world moves: the revision it wants to roll back to gets deleted, the
traffic split it is correcting gets corrected by someone else, the instance it
is about to restart is already gone.

Acting on a stale snapshot is how an agent does the right thing at the wrong
moment. So immediately before a mutating action executes — after policy has
allowed it, with nothing else in between — the target is read from the live API
one more time and the action is confirmed still coherent.

This is cheap: one read per mutation, on the actions where staleness can
actually cause harm.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from interlock.common.models import ActionProposal
from interlock.workers import cloud

logger = logging.getLogger(__name__)


@dataclass
class FreshnessVerdict:
    stale: bool
    detail: str = ""
    observed: dict | None = None
    # True when the check itself could not run. Freshness is an additional
    # safeguard, not a gate: an unreachable API must not block remediation
    # during the outage that made it unreachable.
    degraded: bool = False


async def _service_state(service: str) -> dict:
    return await asyncio.to_thread(cloud.describe_service, service=service)


async def _revisions(service: str) -> dict:
    return await asyncio.to_thread(cloud.list_revisions, service=service, limit=25)


async def _check_traffic_shift(proposal: ActionProposal) -> FreshnessVerdict:
    service = str(proposal.parameters.get("service") or proposal.target)
    revision = str(proposal.parameters.get("revision") or "")
    if not service or not revision:
        return FreshnessVerdict(stale=False)

    try:
        current, revs = await asyncio.gather(_service_state(service), _revisions(service))
    except cloud.NotConfiguredError:
        return FreshnessVerdict(stale=False, degraded=True, detail="no cloud project configured")
    except Exception as exc:  # noqa: BLE001
        logger.warning("freshness check failed for %s: %s", service, exc)
        return FreshnessVerdict(stale=False, degraded=True, detail=str(exc)[:300])

    names = {r["name"]: r for r in revs.get("revisions", [])}
    target = names.get(revision)

    if target is None:
        return FreshnessVerdict(
            stale=True,
            observed={"available_revisions": sorted(names)[:10]},
            detail=(
                f"revision '{revision}' no longer exists on service '{service}'. "
                f"Currently available: {', '.join(sorted(names)[:6]) or 'none'}."
            ),
        )

    if str(target.get("ready", "")).upper() not in ("CONDITION_SUCCEEDED", "TRUE", "READY", ""):
        return FreshnessVerdict(
            stale=True,
            observed={"revision": revision, "ready": target.get("ready")},
            detail=(
                f"revision '{revision}' is not currently healthy "
                f"(Ready={target.get('ready')}); rolling onto it would not restore service."
            ),
        )

    # Somebody — or a previous phase — may already have done this.
    for entry in current.get("traffic", []):
        if entry.get("revision") == revision and entry.get("percent", 0) >= 100:
            return FreshnessVerdict(
                stale=True,
                observed={"traffic": current.get("traffic")},
                detail=(
                    f"service '{service}' is already serving 100% from '{revision}'. "
                    "The change has already been made; re-applying it would be a no-op "
                    "and the incident should be re-verified instead."
                ),
            )

    return FreshnessVerdict(stale=False, observed={"traffic": current.get("traffic")})


async def _check_scaling(proposal: ActionProposal) -> FreshnessVerdict:
    service = str(proposal.parameters.get("service") or proposal.target)
    try:
        current = await _service_state(service)
    except cloud.NotConfiguredError:
        return FreshnessVerdict(stale=False, degraded=True)
    except Exception as exc:  # noqa: BLE001
        return FreshnessVerdict(stale=False, degraded=True, detail=str(exc)[:300])

    wanted_max = proposal.parameters.get("max_instances")
    wanted_min = proposal.parameters.get("min_instances")
    if (
        (wanted_max is None or int(wanted_max) == current.get("max_instance_count"))
        and (wanted_min is None or int(wanted_min) == current.get("min_instance_count"))
    ):
        return FreshnessVerdict(
            stale=True,
            observed=current,
            detail=(
                f"service '{service}' already has these scaling bounds "
                f"(min={current.get('min_instance_count')}, max={current.get('max_instance_count')}); "
                "the change would have no effect."
            ),
        )
    return FreshnessVerdict(stale=False, observed=current)


# Only actions where a stale snapshot can cause real harm are checked.
_CHECKS = {
    "run.services.rollback": _check_traffic_shift,
    "run.services.update_traffic": _check_traffic_shift,
    "run.services.update_scaling": _check_scaling,
}


def is_checked(action_type: str) -> bool:
    return action_type in _CHECKS


async def revalidate(proposal: ActionProposal) -> FreshnessVerdict:
    """Confirm a permitted action still makes sense against live state."""
    check = _CHECKS.get(proposal.action_type)
    if check is None:
        return FreshnessVerdict(stale=False)
    return await check(proposal)
