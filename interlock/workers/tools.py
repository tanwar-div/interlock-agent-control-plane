"""Tools available to the SRE worker fleet.

Every tool is declared with `@governed`, binding it to an entry in the action
catalogue. The Interlock plugin intercepts each call before it runs; by the
time a function body here executes, the action has already been authenticated,
scored and permitted.

Undeclared tools are refused by the plugin, so adding a capability is a
deliberate two-step act: write the function, and characterise its risk.
"""
from __future__ import annotations

import logging
from typing import Any

from google.adk.tools import ToolContext

from interlock.common.config import get_settings
from interlock.common.models import utcnow
from interlock.runtime.governed import governed
from interlock.workers import cloud

logger = logging.getLogger(__name__)


def _fail(exc: Exception) -> dict[str, Any]:
    """Turn a provider failure into something the model can reason about."""
    return {"ok": False, "error": str(exc)[:900]}


# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------


@governed(
    action_type="logging.entries.list",
    summary="Read recent log entries for a service",
    target_param="service",
)
async def investigate_logs(
    service: str,
    minutes: int = 15,
    severity: str = "WARNING",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Read recent Cloud Logging entries for a Cloud Run service.

    Args:
        service: Cloud Run service name.
        minutes: How far back to look.
        severity: Minimum severity, e.g. WARNING or ERROR.
    """
    try:
        return {"ok": True, **cloud.read_logs(service=service, minutes=minutes, severity=severity)}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@governed(
    action_type="monitoring.timeSeries.list",
    summary="Read metric time series for a service",
    target_param="service",
)
async def investigate_metrics(
    service: str,
    metric: str = "request_latencies",
    minutes: int = 30,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Read a Cloud Monitoring metric for a Cloud Run service.

    Args:
        service: Cloud Run service name.
        metric: One of request_count, request_latencies, instance_count, cpu, memory.
        minutes: Lookback window.
    """
    try:
        return {"ok": True, **cloud.read_metrics(service=service, metric=metric, minutes=minutes)}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@governed(
    action_type="run.services.get",
    summary="Describe a Cloud Run service and its traffic split",
    target_param="service",
)
async def inspect_service(service: str, tool_context: ToolContext | None = None) -> dict[str, Any]:
    """Describe a Cloud Run service, including its current traffic allocation.

    Args:
        service: Cloud Run service name.
    """
    try:
        return {"ok": True, **cloud.describe_service(service=service)}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@governed(
    action_type="run.revisions.list",
    summary="List revisions of a Cloud Run service",
    target_param="service",
)
async def inspect_revisions(
    service: str, limit: int = 10, tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """List recent revisions of a Cloud Run service, newest first.

    Args:
        service: Cloud Run service name.
        limit: Maximum revisions to return.
    """
    try:
        return {"ok": True, **cloud.list_revisions(service=service, limit=limit)}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


@governed(
    action_type="run.services.rollback",
    summary="Shift all traffic to a known-good revision",
    target_param="service",
    scored_params=("service", "revision"),
)
async def rollback_to_revision(
    service: str, revision: str, tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Shift 100% of traffic to a previous, known-good revision.

    Args:
        service: Cloud Run service name.
        revision: The revision to send all traffic to.
    """
    try:
        result = cloud.shift_traffic(service=service, revision=revision, percent=100)
        if tool_context is not None:
            tool_context.state["last_undo_token"] = result.get("undo_token")
        return {"ok": True, **result}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@governed(
    action_type="run.services.update_traffic",
    summary="Change the traffic split across revisions",
    target_param="service",
    scored_params=("service", "revision", "percent"),
)
async def shift_service_traffic(
    service: str, revision: str, percent: int, tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Send a percentage of traffic to a specific revision.

    Args:
        service: Cloud Run service name.
        revision: Target revision.
        percent: Percentage of traffic for that revision (1-100).
    """
    try:
        result = cloud.shift_traffic(service=service, revision=revision, percent=int(percent))
        if tool_context is not None:
            tool_context.state["last_undo_token"] = result.get("undo_token")
        return {"ok": True, **result}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@governed(
    action_type="run.services.update_scaling",
    summary="Change autoscaling bounds for a service",
    target_param="service",
    scored_params=("service", "min_instances", "max_instances"),
)
async def adjust_service_scaling(
    service: str,
    min_instances: int | None = None,
    max_instances: int | None = None,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Change a Cloud Run service's minimum and maximum instance counts.

    Args:
        service: Cloud Run service name.
        min_instances: New minimum instance count.
        max_instances: New maximum instance count.
    """
    try:
        result = cloud.update_scaling(
            service=service, min_instances=min_instances, max_instances=max_instances
        )
        if tool_context is not None:
            tool_context.state["last_undo_token"] = result.get("undo_token")
        return {"ok": True, **result}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@governed(
    action_type="sql.backupRuns.create",
    summary="Take an on-demand database backup",
    target_param="instance",
)
async def take_database_backup(
    instance: str, tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Take an on-demand Cloud SQL backup before a risky change.

    Args:
        instance: Cloud SQL instance id.
    """
    try:
        return {"ok": True, **cloud.create_sql_backup(instance=instance)}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


# ---------------------------------------------------------------------------
# High-privilege capabilities
#
# These are real. They exist so that the governance layer is exercised against
# operations that could genuinely cause harm, rather than against stubs.
# ---------------------------------------------------------------------------


@governed(
    action_type="storage.buckets.setIamPolicy",
    summary="Grant a principal access to a storage bucket",
    target_param="bucket",
    scored_params=("bucket", "member", "role"),
)
async def grant_bucket_access(
    bucket: str, member: str, role: str, tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Grant a principal a role on a Cloud Storage bucket.

    Args:
        bucket: Bucket name.
        member: Principal, e.g. user:a@b.com or serviceAccount:x@y.
        role: IAM role, e.g. roles/storage.objectViewer.
    """
    try:
        result = cloud.set_bucket_iam(bucket=bucket, member=member, role=role)
        if tool_context is not None:
            tool_context.state["last_undo_token"] = result.get("undo_token")
        return {"ok": True, **result}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@governed(
    action_type="compute.instances.insert",
    summary="Provision compute capacity",
    scored_params=("machine_type", "count", "zone"),
)
async def provision_compute_capacity(
    machine_type: str, count: int = 1, zone: str = "", tool_context: ToolContext | None = None
) -> dict[str, Any]:
    """Provision compute instances to add capacity.

    Args:
        machine_type: Machine type, e.g. n2-standard-4.
        count: How many instances to create.
        zone: Target zone; defaults to the configured region's -a zone.
    """
    try:
        result = cloud.create_compute_instances(
            machine_type=machine_type, count=int(count), zone=zone
        )
        return {"ok": True, **result}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


# ---------------------------------------------------------------------------
# Incident bookkeeping
# ---------------------------------------------------------------------------


@governed(action_type="incident.note.append", summary="Record a finding on the incident")
async def record_finding(finding: str, tool_context: ToolContext | None = None) -> dict[str, Any]:
    """Record an investigative finding on the incident record.

    Args:
        finding: A single, specific observation with the evidence behind it.
    """
    if tool_context is None:
        return {"ok": False, "error": "no tool context"}
    from interlock.common.store import get_store

    settings = get_settings()
    store = get_store()
    incident_id = tool_context.state.get("incident_id", "")
    if not incident_id:
        return {"ok": False, "error": "no incident bound to this run"}

    raw = await store.get(settings.collection_incidents, incident_id) or {}
    findings = list(raw.get("findings") or [])
    findings.append(finding)
    await store.patch(
        settings.collection_incidents,
        incident_id,
        {"findings": findings, "updated_at": utcnow().isoformat()},
    )
    return {"ok": True, "recorded": finding, "total_findings": len(findings)}


@governed(action_type="incident.escalate", summary="Hand the incident to a human")
async def escalate_to_human(reason: str, tool_context: ToolContext | None = None) -> dict[str, Any]:
    """Escalate the incident to a human operator and stop autonomous work.

    Args:
        reason: Why autonomous remediation cannot safely continue.
    """
    if tool_context is not None:
        tool_context.state["escalation_reason"] = reason
        tool_context.state["terminal_intent"] = "ESCALATED"
    return {"ok": True, "escalated": True, "reason": reason}


@governed(action_type="incident.resolve", summary="Close the incident as resolved")
async def resolve_incident(summary: str, tool_context: ToolContext | None = None) -> dict[str, Any]:
    """Close the incident, recording how it was resolved.

    Args:
        summary: What was wrong, what was done, and the evidence it is fixed.
    """
    if tool_context is not None:
        tool_context.state["resolution"] = summary
        tool_context.state["terminal_intent"] = "RESOLVED"
    return {"ok": True, "resolved": True, "summary": summary}


# Tool groupings used when constructing the fleet.
INVESTIGATION_TOOLS = [investigate_logs, investigate_metrics, inspect_service, inspect_revisions]
REMEDIATION_TOOLS = [
    rollback_to_revision,
    shift_service_traffic,
    adjust_service_scaling,
    take_database_backup,
    grant_bucket_access,
    provision_compute_capacity,
]
BOOKKEEPING_TOOLS = [record_finding, escalate_to_human, resolve_incident]
