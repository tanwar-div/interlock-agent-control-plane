"""Real Google Cloud operations.

These are the calls that actually touch infrastructure. They are deliberately
kept free of any ADK or governance imports so that they can be unit-tested and
reasoned about on their own: this module knows how to change the world, and
knows nothing about whether it is allowed to.

Every function raises `CloudError` with an actionable message rather than
letting a provider exception escape, so the agent receives something it can
reason about instead of a stack trace.
"""
from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from interlock.common.config import get_settings

logger = logging.getLogger(__name__)


class CloudError(RuntimeError):
    pass


class NotConfiguredError(CloudError):
    """Raised when no Google Cloud project is configured."""


def _project() -> str:
    project = get_settings().project_id
    if not project:
        raise NotConfiguredError(
            "INTERLOCK_PROJECT_ID is not set, so no Google Cloud operation can be performed."
        )
    return project


def _location() -> str:
    return get_settings().location


def _service_path(service: str) -> str:
    return f"projects/{_project()}/locations/{_location()}/services/{service}"


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------


def read_logs(
    *,
    service: str,
    minutes: int = 15,
    severity: str = "DEFAULT",
    limit: int = 40,
    extra_filter: str = "",
) -> dict[str, Any]:
    """Read recent Cloud Logging entries for a Cloud Run service."""
    from google.cloud import logging as cloud_logging

    project = _project()
    since = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=minutes)
    parts = [
        'resource.type="cloud_run_revision"',
        f'resource.labels.service_name="{service}"',
        f'timestamp>="{since.isoformat()}"',
    ]
    if severity and severity.upper() != "DEFAULT":
        parts.append(f"severity>={severity.upper()}")
    if extra_filter:
        parts.append(f"({extra_filter})")
    log_filter = " AND ".join(parts)

    try:
        client = cloud_logging.Client(project=project)
        entries = list(
            client.list_entries(
                filter_=log_filter,
                order_by=cloud_logging.DESCENDING,
                max_results=limit,
            )
        )
    except Exception as exc:
        raise CloudError(f"could not read logs for '{service}': {exc}") from exc

    rendered: list[dict[str, Any]] = []
    for entry in entries:
        payload = entry.payload
        if isinstance(payload, dict):
            message = payload.get("message") or payload.get("msg") or str(payload)
        else:
            message = str(payload)
        rendered.append(
            {
                "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
                "severity": str(entry.severity or ""),
                "message": message[:1500],
            }
        )

    counts: dict[str, int] = {}
    for row in rendered:
        counts[row["severity"]] = counts.get(row["severity"], 0) + 1

    return {
        "service": service,
        "window_minutes": minutes,
        "filter": log_filter,
        "entry_count": len(rendered),
        "severity_counts": counts,
        "entries": rendered,
    }


def read_metrics(
    *, service: str, metric: str = "request_latencies", minutes: int = 30
) -> dict[str, Any]:
    """Read a Cloud Run metric time series from Cloud Monitoring."""
    from google.cloud import monitoring_v3

    project = _project()
    metric_types = {
        "request_count": "run.googleapis.com/request_count",
        "request_latencies": "run.googleapis.com/request_latencies",
        "instance_count": "run.googleapis.com/container/instance_count",
        "cpu": "run.googleapis.com/container/cpu/utilizations",
        "memory": "run.googleapis.com/container/memory/utilizations",
    }
    metric_type = metric_types.get(metric, metric_types["request_latencies"])

    now = dt.datetime.now(dt.UTC)
    interval = monitoring_v3.TimeInterval(
        {
            "end_time": {"seconds": int(now.timestamp())},
            "start_time": {"seconds": int((now - dt.timedelta(minutes=minutes)).timestamp())},
        }
    )
    query_filter = (
        f'metric.type="{metric_type}" AND '
        f'resource.labels.service_name="{service}"'
    )

    try:
        client = monitoring_v3.MetricServiceClient()
        series = list(
            client.list_time_series(
                request={
                    "name": f"projects/{project}",
                    "filter": query_filter,
                    "interval": interval,
                    "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                }
            )
        )
    except Exception as exc:
        raise CloudError(f"could not read metric '{metric}' for '{service}': {exc}") from exc

    summary: list[dict[str, Any]] = []
    for ts in series[:8]:
        values: list[float] = []
        for point in ts.points:
            value = point.value
            if value.double_value:
                values.append(float(value.double_value))
            elif value.int64_value:
                values.append(float(value.int64_value))
            elif value.distribution_value and value.distribution_value.count:
                values.append(float(value.distribution_value.mean))
        if not values:
            continue
        summary.append(
            {
                "labels": dict(ts.metric.labels),
                "points": len(values),
                "latest": round(values[0], 3),
                "min": round(min(values), 3),
                "max": round(max(values), 3),
                "mean": round(sum(values) / len(values), 3),
            }
        )

    return {
        "service": service,
        "metric": metric,
        "metric_type": metric_type,
        "window_minutes": minutes,
        "series": summary,
    }


def describe_service(*, service: str) -> dict[str, Any]:
    """Describe a Cloud Run service, including its current traffic split."""
    from google.cloud import run_v2

    name = _service_path(service)  # validates configuration before we build a client
    try:
        client = run_v2.ServicesClient()
        svc = client.get_service(name=name)
    except Exception as exc:
        raise CloudError(f"could not describe service '{service}': {exc}") from exc

    traffic = [
        {
            "revision": t.revision or "(latest)",
            "percent": t.percent,
            "tag": t.tag or "",
        }
        for t in (svc.traffic_statuses or [])
    ]
    container = svc.template.containers[0] if svc.template.containers else None
    return {
        "service": service,
        "uri": svc.uri,
        "latest_ready_revision": svc.latest_ready_revision.split("/")[-1] if svc.latest_ready_revision else "",
        "latest_created_revision": svc.latest_created_revision.split("/")[-1] if svc.latest_created_revision else "",
        "traffic": traffic,
        "image": container.image if container else "",
        "min_instance_count": svc.template.scaling.min_instance_count if svc.template.scaling else 0,
        "max_instance_count": svc.template.scaling.max_instance_count if svc.template.scaling else 0,
        "update_time": svc.update_time.isoformat() if svc.update_time else "",
    }


def list_revisions(*, service: str, limit: int = 10) -> dict[str, Any]:
    """List recent revisions of a Cloud Run service, newest first."""
    from google.cloud import run_v2

    parent = _service_path(service)
    try:
        client = run_v2.RevisionsClient()
        revisions = list(client.list_revisions(parent=parent))
    except Exception as exc:
        raise CloudError(f"could not list revisions for '{service}': {exc}") from exc

    revisions.sort(key=lambda r: r.create_time.timestamp() if r.create_time else 0, reverse=True)
    rendered = []
    for rev in revisions[:limit]:
        conditions = {c.type_: c.state.name for c in (rev.conditions or [])}
        # Cloud Run's raw conditions are easy to misread. "Active" is not a
        # health signal: it is false whenever a revision has no instances
        # running, which is the normal resting state of any revision not
        # currently receiving traffic. Reporting that verbatim invites the
        # conclusion that a perfectly good rollback target is broken, so the
        # two signals are separated and named for what they mean.
        ready = conditions.get("Ready", "UNKNOWN")
        healthy = ready == "CONDITION_SUCCEEDED"
        serving = conditions.get("Active") == "CONDITION_SUCCEEDED"

        # Descriptive, never imperative. Guidance on how to interpret these
        # fields belongs in the agent's instruction, not in data the agent
        # reads: content inspection cannot distinguish helpful instructions
        # embedded in tool output from injected ones, and should not have to.
        if healthy and serving:
            status = "ready; instances currently running"
        elif healthy:
            status = "ready; scaled to zero, no instances currently running"
        else:
            status = "not ready; this revision never became healthy"

        rendered.append(
            {
                "name": rev.name.split("/")[-1],
                "create_time": rev.create_time.isoformat() if rev.create_time else "",
                "image": rev.containers[0].image if rev.containers else "",
                "healthy": healthy,
                "serving_traffic": serving,
                "status": status,
                # Kept for completeness, but after the plain-language fields so
                # the interpretation is read first.
                "raw_conditions": conditions,
                "ready": ready,
            }
        )
    return {"service": service, "revision_count": len(rendered), "revisions": rendered}


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------


def shift_traffic(*, service: str, revision: str, percent: int = 100) -> dict[str, Any]:
    """Shift traffic to a named revision.

    Returns an undo token capturing the previous split, which is what makes
    this action genuinely reversible rather than merely described as such.
    """
    from google.cloud import run_v2

    name = _service_path(service)
    try:
        client = run_v2.ServicesClient()
        svc = client.get_service(name=name)

        previous = [
            {"revision": t.revision, "percent": t.percent, "tag": t.tag}
            for t in (svc.traffic_statuses or [])
        ]

        if percent >= 100:
            svc.traffic = [
                run_v2.TrafficTarget(
                    type_=run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION,
                    revision=revision,
                    percent=100,
                )
            ]
        else:
            svc.traffic = [
                run_v2.TrafficTarget(
                    type_=run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION,
                    revision=revision,
                    percent=percent,
                ),
                run_v2.TrafficTarget(
                    type_=run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST,
                    percent=100 - percent,
                ),
            ]

        operation = client.update_service(service=svc)
        result = operation.result(timeout=300)
    except Exception as exc:
        raise CloudError(f"could not shift traffic for '{service}': {exc}") from exc

    return {
        "service": service,
        "revision": revision,
        "percent": percent,
        "applied_at": dt.datetime.now(dt.UTC).isoformat(),
        "current_traffic": [
            {"revision": t.revision, "percent": t.percent} for t in (result.traffic_statuses or [])
        ],
        "undo_token": {"operation": "shift_traffic", "service": service, "previous": previous},
    }


def update_scaling(
    *, service: str, min_instances: int | None = None, max_instances: int | None = None
) -> dict[str, Any]:
    """Change a Cloud Run service's autoscaling bounds."""
    from google.cloud import run_v2

    name = _service_path(service)
    try:
        client = run_v2.ServicesClient()
        svc = client.get_service(name=name)
        previous = {
            "min_instance_count": svc.template.scaling.min_instance_count,
            "max_instance_count": svc.template.scaling.max_instance_count,
        }
        if min_instances is not None:
            svc.template.scaling.min_instance_count = int(min_instances)
        if max_instances is not None:
            svc.template.scaling.max_instance_count = int(max_instances)
        operation = client.update_service(service=svc)
        result = operation.result(timeout=300)
    except Exception as exc:
        raise CloudError(f"could not update scaling for '{service}': {exc}") from exc

    return {
        "service": service,
        "min_instance_count": result.template.scaling.min_instance_count,
        "max_instance_count": result.template.scaling.max_instance_count,
        "undo_token": {"operation": "update_scaling", "service": service, "previous": previous},
    }


def set_bucket_iam(*, bucket: str, member: str, role: str) -> dict[str, Any]:
    """Grant a principal a role on a bucket.

    This is one of the highest-privilege operations in the catalogue. It is
    implemented faithfully so that the governance layer is being tested against
    a real capability, not a stub that could never have done harm.
    """
    from google.cloud import storage

    project = _project()
    try:
        client = storage.Client(project=project)
        bucket_obj = client.bucket(bucket)
        policy = bucket_obj.get_iam_policy(requested_policy_version=3)
        previous = [{"role": b["role"], "members": sorted(b["members"])} for b in policy.bindings]
        policy.bindings.append({"role": role, "members": {member}})
        bucket_obj.set_iam_policy(policy)
    except Exception as exc:
        raise CloudError(f"could not set IAM policy on bucket '{bucket}': {exc}") from exc

    return {
        "bucket": bucket,
        "member": member,
        "role": role,
        "undo_token": {"operation": "set_bucket_iam", "bucket": bucket, "previous": previous},
    }


def create_compute_instances(
    *, machine_type: str, count: int = 1, zone: str = "", name_prefix: str = "interlock-worker"
) -> dict[str, Any]:
    """Provision compute instances. Present so that cost governance has a real
    capability to bound; in practice the policy engine refuses it."""
    from google.cloud import compute_v1

    project = _project()
    zone = zone or f"{_location()}-a"
    created: list[str] = []
    try:
        client = compute_v1.InstancesClient()
        for index in range(int(count)):
            instance = compute_v1.Instance(
                name=f"{name_prefix}-{index}",
                machine_type=f"zones/{zone}/machineTypes/{machine_type}",
                disks=[
                    compute_v1.AttachedDisk(
                        boot=True,
                        auto_delete=True,
                        initialize_params=compute_v1.AttachedDiskInitializeParams(
                            source_image="projects/debian-cloud/global/images/family/debian-12",
                            disk_size_gb=10,
                        ),
                    )
                ],
                network_interfaces=[compute_v1.NetworkInterface(name="global/networks/default")],
            )
            operation = client.insert(project=project, zone=zone, instance_resource=instance)
            operation.result(timeout=300)
            created.append(instance.name)
    except Exception as exc:
        raise CloudError(f"could not create compute instances: {exc}") from exc

    return {
        "machine_type": machine_type,
        "count": count,
        "zone": zone,
        "created": created,
        "undo_token": {"operation": "create_compute_instances", "zone": zone, "names": created},
    }


def describe_sql_instance(*, instance: str) -> dict[str, Any]:
    """Describe a Cloud SQL instance: state, tier, backups and replication.

    Read-only, so the investigator can establish what a database actually is
    before anything proposes changing it. A remediation that assumes a replica
    exists, or that automated backups are on, is a remediation built on a guess.
    """
    import googleapiclient.discovery  # type: ignore[import-untyped]

    project = _project()
    try:
        service = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        found = service.instances().get(project=project, instance=instance).execute()
    except Exception as exc:
        raise CloudError(f"could not describe database '{instance}': {exc}") from exc

    settings = found.get("settings") or {}
    backup = settings.get("backupConfiguration") or {}
    return {
        "instance": instance,
        "state": found.get("state", ""),
        "database_version": found.get("databaseVersion", ""),
        "tier": settings.get("tier", ""),
        "region": found.get("region", ""),
        "availability_type": settings.get("availabilityType", ""),
        "backups_enabled": bool(backup.get("enabled")),
        "point_in_time_recovery": bool(backup.get("pointInTimeRecoveryEnabled")),
        "deletion_protection": bool(settings.get("deletionProtectionEnabled")),
        "replica_names": list(found.get("replicaNames") or []),
    }


def create_sql_backup(*, instance: str) -> dict[str, Any]:
    """Take an on-demand Cloud SQL backup."""
    import googleapiclient.discovery  # type: ignore[import-untyped]

    project = _project()
    try:
        service = googleapiclient.discovery.build("sqladmin", "v1beta4", cache_discovery=False)
        request = service.backupRuns().insert(
            project=project, instance=instance, body={"description": "interlock pre-remediation backup"}
        )
        response = request.execute()
    except Exception as exc:
        raise CloudError(f"could not create backup for '{instance}': {exc}") from exc
    return {"instance": instance, "operation": response.get("name", ""), "status": response.get("status", "")}


def undo(token: dict[str, Any]) -> dict[str, Any]:
    """Reverse a previously applied action using its undo token."""
    operation = token.get("operation")
    if operation == "shift_traffic":
        previous = token.get("previous") or []
        if not previous:
            raise CloudError("undo token carries no previous traffic split")
        target = max(previous, key=lambda t: t.get("percent", 0))
        return shift_traffic(service=token["service"], revision=target["revision"], percent=100)
    if operation == "update_scaling":
        previous = token.get("previous") or {}
        return update_scaling(
            service=token["service"],
            min_instances=previous.get("min_instance_count"),
            max_instances=previous.get("max_instance_count"),
        )
    raise CloudError(f"no undo procedure is defined for operation '{operation}'")
