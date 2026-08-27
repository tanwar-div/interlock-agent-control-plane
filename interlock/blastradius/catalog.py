"""Catalogue of known infrastructure actions and their intrinsic risk profile.

The catalogue is deliberately hand-written data, not model output. An action's
baseline danger is a property of the operation itself and must not be something
an agent can argue its way out of.

Any action type absent from this catalogue is treated as maximally dangerous by
`interlock.blastradius.scorer`. Adding a capability is therefore an explicit,
reviewable act rather than an emergent one.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from interlock.common.models import Reversibility


@dataclass(frozen=True)
class ActionSpec:
    """Baseline risk profile for one action type."""

    action_type: str
    description: str
    reversibility: Reversibility
    # Ordinal 0-4 baselines. The scorer may raise these based on the concrete
    # parameters of a proposal, but never lowers them.
    scope: int
    data_risk: int
    availability_risk: int
    privilege_risk: int
    # Fixed cost floor in USD for performing the action once.
    base_cost_usd: float = 0.0
    # Parameter names whose presence must be validated before execution.
    required_params: tuple[str, ...] = field(default_factory=tuple)
    # True when the executor is able to capture an undo token.
    undoable: bool = False


# --- Read-only operations --------------------------------------------------
# Investigation is where an SRE agent should spend most of its time, so reads
# are catalogued explicitly and scored at zero rather than left unknown.
_READS = [
    ActionSpec("logging.entries.list", "Read log entries", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("monitoring.timeSeries.list", "Read metric time series", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("run.services.get", "Describe a Cloud Run service", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("run.revisions.list", "List Cloud Run revisions", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("sql.instances.get", "Describe a Cloud SQL instance", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("storage.buckets.get", "Describe a storage bucket", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("storage.buckets.getIamPolicy", "Read bucket IAM policy", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("compute.instances.list", "List compute instances", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("billing.cost.query", "Query current spend", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("error_reporting.groups.list", "List error groups", Reversibility.REVERSIBLE, 0, 0, 0, 0),
]

# --- Cloud Run -------------------------------------------------------------
_CLOUD_RUN = [
    ActionSpec(
        "run.services.rollback",
        "Shift 100% traffic to a previously healthy revision",
        Reversibility.REVERSIBLE,
        scope=1, data_risk=0, availability_risk=1, privilege_risk=0,
        required_params=("service", "revision"), undoable=True,
    ),
    ActionSpec(
        "run.services.update_traffic",
        "Change traffic split across revisions",
        Reversibility.REVERSIBLE,
        scope=1, data_risk=0, availability_risk=2, privilege_risk=0,
        required_params=("service",), undoable=True,
    ),
    ActionSpec(
        "run.services.update_scaling",
        "Change min/max instance counts",
        Reversibility.REVERSIBLE,
        scope=1, data_risk=0, availability_risk=1, privilege_risk=0,
        base_cost_usd=0.0, required_params=("service",), undoable=True,
    ),
    ActionSpec(
        "run.services.update_env",
        "Change service environment variables (triggers new revision)",
        Reversibility.RECOVERABLE,
        scope=1, data_risk=0, availability_risk=2, privilege_risk=1,
        required_params=("service",), undoable=True,
    ),
    ActionSpec(
        "run.services.set_iam_policy",
        "Change who may invoke a Cloud Run service",
        Reversibility.RECOVERABLE,
        scope=2, data_risk=1, availability_risk=0, privilege_risk=3,
        required_params=("service",), undoable=True,
    ),
    ActionSpec(
        "run.services.delete",
        "Delete a Cloud Run service permanently",
        Reversibility.IRREVERSIBLE,
        scope=2, data_risk=2, availability_risk=4, privilege_risk=0,
        required_params=("service",),
    ),
]

# --- Cloud SQL -------------------------------------------------------------
_CLOUD_SQL = [
    ActionSpec(
        "sql.instances.restart",
        "Restart a Cloud SQL instance",
        Reversibility.RECOVERABLE,
        scope=2, data_risk=1, availability_risk=3, privilege_risk=0,
        required_params=("instance",),
    ),
    ActionSpec(
        "sql.backupRuns.create",
        "Take an on-demand backup",
        Reversibility.REVERSIBLE,
        scope=1, data_risk=0, availability_risk=0, privilege_risk=0,
        base_cost_usd=0.50, required_params=("instance",),
    ),
    ActionSpec(
        "sql.instances.failover",
        "Fail over to the standby replica",
        Reversibility.RECOVERABLE,
        scope=3, data_risk=2, availability_risk=4, privilege_risk=0,
        required_params=("instance",),
    ),
    ActionSpec(
        "sql.instances.delete",
        "Delete a Cloud SQL instance and all of its data",
        Reversibility.IRREVERSIBLE,
        scope=3, data_risk=4, availability_risk=4, privilege_risk=0,
        required_params=("instance",),
    ),
]

# --- Storage / data --------------------------------------------------------
_STORAGE = [
    ActionSpec(
        "storage.buckets.setIamPolicy",
        "Change who may read or write a bucket",
        Reversibility.RECOVERABLE,
        scope=3, data_risk=3, availability_risk=0, privilege_risk=3,
        required_params=("bucket",), undoable=True,
    ),
    ActionSpec(
        "storage.objects.delete",
        "Delete objects from a bucket",
        Reversibility.IRREVERSIBLE,
        scope=2, data_risk=4, availability_risk=1, privilege_risk=0,
        required_params=("bucket",),
    ),
    ActionSpec(
        "firestore.documents.delete",
        "Delete Firestore documents",
        Reversibility.IRREVERSIBLE,
        scope=2, data_risk=4, availability_risk=1, privilege_risk=0,
        required_params=("path",),
    ),
]

# --- IAM -------------------------------------------------------------------
_IAM = [
    ActionSpec(
        "iam.serviceAccounts.setIamPolicy",
        "Change service account permissions",
        Reversibility.RECOVERABLE,
        scope=3, data_risk=2, availability_risk=1, privilege_risk=4,
        required_params=("service_account",), undoable=True,
    ),
    ActionSpec(
        "resourcemanager.projects.setIamPolicy",
        "Change project-level IAM bindings",
        Reversibility.RECOVERABLE,
        scope=4, data_risk=3, availability_risk=2, privilege_risk=4,
        required_params=("project",), undoable=True,
    ),
    ActionSpec(
        "iam.serviceAccountKeys.create",
        "Mint a long-lived service account key",
        Reversibility.RECOVERABLE,
        scope=3, data_risk=3, availability_risk=0, privilege_risk=4,
        required_params=("service_account",), undoable=True,
    ),
]

# --- Compute ---------------------------------------------------------------
_COMPUTE = [
    ActionSpec(
        "compute.instances.insert",
        "Provision new compute instances",
        Reversibility.REVERSIBLE,
        scope=2, data_risk=0, availability_risk=1, privilege_risk=1,
        base_cost_usd=1.0, required_params=("machine_type",), undoable=True,
    ),
    ActionSpec(
        "compute.instances.delete",
        "Delete compute instances",
        Reversibility.IRREVERSIBLE,
        scope=2, data_risk=3, availability_risk=3, privilege_risk=0,
        required_params=("instance",),
    ),
    ActionSpec(
        "compute.firewalls.insert",
        "Add a firewall rule",
        Reversibility.REVERSIBLE,
        scope=3, data_risk=1, availability_risk=2, privilege_risk=4,
        required_params=("name",), undoable=True,
    ),
]

# --- Incident bookkeeping (safe, non-infrastructure) -----------------------
_BOOKKEEPING = [
    ActionSpec("incident.note.append", "Record a finding on the incident", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("incident.escalate", "Hand the incident to a human", Reversibility.REVERSIBLE, 0, 0, 0, 0),
    ActionSpec("incident.resolve", "Close the incident as resolved", Reversibility.REVERSIBLE, 0, 0, 0, 0),
]


ACTION_CATALOG: dict[str, ActionSpec] = {
    spec.action_type: spec
    for spec in (
        *_READS, *_CLOUD_RUN, *_CLOUD_SQL, *_STORAGE, *_IAM, *_COMPUTE, *_BOOKKEEPING
    )
}


def lookup(action_type: str) -> ActionSpec | None:
    return ACTION_CATALOG.get(action_type)


def is_read_only(action_type: str) -> bool:
    spec = ACTION_CATALOG.get(action_type)
    if spec is None:
        return False
    return (
        spec.scope == 0
        and spec.data_risk == 0
        and spec.availability_risk == 0
        and spec.privilege_risk == 0
    )
