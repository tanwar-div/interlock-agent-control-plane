"""Core domain model for Interlock.

These types are the contract between the worker plane (agents that propose and
perform work) and the governance plane (the components that decide whether that
work is permitted, and that record what happened).
"""
from __future__ import annotations

import datetime as dt
import enum
import hashlib
import json
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def canonical_json(payload: Any) -> str:
    """Stable serialisation used for hashing and signing.

    Key order and separators are fixed so that the same logical content always
    produces the same bytes, which is what makes the ledger hash chain and the
    proposal signatures verifiable by a third party.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Reversibility(str, enum.Enum):
    """Can the effect of this action be undone, and at what cost?"""

    REVERSIBLE = "REVERSIBLE"        # undo is a single symmetric operation
    RECOVERABLE = "RECOVERABLE"      # undo needs a restore/redeploy, data intact
    IRREVERSIBLE = "IRREVERSIBLE"    # effect cannot be undone by any operation


class Severity(str, enum.Enum):
    NEGLIGIBLE = "NEGLIGIBLE"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CATASTROPHIC = "CATASTROPHIC"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.rank < other.rank


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class IncidentState(str, enum.Enum):
    """Explicit state machine. The agent cannot skip a state or invent one."""

    RECEIVED = "RECEIVED"
    TRIAGING = "TRIAGING"
    INVESTIGATING = "INVESTIGATING"
    PLANNING = "PLANNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REMEDIATING = "REMEDIATING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    FAILED = "FAILED"

    @property
    def terminal(self) -> bool:
        return self in (IncidentState.RESOLVED, IncidentState.ESCALATED, IncidentState.FAILED)


class LedgerEventType(str, enum.Enum):
    INCIDENT_OPENED = "INCIDENT_OPENED"
    STATE_TRANSITION = "STATE_TRANSITION"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    ACTION_SCORED = "ACTION_SCORED"
    POLICY_DECISION = "POLICY_DECISION"
    GUARD_VERDICT = "GUARD_VERDICT"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    ACTION_BLOCKED = "ACTION_BLOCKED"
    ACTION_FAILED = "ACTION_FAILED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_RESOLVED = "APPROVAL_RESOLVED"
    AUDIT_VERDICT = "AUDIT_VERDICT"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    CHECKPOINT_WRITTEN = "CHECKPOINT_WRITTEN"
    RUN_RESUMED = "RUN_RESUMED"
    INCIDENT_CLOSED = "INCIDENT_CLOSED"


class GuardCategory(str, enum.Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    PII = "PII"
    SECRET = "SECRET"
    MALICIOUS_URI = "MALICIOUS_URI"
    UNSAFE_CONTENT = "UNSAFE_CONTENT"


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class AgentCard(BaseModel):
    """Public identity document for an agent.

    Modelled on the A2A signed agent card: the card carries the agent's public
    key and declared capabilities, and is itself signed by the registry so a
    verifier can establish both who an agent is and what it is entitled to do.
    """

    model_config = ConfigDict(use_enum_values=False)

    agent_id: str
    display_name: str
    # SPIFFE-style workload identifier, e.g.
    # spiffe://interlock.internal/ns/sre/agent/remediation
    spiffe_id: str
    namespace: str
    public_key_pem: str
    # Tool names this agent is entitled to invoke. Anything absent is denied,
    # so capability is an allowlist rather than a blocklist.
    allowed_tools: list[str] = Field(default_factory=list)
    # Ceiling this agent may never exceed regardless of policy outcome.
    max_severity: Severity = Severity.LOW
    created_at: dt.datetime = Field(default_factory=utcnow)
    revoked: bool = False
    registry_signature: str | None = None

    def signing_payload(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "spiffe_id": self.spiffe_id,
            "namespace": self.namespace,
            "public_key_pem": self.public_key_pem,
            "allowed_tools": sorted(self.allowed_tools),
            "max_severity": self.max_severity.value,
            "created_at": self.created_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


class ActionProposal(BaseModel):
    """An agent's request to change the world.

    Every mutation of a real resource must be expressed as a proposal and pass
    the governance plane before it can execute.
    """

    proposal_id: str = Field(default_factory=lambda: new_id("prop"))
    incident_id: str
    # SPIFFE id of the proposing agent, bound to the signature below.
    actor: str
    action_type: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    # Set by the agent: what it expects to be true after the action succeeds.
    # The independent auditor checks reality against this claim.
    expected_outcome: str = ""
    created_at: dt.datetime = Field(default_factory=utcnow)
    signature: str | None = None

    def signing_payload(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "incident_id": self.incident_id,
            "actor": self.actor,
            "action_type": self.action_type,
            "target": self.target,
            "parameters": self.parameters,
            "created_at": self.created_at.isoformat(),
        }

    def fingerprint(self) -> str:
        return sha256_hex(canonical_json(self.signing_payload()))


class BlastRadius(BaseModel):
    """Deterministic, model-free assessment of what an action could destroy."""

    reversibility: Reversibility
    # 0-4 ordinal scales; see interlock.blastradius.scorer for the rubric.
    scope: int = Field(ge=0, le=4)
    data_risk: int = Field(ge=0, le=4)
    availability_risk: int = Field(ge=0, le=4)
    privilege_risk: int = Field(ge=0, le=4)
    cost_ceiling_usd: float = 0.0
    severity: Severity
    score: float
    factors: list[str] = Field(default_factory=list)
    # True when the action type was not found in the catalogue and the scorer
    # therefore assumed worst case.
    unknown_action: bool = False


class GuardVerdict(BaseModel):
    """Result of an inline content inspection (Model Armor / guard model)."""

    blocked: bool
    categories: list[GuardCategory] = Field(default_factory=list)
    detail: str = ""
    source: str = "model_armor"
    # True when the scan could not be completed and the configured fail-closed
    # behaviour was applied.
    degraded: bool = False


class PolicyDecision(BaseModel):
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    requires_approval_from: str | None = None
    blast_radius: BlastRadius | None = None
    guard: GuardVerdict | None = None
    evaluated_at: dt.datetime = Field(default_factory=utcnow)

    @property
    def permitted(self) -> bool:
        return self.decision is Decision.ALLOW


class ActionResult(BaseModel):
    proposal_id: str
    succeeded: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    started_at: dt.datetime = Field(default_factory=utcnow)
    finished_at: dt.datetime | None = None
    # Populated when the executor captured enough information to undo the
    # action; the presence of this is what makes an action truly reversible.
    undo_token: dict[str, Any] | None = None


class AuditVerdict(BaseModel):
    """Independent verification that an executed action did what was claimed."""

    proposal_id: str
    confirmed: bool
    # Auditor observed the target state independently of the worker's report.
    observed_state: dict[str, Any] = Field(default_factory=dict)
    discrepancies: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    narrative: str = ""
    auditor: str = ""
    created_at: dt.datetime = Field(default_factory=utcnow)


class ApprovalRequest(BaseModel):
    approval_id: str = Field(default_factory=lambda: new_id("apr"))
    incident_id: str
    proposal: ActionProposal
    decision: PolicyDecision
    requested_at: dt.datetime = Field(default_factory=utcnow)
    expires_at: dt.datetime | None = None
    resolved: bool = False
    approved: bool | None = None
    resolved_by: str | None = None
    resolved_at: dt.datetime | None = None
    justification: str = ""


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: new_id("alt"))
    source: str = "cloud-monitoring"
    title: str
    description: str = ""
    resource_type: str = ""
    resource_name: str = ""
    severity: str = "WARNING"
    labels: dict[str, str] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    received_at: dt.datetime = Field(default_factory=utcnow)


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: new_id("inc"))
    alert: Alert
    state: IncidentState = IncidentState.RECEIVED
    opened_at: dt.datetime = Field(default_factory=utcnow)
    updated_at: dt.datetime = Field(default_factory=utcnow)
    closed_at: dt.datetime | None = None
    # Monotonic counter; every durable write increments it so a resumed run can
    # detect that it lost a race and refuse to double-apply.
    revision: int = 0
    session_id: str = ""
    actions_taken: int = 0
    spend_usd: float = 0.0
    findings: list[str] = Field(default_factory=list)
    resolution: str = ""
    escalation_reason: str = ""
    pending_approval_id: str | None = None
    ledger_head: str = ""
    # Cooperative lease. Pub/Sub delivers at least once, so the same phase can
    # be dispatched to two workers concurrently; whoever holds an unexpired
    # lease is the one permitted to advance this incident.
    lease_until: dt.datetime | None = None
    lease_owner: str = ""

    def is_over_budget(self, limit: float) -> bool:
        return self.spend_usd >= limit


class Checkpoint(BaseModel):
    """Durable snapshot allowing an interrupted run to resume exactly once."""

    checkpoint_id: str = Field(default_factory=lambda: new_id("ckpt"))
    incident_id: str
    state: IncidentState
    revision: int
    session_id: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: dt.datetime = Field(default_factory=utcnow)


class LedgerEntry(BaseModel):
    """One tamper-evident record in the append-only audit chain."""

    entry_id: str = Field(default_factory=lambda: new_id("led"))
    incident_id: str
    sequence: int
    event_type: LedgerEventType
    actor: str
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: dt.datetime = Field(default_factory=utcnow)
    prev_hash: str = ""
    entry_hash: str = ""
    signature: str = ""

    def hashing_payload(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "incident_id": self.incident_id,
            "sequence": self.sequence,
            "event_type": self.event_type.value,
            "actor": self.actor,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self.hashing_payload()))
