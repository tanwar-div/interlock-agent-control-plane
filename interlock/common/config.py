"""Runtime configuration for every Interlock service.

Configuration is read from the environment so that the same container image can
run locally, in Cloud Run, or in a test harness without code changes.
"""
from __future__ import annotations

import functools
import os
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INTERLOCK_", extra="ignore")

    # --- Google Cloud -----------------------------------------------------
    project_id: str = Field(default="", description="Google Cloud project id.")
    location: str = Field(default="us-central1", description="Region for infrastructure.")
    # Gemini and Gemma are served from the global endpoint, not from a regional
    # one. Requesting them regionally returns 404/FAILED_PRECONDITION even
    # though the models appear in the regional catalogue.
    model_location: str = Field(default="global", description="Endpoint for model calls.")

    # --- Models -----------------------------------------------------------
    # Gemini 3.5 Flash, deliberately not the newest model available.
    # The newest release carries the most contended quota, and an agent fleet
    # makes many calls per incident, so it is the first thing to hit 429
    # RESOURCE_EXHAUSTED. A slightly older model with headroom finishes
    # incidents; a newer one that is rate limited does not.
    reasoning_model: str = Field(default="gemini-3.5-flash")
    # A deliberately separate, smaller model performs the always-on guard
    # classification. Keeping the guard off the reasoning model means a
    # compromised reasoning context cannot silently disable its own guard.
    # The serverless ("-maas") Gemma variant: callable directly, with no
    # endpoint to deploy and keep warm.
    guard_model: str = Field(default="gemma-4-26b-a4b-it-maas")
    # The auditor runs on a different model family/config from the worker that
    # produced the work, so a systematic reasoning error is less likely to be
    # reproduced identically by its own reviewer.
    auditor_model: str = Field(default="gemini-3.5-flash")
    # Blast-radius assessment. Runs stateless, sees only the action and its
    # arguments, and never sees the proposing agent's reasoning.
    scoring_model: str = Field(default="gemini-3.5-flash")
    model_scoring_enabled: bool = Field(default=True)
    # Memories are deduplicated by meaning rather than by exact string, so a
    # repeated observation reinforces one record instead of creating a second.
    memory_embedding_model: str = Field(default="gemini-embedding-001")
    memory_embeddings_enabled: bool = Field(default=True)
    # Measured, not guessed. Against gemini-embedding-001 at 768 dimensions,
    # genuine paraphrases of the same fact scored 0.826-0.966, and different
    # facts about the same service scored 0.605-0.754. 0.80 sits in that gap.
    #
    # The margin is narrow, and it only exists because matching is scoped to
    # one service and one kind. Unscoped, the same fault text on two different
    # services scores 0.905 — higher than a real paraphrase — and no threshold
    # separates the classes at all. The scoping is load-bearing, not tidiness.
    memory_similarity_threshold: float = Field(default=0.80)

    # --- Public read-only face --------------------------------------------
    # Off by default: enabling it is a deployment decision, because it only
    # makes sense when the Cloud Run IAM boundary has been opened as well.
    public_readonly_enabled: bool = Field(default=False)
    # Shared secret for everything that is not public. Empty means every
    # protected route refuses, which is the safe way to be misconfigured.
    admin_token: str = Field(default="")
    public_rate_limit: int = Field(default=30)
    public_rate_window_seconds: int = Field(default=60)

    # --- Firestore --------------------------------------------------------
    firestore_database: str = Field(default="(default)")
    collection_incidents: str = Field(default="incidents")
    collection_ledger: str = Field(default="ledger")
    collection_agents: str = Field(default="agents")
    collection_checkpoints: str = Field(default="checkpoints")
    collection_policies: str = Field(default="policies")
    collection_approvals: str = Field(default="approvals")

    # --- Pub/Sub ----------------------------------------------------------
    topic_alerts: str = Field(default="interlock-alerts")
    topic_actions: str = Field(default="interlock-actions")
    topic_approvals: str = Field(default="interlock-approvals")
    topic_events: str = Field(default="interlock-events")
    topic_dlq: str = Field(default="interlock-dlq")

    # --- Model Armor ------------------------------------------------------
    model_armor_enabled: bool = Field(default=True)
    model_armor_template: str = Field(default="interlock-guard")
    model_armor_location: str = Field(default="us-central1")
    # Fail closed: if the guard cannot render a verdict, treat the content as
    # hostile rather than waving it through.
    model_armor_fail_open: bool = Field(default=False)

    # --- Containment ------------------------------------------------------
    # Ceiling on autonomous spend per incident before every action, regardless
    # of blast radius, requires a human.
    incident_budget_usd: float = Field(default=25.0)
    # Hard ceiling on autonomous actions per incident; prevents runaway loops
    # of the kind that produce five-figure cloud bills.
    max_actions_per_incident: int = Field(default=25)
    # Wall-clock ceiling for a single incident before it is force-escalated.
    incident_max_duration_seconds: int = Field(default=86_400)
    # How long a pending human approval blocks before it expires closed.
    approval_timeout_seconds: int = Field(default=3_600)

    # --- Context management -----------------------------------------------
    # A long-running incident accumulates far more events than a chat turn.
    # ADK compacts older events into summaries so the model keeps working from
    # a bounded context instead of an ever-growing transcript.
    compaction_interval: int = Field(default=4, description="Events between compactions.")
    compaction_overlap: int = Field(default=1, description="Events of overlap between summaries.")
    compaction_enabled: bool = Field(default=True)
    # Let ADK snapshot and resume an interrupted invocation.
    adk_resumable: bool = Field(default=True)

    # --- Memory -----------------------------------------------------------
    # Cross-incident recall: what this service has done before, and what
    # operators decided last time.
    memory_enabled: bool = Field(default=True)
    collection_memories: str = Field(default="memories")
    memory_recall_limit: int = Field(default=6)
    # Memories older than this stop being surfaced. What mattered a month ago
    # about a service that has been rewritten since is noise, not context.
    memory_ttl_days: int = Field(default=90)

    # --- Sweeper ----------------------------------------------------------
    # Cloud Scheduler wakes the control plane on this cadence so dormant work
    # progresses without anyone watching.
    sweep_stalled_after_seconds: int = Field(default=900)

    # --- Identity ---------------------------------------------------------
    trust_domain: str = Field(default="interlock.internal")
    signing_key_secret: str = Field(default="interlock-ledger-signing-key")
    # Reject action proposals whose signature is older than this, to blunt
    # replay of a previously-approved proposal.
    proposal_max_age_seconds: int = Field(default=300)

    # --- Service wiring ---------------------------------------------------
    gateway_url: str = Field(default="http://localhost:8080")
    # Optional SQLAlchemy URL enabling ADK's DatabaseSessionService. When unset,
    # phase-level durability in Firestore is the recovery mechanism.
    session_db_url: str = Field(default="")
    environment: Literal["local", "cloud"] = Field(default="local")
    log_level: str = Field(default="INFO")
    enable_cloud_trace: bool = Field(default=True)

    @field_validator("project_id")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @property
    def trace_service_namespace(self) -> str:
        return "interlock"

    def topic_path(self, topic: str) -> str:
        return f"projects/{self.project_id}/topics/{topic}"

    def subscription_path(self, sub: str) -> str:
        return f"projects/{self.project_id}/subscriptions/{sub}"

    def model_armor_template_path(self) -> str:
        return (
            f"projects/{self.project_id}/locations/{self.model_armor_location}"
            f"/templates/{self.model_armor_template}"
        )


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()


def model_credentials_available(settings: Settings | None = None) -> bool:
    """Whether a Gemini client has any chance of authenticating.

    Constructing google-genai's client succeeds unconditionally, so a process
    with no credentials only discovers the problem when it makes a call — and
    the client's own cleanup then raises, because its async transport was never
    initialised. That traceback reaches stderr repeatedly and makes a working
    fallback look like a crash.

    Checking first keeps the common case quiet: someone running the MCP server
    straight from the package, with no cloud project and no credentials, whose
    scores are served entirely by the deterministic catalogue.
    """
    resolved = settings or get_settings()
    if resolved.project_id:
        return True
    return bool(os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"))
