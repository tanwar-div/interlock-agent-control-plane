"""Runtime configuration for every Interlock service.

Configuration is read from the environment so that the same container image can
run locally, in Cloud Run, or in a test harness without code changes.
"""
from __future__ import annotations

import functools
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="INTERLOCK_", extra="ignore")

    # --- Google Cloud -----------------------------------------------------
    project_id: str = Field(default="", description="Google Cloud project id.")
    location: str = Field(default="us-central1", description="Primary region.")

    # --- Models -----------------------------------------------------------
    # Gemini 3.6 Flash is the reasoning model: cheaper than 3.5 Flash and
    # measurably stronger at agentic planning. Anything >= 3.5 satisfies the
    # hackathon requirement.
    reasoning_model: str = Field(default="gemini-3.6-flash")
    # A deliberately separate, smaller model performs the always-on guard
    # classification. Keeping the guard off the reasoning model means a
    # compromised reasoning context cannot silently disable its own guard.
    guard_model: str = Field(default="gemma-3-12b-it")
    # The auditor runs on a different model family/config from the worker that
    # produced the work, so a systematic reasoning error is less likely to be
    # reproduced identically by its own reviewer.
    auditor_model: str = Field(default="gemini-3.6-flash")

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
