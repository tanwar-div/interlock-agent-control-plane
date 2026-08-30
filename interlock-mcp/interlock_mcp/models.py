"""Response shapes.

These are declared explicitly rather than returning loose dictionaries, because
an MCP client derives its output schema from them. A calling model reads that
schema before it reads any answer, so the shape is part of the interface.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class Dimensions(BaseModel):
    """What an action could cost, on four independent axes, each 0-4."""

    data_risk: int = Field(description="0 no data involved, 4 permanently destroys data.")
    availability_risk: int = Field(description="0 no effect, 4 service down and needs rebuilding.")
    privilege_risk: int = Field(description="0 no permission change, 4 grants broad or public access.")
    scope: int = Field(description="0 nothing modified, 4 an entire project or unbounded set.")


class Verdict(BaseModel):
    """The answer to: may this action run?"""

    decision: str = Field(description="ALLOW, REQUIRE_APPROVAL, or DENY.")
    safe_to_run_unattended: bool = Field(
        description="True only when the decision is ALLOW. If false, do not perform this "
        "action without a human deciding first."
    )
    severity: str = Field(description="NEGLIGIBLE, LOW, MODERATE, HIGH, or CATASTROPHIC.")
    score: float = Field(description="Composite 0-100. Higher is more dangerous.")
    reversibility: str = Field(description="REVERSIBLE, RECOVERABLE, or IRREVERSIBLE.")
    dimensions: Dimensions
    cost_ceiling_usd: float = Field(description="Bounded worst-case 24h cost of this action.")
    reasons: list[str] = Field(description="Every policy rule that fired, in order.")
    factors: list[str] = Field(description="Why the score is what it is, factor by factor.")
    catalogued: bool = Field(
        description="False when the action type is unknown to the catalogue, in which case it "
        "is scored as maximally dangerous rather than assumed safe."
    )
    assessed_by: str = Field(
        description="Which path produced the score: a model assessment floored by the "
        "hand-written heuristics, or the heuristics alone when no model was reachable."
    )


class PlanStep(BaseModel):
    """One action's verdict within a plan."""

    step: int
    action_type: str
    target: str
    decision: str
    severity: str
    score: float
    reasons: list[str]


class PlanVerdict(BaseModel):
    """The answer to: may this whole plan run unattended?"""

    safe_to_run_unattended: bool = Field(
        description="True only when every step is ALLOW."
    )
    worst_severity: str
    blocked_steps: list[int] = Field(description="1-based indices of steps that are not ALLOW.")
    summary: str
    steps: list[PlanStep]


class ContentVerdict(BaseModel):
    """The answer to: is this text safe to treat as evidence?"""

    safe: bool = Field(description="False when the text tries to direct behaviour or exposes secrets.")
    categories: list[str] = Field(
        description="PROMPT_INJECTION, JAILBREAK, PII, SECRET, MALICIOUS_URI, or UNSAFE_CONTENT."
    )
    detail: str = Field(description="What was found, and where.")
    recommendation: str = Field(description="What the calling agent should do about it.")
    inspected_by: str
