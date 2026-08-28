"""Scorer variants under test.

Every model variant bypasses the production cache deliberately: caching would
return one stored answer and report perfect stability, hiding exactly the
property we are trying to measure.
"""
from __future__ import annotations

import asyncio
import json
import statistics
from typing import Any

from interlock.blastradius.catalog import lookup
from interlock.blastradius.model_scorer import build_prompt, parse_assessment
from interlock.blastradius.scorer import (
    _project_cost,
    catalogue_floor,
    compose,
    score_proposal,
)
from interlock.common.config import get_settings
from interlock.common.models import ActionProposal, BlastRadius

_DIMS = ("data_risk", "availability_risk", "privilege_risk", "scope")
_client: Any = None


def _genai():
    global _client
    if _client is None:
        from google import genai

        s = get_settings()
        _client = genai.Client(vertexai=True, project=s.project_id, location=s.model_location)
    return _client


# --- response schema, per the Gemini structured-output contract ----------
def _schema(with_reasoning: bool) -> dict:
    props: dict[str, Any] = {}
    order: list[str] = []
    if with_reasoning:
        # Reasoning first: the model commits to an analysis before a number,
        # rather than justifying a number it has already emitted.
        props["analysis"] = {
            "type": "STRING",
            "description": "One sentence on the worst outcome this could cause.",
        }
        order.append("analysis")
    for d in _DIMS:
        props[d] = {"type": "INTEGER", "minimum": 0, "maximum": 4}
        order.append(d)
    props["reason"] = {"type": "STRING"}
    order.append("reason")
    return {
        "type": "OBJECT",
        "properties": props,
        "required": order,
        "propertyOrdering": order,
    }


async def _ask(prompt: str, *, schema: dict | None, temperature: float) -> str:
    from google.genai import types

    cfg: dict[str, Any] = {
        "temperature": temperature,
        "max_output_tokens": 8192,
        "response_mime_type": "application/json",
    }
    if schema is not None:
        cfg["response_schema"] = schema

    def _call() -> str:
        r = _genai().models.generate_content(
            model=get_settings().scoring_model,
            contents=prompt,
            config=types.GenerateContentConfig(**cfg),
        )
        return r.text or ""

    try:
        return await asyncio.wait_for(asyncio.to_thread(_call), timeout=30)
    except Exception:
        return ""


def _finalise(proposal, spec, dims: dict[str, int] | None, budget: float, label: str) -> BlastRadius:
    """Apply the floor and compose. Falls back when the model gave nothing."""
    deterministic = score_proposal(proposal, budget_remaining_usd=budget)
    if dims is None:
        deterministic.scored_by = f"{label}-fallback"
        return deterministic

    floor = {
        "data_risk": max(spec.data_risk, deterministic.data_risk),
        "availability_risk": max(spec.availability_risk, deterministic.availability_risk),
        "privilege_risk": max(spec.privilege_risk, deterministic.privilege_risk),
        "scope": max(spec.scope, deterministic.scope),
    }
    merged = {d: max(floor[d], dims[d]) for d in _DIMS}
    factors: list[str] = []
    cost = _project_cost(spec, proposal.parameters or {}, factors)
    return compose(
        reversibility=deterministic.reversibility, dimensions=merged, cost_ceiling=cost,
        factors=factors, budget_remaining_usd=budget, scored_by=label,
        model_assessment={**dims, "deterministic_score": deterministic.score},
    )


# --- the variants --------------------------------------------------------


async def deterministic(proposal: ActionProposal, budget: float) -> BlastRadius:
    """Heuristics only. The main branch."""
    return score_proposal(proposal, budget_remaining_usd=budget)


async def _model_once(proposal, budget, *, schema, temperature, label):
    spec = lookup(proposal.action_type)
    if spec is None:
        return score_proposal(proposal, budget_remaining_usd=budget)
    raw = await _ask(build_prompt(proposal, spec), schema=schema, temperature=temperature)
    a = parse_assessment(raw, "eval")
    dims = None if a is None else {d: getattr(a, d) for d in _DIMS}
    return _finalise(proposal, spec, dims, budget, label)


async def model_plain(proposal: ActionProposal, budget: float) -> BlastRadius:
    """Current production behaviour: JSON mime type, no schema."""
    return await _model_once(proposal, budget, schema=None, temperature=0.0, label="model")


async def model_schema(proposal: ActionProposal, budget: float) -> BlastRadius:
    """Constrain the output shape with a response schema."""
    return await _model_once(proposal, budget, schema=_schema(False), temperature=0.0, label="schema")


async def model_analysis_first(proposal: ActionProposal, budget: float) -> BlastRadius:
    """Schema that forces a written analysis before any number is emitted."""
    return await _model_once(proposal, budget, schema=_schema(True), temperature=0.0, label="analysis")


async def model_self_consistency(proposal: ActionProposal, budget: float) -> BlastRadius:
    """Three independent assessments; per-dimension median.

    The median is chosen over the mean so a single outlier cannot drag a
    verdict, and over the max so the variant is not trivially safer by being
    uniformly more alarmed.
    """
    spec = lookup(proposal.action_type)
    if spec is None:
        return score_proposal(proposal, budget_remaining_usd=budget)

    prompt = build_prompt(proposal, spec)
    raws = await asyncio.gather(*(
        _ask(prompt, schema=_schema(True), temperature=0.4) for _ in range(3)
    ))
    parsed = [p for p in (parse_assessment(r, "eval") for r in raws) if p is not None]
    if not parsed:
        return _finalise(proposal, spec, None, budget, "consistency")

    dims = {
        d: int(statistics.median([getattr(p, d) for p in parsed]))
        for d in _DIMS
    }
    return _finalise(proposal, spec, dims, budget, "consistency")


VARIANTS = {
    "deterministic": deterministic,
    "model": model_plain,
    "schema": model_schema,
    "analysis-first": model_analysis_first,
    "self-consistency": model_self_consistency,
}
