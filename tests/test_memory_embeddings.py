"""Semantic deduplication of memories.

These run with no credentials and no network. Real embeddings are exercised
separately during calibration; what matters here is the matching policy around
them, including how it behaves when the model is unavailable — which is the
state CI, and any contributor's laptop, is permanently in.
"""
from __future__ import annotations

import math

import pytest

from interlock.common.config import get_settings
from interlock.memory.embedding import cosine
from interlock.memory.service import KIND_FAULT, KIND_GOVERNANCE, IncidentMemory


def _unit(*values: float) -> list[float]:
    norm = math.sqrt(sum(v * v for v in values))
    return [v / norm for v in values]


def test_cosine_is_bounded_and_degenerate_input_is_zero():
    assert cosine(_unit(1, 0), _unit(1, 0)) == pytest.approx(1.0)
    assert cosine(_unit(1, 0), _unit(0, 1)) == pytest.approx(0.0, abs=1e-9)
    # Anything missing, mismatched or zero-length scores 0 rather than raising:
    # a similarity function that throws would take the memory write with it.
    assert cosine(None, _unit(1, 0)) == 0.0
    assert cosine([], [1.0]) == 0.0
    assert cosine([1.0, 2.0], [1.0]) == 0.0
    assert cosine([0.0, 0.0], [1.0, 0.0]) == 0.0


def test_exact_summaries_match_without_any_embedding():
    """The fallback path. No vector is available, so string equality decides."""
    memory = IncidentMemory()
    rows = [{"memory_id": "m1", "summary": "identical text", "embedding": None}]
    assert memory._match(rows, "identical text", None) is rows[0]
    assert memory._match(rows, "different text", None) is None


def test_similar_summaries_reinforce_and_dissimilar_ones_do_not():
    memory = IncidentMemory()
    threshold = get_settings().memory_similarity_threshold
    near = _unit(1.0, 0.05)
    far = _unit(0.2, 1.0)
    rows = [
        {"memory_id": "near", "summary": "a", "embedding": near},
        {"memory_id": "far", "summary": "b", "embedding": far},
    ]
    query = _unit(1.0, 0.0)
    assert cosine(query, near) >= threshold
    assert cosine(query, far) < threshold
    assert memory._match(rows, "unseen wording", query)["memory_id"] == "near"


def test_the_closest_memory_wins_not_the_first_above_threshold():
    memory = IncidentMemory()
    rows = [
        {"memory_id": "good", "summary": "a", "embedding": _unit(1.0, 0.20)},
        {"memory_id": "better", "summary": "b", "embedding": _unit(1.0, 0.02)},
    ]
    assert memory._match(rows, "q", _unit(1.0, 0.0))["memory_id"] == "better"


def test_a_memory_written_without_an_embedding_still_matches_by_string_later():
    """Embeddings can be unavailable when a memory is written and available
    later. That memory must not become unreachable in the meantime."""
    memory = IncidentMemory()
    rows = [{"memory_id": "old", "summary": "exact wording", "embedding": None}]
    assert memory._match(rows, "exact wording", _unit(1.0, 0.0))["memory_id"] == "old"


@pytest.mark.asyncio
async def test_dedup_still_works_end_to_end_with_embeddings_unavailable(clean_store):
    """CI has no credentials, so embed() returns None throughout. Behaviour must
    be exactly the pre-existing exact-match behaviour."""
    memory = IncidentMemory()
    for incident in ("inc_1", "inc_2"):
        await memory.remember(
            service="checkout-api", kind=KIND_FAULT,
            summary="503s follow a new revision", incident_id=incident,
        )
    await memory.remember(
        service="checkout-api", kind=KIND_FAULT,
        summary="a completely unrelated fault", incident_id="inc_3",
    )
    rows = await memory.recall(service="checkout-api")
    assert len(rows) == 2
    reinforced = next(r for r in rows if r["summary"] == "503s follow a new revision")
    assert reinforced["occurrences"] == 2


@pytest.mark.asyncio
async def test_kinds_are_never_merged_with_each_other(clean_store):
    """A fault and a human decision are different kinds of fact. Identical
    wording must not collapse them, or a denial would be recalled as an
    observation and lose its precedence."""
    memory = IncidentMemory()
    await memory.remember(service="api", kind=KIND_FAULT, summary="same words")
    await memory.remember(service="api", kind=KIND_GOVERNANCE, summary="same words")
    rows = await memory.recall(service="api")
    assert len(rows) == 2
    assert {r["kind"] for r in rows} == {KIND_FAULT, KIND_GOVERNANCE}


@pytest.mark.asyncio
async def test_identical_wording_on_two_services_never_merges(clean_store):
    """The scoping the similarity threshold depends on.

    Measured against gemini-embedding-001, the same fault text on two different
    services scores 0.905 — above the weakest genuine paraphrase. Similarity
    alone cannot tell those apart, so matching must never reach across services.
    If this test fails, the threshold in config is no longer safe.
    """
    memory = IncidentMemory()
    await memory.remember(
        service="checkout-api", kind=KIND_FAULT,
        summary="returned 503 after revision v42", incident_id="inc_1",
    )
    await memory.remember(
        service="payments-api", kind=KIND_FAULT,
        summary="returned 503 after revision v42", incident_id="inc_2",
    )
    checkout = await memory.recall(service="checkout-api")
    payments = await memory.recall(service="payments-api")
    assert len(checkout) == 1 and len(payments) == 1
    assert checkout[0]["memory_id"] != payments[0]["memory_id"]
    assert checkout[0]["occurrences"] == 1
