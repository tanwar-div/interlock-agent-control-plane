"""Semantic similarity for memory deduplication.

Memories were previously deduplicated by exact string equality on the summary,
which meant "checkout-api returned 503 after revision v42" and "checkout-api
503s on revision v42" were stored as two unrelated facts. That matters more
than it looks: the incident brief is assembled from recalled memories, so
duplicates crowd out other services' context and make a repeated observation
look like two independent ones when weighting.

Embeddings are an optimisation, never a requirement. Every function here
returns None rather than raising when the model is unreachable, and the caller
falls back to exact matching — the same posture the scorer takes toward Gemini.
"""
from __future__ import annotations

import asyncio
import logging
import math
from typing import Any

from interlock.common.config import get_settings, model_credentials_available

logger = logging.getLogger(__name__)

# 768 rather than the model's native 3072: memory records live in Firestore and
# are read on every incident brief, so a vector four times smaller is four times
# less to fetch. Retrieval quality at 768 is indistinguishable for text this
# short.
_DIMENSIONS = 768

_client: Any | None = None
_unavailable = False


def _get_client() -> Any | None:
    global _client, _unavailable
    if _unavailable:
        return None
    if _client is None:
        settings = get_settings()
        if not model_credentials_available(settings):
            _unavailable = True
            return None
        try:
            from google import genai

            _client = genai.Client(
                vertexai=True,
                project=settings.project_id,
                location=settings.model_location,
            )
        except Exception as exc:  # pragma: no cover - depends on environment
            logger.debug("embedding client unavailable: %s", exc)
            _unavailable = True
            return None
    return _client


async def embed(text: str) -> list[float] | None:
    """Embed one summary. Returns None whenever the caller should fall back."""
    settings = get_settings()
    if not settings.memory_embeddings_enabled or not text.strip():
        return None
    client = _get_client()
    if client is None:
        return None

    def _call() -> list[float] | None:
        from google.genai import types

        response = client.models.embed_content(
            model=settings.memory_embedding_model,
            contents=text[:2000],
            config=types.EmbedContentConfig(output_dimensionality=_DIMENSIONS),
        )
        if not response.embeddings:
            return None
        return list(response.embeddings[0].values)

    try:
        return await asyncio.wait_for(asyncio.to_thread(_call), timeout=10.0)
    except Exception as exc:
        logger.debug("embedding failed, falling back to exact match: %s", exc)
        return None


def cosine(a: list[float] | None, b: list[float] | None) -> float:
    """Cosine similarity. Returns 0.0 for anything missing or degenerate."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)
