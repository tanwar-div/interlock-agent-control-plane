"""Cross-incident memory.

A long-running fleet that cannot remember is condemned to make the same
proposal, get the same refusal, and waste the same tokens every time. This
module gives the fleet three kinds of durable recall, scoped to the service an
incident concerns:

  * **fault patterns** — how this service has failed before, and what the
    evidence looked like;
  * **remediation outcomes** — what was tried, and whether the independent
    auditor confirmed it worked;
  * **governance outcomes** — and this is the important one: what a human
    approved or denied, and the reason they gave.

The third kind is what makes refusal productive. When an operator denies an
action, that denial becomes context the fleet carries into every future
incident on that service. The agent stops re-proposing things people have
already rejected, which is the difference between a system that is governed and
a system that is merely blocked.

Memories decay. Something learned about a service three months ago, after the
service has been rewritten twice, is noise rather than context, so recall is
bounded by a TTL and ordered by recency.
"""
from __future__ import annotations

import datetime as dt
import logging
from typing import Any

from google.adk.memory import BaseMemoryService

from interlock.common.config import get_settings
from interlock.common.models import new_id, utcnow
from interlock.common.store import DocumentStore, get_store

logger = logging.getLogger(__name__)

# Memory kinds, most operationally valuable first.
KIND_GOVERNANCE = "governance_outcome"
KIND_REMEDIATION = "remediation_outcome"
KIND_FAULT = "fault_pattern"

_KIND_PRIORITY = {KIND_GOVERNANCE: 0, KIND_REMEDIATION: 1, KIND_FAULT: 2}

# Memories expire at different rates because they age at different rates. A
# human's decision about what is acceptable stays true until a human revisits
# it. An observation that an action failed is a fact about one moment in a
# mutable environment: permissions get granted, quotas get raised, deployments
# get fixed. Carrying such an observation for months is how a fleet talks
# itself out of trying something that would now succeed.
_KIND_TTL_DAYS = {
    KIND_GOVERNANCE: None,      # falls back to the configured TTL
    KIND_REMEDIATION: 14,
    KIND_FAULT: 30,
}


def _aware(value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    try:
        parsed = dt.datetime.fromisoformat(str(value))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
    except (TypeError, ValueError):
        return dt.datetime.min.replace(tzinfo=dt.UTC)


class IncidentMemory:
    """Durable, service-scoped recall backed by Firestore."""

    def __init__(self, store: DocumentStore | None = None) -> None:
        self._store = store or get_store()
        self._settings = get_settings()
        self._collection = self._settings.collection_memories

    # -- writing -----------------------------------------------------------

    async def remember(
        self,
        *,
        service: str,
        kind: str,
        summary: str,
        incident_id: str = "",
        detail: dict[str, Any] | None = None,
        weight: float = 1.0,
    ) -> dict[str, Any]:
        """Record one memory. Repeated observations reinforce rather than duplicate."""
        if not self._settings.memory_enabled or not service or not summary:
            return {}

        # Single-field filter, matched in process, for the same reason the
        # ledger avoids composite queries.
        candidates = await self._store.query(
            self._collection, where=[("service", "==", service)]
        )
        existing = [
            r for r in candidates if r.get("kind") == kind and r.get("summary") == summary
        ]
        if existing:
            record = existing[0]
            record["occurrences"] = int(record.get("occurrences", 1)) + 1
            record["last_seen"] = utcnow().isoformat()
            record["weight"] = float(record.get("weight", 1.0)) + weight
            if incident_id:
                incidents = list(record.get("incidents") or [])
                if incident_id not in incidents:
                    incidents.append(incident_id)
                record["incidents"] = incidents[-20:]
            await self._store.put(self._collection, record["memory_id"], record)
            logger.debug("reinforced memory for %s (x%d)", service, record["occurrences"])
            return record

        record = {
            "memory_id": new_id("mem"),
            "service": service,
            "kind": kind,
            "summary": summary,
            "detail": detail or {},
            "incidents": [incident_id] if incident_id else [],
            "occurrences": 1,
            "weight": weight,
            "created_at": utcnow().isoformat(),
            "last_seen": utcnow().isoformat(),
        }
        await self._store.put(self._collection, record["memory_id"], record)
        logger.info("remembered %s for %s: %s", kind, service, summary[:80])
        return record

    async def remember_governance_outcome(
        self,
        *,
        service: str,
        incident_id: str,
        action_type: str,
        approved: bool,
        resolved_by: str,
        justification: str,
    ) -> dict[str, Any]:
        """Record a human's decision so the fleet stops relitigating it."""
        verdict = "approved" if approved else "refused"
        summary = (
            f"A human {verdict} '{action_type}' on this service"
            + (f" — {justification}" if justification else "")
        )
        return await self.remember(
            service=service,
            kind=KIND_GOVERNANCE,
            summary=summary,
            incident_id=incident_id,
            detail={
                "action_type": action_type,
                "approved": approved,
                "resolved_by": resolved_by,
                "justification": justification,
            },
            # A human decision outweighs anything the fleet inferred by itself.
            weight=3.0,
        )

    async def remember_blocked_action(
        self, *, service: str, incident_id: str, action_type: str, reasons: list[str]
    ) -> dict[str, Any]:
        return await self.remember(
            service=service,
            kind=KIND_GOVERNANCE,
            summary=f"Policy refuses '{action_type}' on this service: {reasons[0] if reasons else 'blocked'}",
            incident_id=incident_id,
            detail={"action_type": action_type, "reasons": reasons, "approved": False},
            weight=2.0,
        )

    # -- reading -----------------------------------------------------------

    async def recall(self, *, service: str, limit: int | None = None) -> list[dict[str, Any]]:
        """Recall the most relevant live memories for a service."""
        if not self._settings.memory_enabled or not service:
            return []

        rows = await self._store.query(self._collection, where=[("service", "==", service)])
        now = utcnow()

        def _is_live(row: dict[str, Any]) -> bool:
            days = _KIND_TTL_DAYS.get(row.get("kind", ""))
            if days is None:
                days = self._settings.memory_ttl_days
            return _aware(row.get("last_seen")) >= now - dt.timedelta(days=days)

        live = [r for r in rows if _is_live(r)]

        # Human decisions first, then reinforcement, then recency.
        live.sort(
            key=lambda r: (
                _KIND_PRIORITY.get(r.get("kind", ""), 9),
                -float(r.get("weight", 1.0)),
                -_aware(r.get("last_seen")).timestamp(),
            )
        )
        return live[: (limit or self._settings.memory_recall_limit)]

    async def recall_brief(self, *, service: str) -> str:
        """Render recall as a block for an agent brief."""
        memories = await self.recall(service=service)
        if not memories:
            return ""

        governance = [m for m in memories if m.get("kind") == KIND_GOVERNANCE]
        observations = [m for m in memories if m.get("kind") != KIND_GOVERNANCE]
        lines: list[str] = []

        if governance:
            lines.append("DECISIONS A HUMAN HAS ALREADY MADE ABOUT THIS SERVICE (binding):")
            for memory in governance:
                lines.append(f"- {memory.get('summary')}")
            lines.append(
                "These are precedent. Do not propose an action a human has refused here "
                "unless circumstances are materially different, and say what changed."
            )

        if observations:
            if lines:
                lines.append("")
            lines.append("WHAT PAST INCIDENTS ON THIS SERVICE OBSERVED (context, not fact):")
            for memory in observations:
                seen = ""
                if int(memory.get("occurrences", 1)) > 1:
                    seen = f" (seen {memory['occurrences']} times)"
                lines.append(f"- {memory.get('summary')}{seen}")
            lines.append(
                "\nThese are observations from earlier incidents, not statements about the "
                "system as it is now. Environments change between incidents: permissions "
                "are granted, quotas are raised, bad deployments are replaced.\n"
                "Use them to know where to look first. NEVER use them as a reason to skip "
                "an action or to declare something impossible. In particular, if a past "
                "incident records that an action failed, you must still attempt that action "
                "and observe what happens now — a remembered failure is a hypothesis to "
                "test, not a result to report. Only what you observe in this incident may "
                "be stated as fact."
            )
        return "\n".join(lines)

    async def forget_service(self, service: str) -> int:
        rows = await self._store.query(self._collection, where=[("service", "==", service)])
        for row in rows:
            await self._store.delete(self._collection, row["memory_id"])
        return len(rows)

    async def all_memories(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = await self._store.query(self._collection, limit=limit)
        rows.sort(key=lambda r: _aware(r.get("last_seen")), reverse=True)
        return rows


class InterlockMemoryService(BaseMemoryService):
    """Adapter exposing `IncidentMemory` through ADK's memory interface.

    This lets agents reach recall through ADK's own `load_memory` tool, rather
    than only through briefs the orchestrator assembles. It must genuinely
    subclass `BaseMemoryService`: ADK type-validates the service it is handed,
    so a structurally compatible class is not sufficient.
    """

    def __init__(self, memory: IncidentMemory | None = None) -> None:
        self._memory = memory or IncidentMemory()

    async def add_session_to_memory(self, session: Any) -> None:  # pragma: no cover - ADK hook
        return None

    async def add_memory(self, *, app_name: str, user_id: str, memories: Any, **_: Any) -> None:
        for entry in memories or []:
            text = ""
            content = getattr(entry, "content", None)
            if content is not None and getattr(content, "parts", None):
                text = " ".join(getattr(p, "text", "") or "" for p in content.parts)
            if text.strip():
                await self._memory.remember(service=user_id, kind=KIND_FAULT, summary=text[:500])

    async def search_memory(self, *, app_name: str, user_id: str, query: str) -> Any:
        from google.adk.memory.base_memory_service import SearchMemoryResponse
        from google.adk.memory.memory_entry import MemoryEntry
        from google.genai import types

        rows = await self._memory.recall(service=user_id)
        terms = {t for t in query.lower().split() if len(t) > 3}
        if terms:
            scored = [
                (sum(1 for t in terms if t in r.get("summary", "").lower()), r) for r in rows
            ]
            rows = [r for score, r in sorted(scored, key=lambda x: -x[0])]

        return SearchMemoryResponse(
            memories=[
                MemoryEntry(
                    content=types.Content(
                        role="user", parts=[types.Part(text=r.get("summary", ""))]
                    ),
                    author=r.get("kind", "memory"),
                    timestamp=str(r.get("last_seen", "")),
                )
                for r in rows[: self._memory._settings.memory_recall_limit]
            ]
        )
