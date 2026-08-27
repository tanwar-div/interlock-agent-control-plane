"""Append-only, hash-chained, signed audit ledger.

Every consequential thing that happens to an incident is written here before it
is considered to have happened. Each entry commits to its predecessor's hash,
and the whole entry is signed by the control plane key, so:

  * removing an entry breaks the chain at that point;
  * editing an entry changes its hash and breaks its successor's link; and
  * forging an entry requires the control plane signing key.

This is what makes "the agent did X at time T because of Y" a claim that can be
checked rather than merely asserted.
"""
from __future__ import annotations

import logging
from typing import Any

from interlock.common.config import get_settings
from interlock.common.models import (
    LedgerEntry,
    LedgerEventType,
    canonical_json,
    sha256_hex,
)
from interlock.common.store import DocumentStore, get_store
from interlock.identity.keys import control_plane_key, verify

logger = logging.getLogger(__name__)

HEADS_COLLECTION = "ledger_heads"
GENESIS_HASH = "0" * 64


class ChainVerificationError(RuntimeError):
    pass


class VerificationReport:
    def __init__(
        self,
        *,
        incident_id: str,
        entries_checked: int,
        valid: bool,
        problems: list[str],
    ) -> None:
        self.incident_id = incident_id
        self.entries_checked = entries_checked
        self.valid = valid
        self.problems = problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "entries_checked": self.entries_checked,
            "valid": self.valid,
            "problems": self.problems,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        status = "VALID" if self.valid else "BROKEN"
        return f"<VerificationReport {self.incident_id} {status} n={self.entries_checked}>"


def _doc_id(incident_id: str, sequence: int) -> str:
    # Zero padding keeps lexical ordering identical to numeric ordering, which
    # lets the chain be read back in order without a composite index.
    return f"{incident_id}__{sequence:08d}"


class Ledger:
    def __init__(self, store: DocumentStore | None = None) -> None:
        self._store = store or get_store()
        self._settings = get_settings()
        self._collection = self._settings.collection_ledger

    async def append(
        self,
        *,
        incident_id: str,
        event_type: LedgerEventType,
        actor: str,
        payload: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        """Atomically append one entry and return it."""
        private_pem, _ = control_plane_key()
        collection = self._collection

        def _txn(view: Any) -> dict[str, Any]:
            head = view.get(HEADS_COLLECTION, incident_id) or {}
            sequence = int(head.get("sequence", -1)) + 1
            prev_hash = head.get("hash") or GENESIS_HASH

            entry = LedgerEntry(
                incident_id=incident_id,
                sequence=sequence,
                event_type=event_type,
                actor=actor,
                payload=payload or {},
                prev_hash=prev_hash,
            )
            entry.entry_hash = entry.compute_hash()
            # Sign the hash rather than the whole document: the hash already
            # commits to every field including prev_hash.
            from interlock.identity.keys import sign as _sign

            entry.signature = _sign(private_pem, entry.entry_hash)

            record = entry.model_dump(mode="json")
            view.put(collection, _doc_id(incident_id, sequence), record)
            view.put(
                HEADS_COLLECTION,
                incident_id,
                {"sequence": sequence, "hash": entry.entry_hash, "incident_id": incident_id},
            )
            return record

        record = await self._store.transact(_txn)
        entry = LedgerEntry.model_validate(record)
        logger.debug(
            "ledger append incident=%s seq=%s event=%s", incident_id, entry.sequence, event_type.value
        )
        return entry

    async def head(self, incident_id: str) -> dict[str, Any] | None:
        return await self._store.get(HEADS_COLLECTION, incident_id)

    async def entries(self, incident_id: str, *, limit: int | None = None) -> list[LedgerEntry]:
        rows = await self._store.query(
            self._collection,
            where=[("incident_id", "==", incident_id)],
            order_by="sequence",
            limit=limit,
        )
        return [LedgerEntry.model_validate(r) for r in rows]

    async def verify_chain(self, incident_id: str) -> VerificationReport:
        """Recompute the whole chain and check every hash and signature."""
        _, public_pem = control_plane_key()
        entries = await self.entries(incident_id)
        problems: list[str] = []

        expected_prev = GENESIS_HASH
        for index, entry in enumerate(entries):
            if entry.sequence != index:
                problems.append(
                    f"sequence gap at position {index}: found {entry.sequence}"
                )
            if entry.prev_hash != expected_prev:
                problems.append(
                    f"entry {entry.sequence} links to {entry.prev_hash[:12]}… "
                    f"but predecessor hashes to {expected_prev[:12]}…"
                )
            recomputed = entry.compute_hash()
            if recomputed != entry.entry_hash:
                problems.append(
                    f"entry {entry.sequence} content does not match its hash "
                    f"(stored {entry.entry_hash[:12]}…, recomputed {recomputed[:12]}…)"
                )
            if not verify(public_pem, entry.entry_hash, entry.signature):
                problems.append(f"entry {entry.sequence} has an invalid control-plane signature")
            expected_prev = entry.entry_hash

        head = await self.head(incident_id)
        if head and entries and head.get("hash") != entries[-1].entry_hash:
            problems.append("recorded chain head does not match the last entry")

        return VerificationReport(
            incident_id=incident_id,
            entries_checked=len(entries),
            valid=not problems,
            problems=problems,
        )

    async def export_chain(self, incident_id: str) -> dict[str, Any]:
        """Portable evidence bundle for an external auditor."""
        entries = await self.entries(incident_id)
        report = await self.verify_chain(incident_id)
        _, public_pem = control_plane_key()
        body = {
            "incident_id": incident_id,
            "public_key_pem": public_pem,
            "entry_count": len(entries),
            "entries": [e.model_dump(mode="json") for e in entries],
            "verification": report.to_dict(),
        }
        body["bundle_digest"] = sha256_hex(canonical_json(body["entries"]))
        return body
