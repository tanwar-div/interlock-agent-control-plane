"""Durable document store.

Interlock keeps every piece of long-lived state in Firestore: incident state
machines, checkpoints, the audit ledger, the agent registry and pending
approvals. Firestore is the reason an incident can survive the death of the
process that was handling it.

A memory-backed implementation with identical semantics is provided so the
whole system can be exercised locally and in tests without a cloud project.
"""
from __future__ import annotations

import asyncio
import copy
import logging
import threading
from collections.abc import Callable, Iterable
from typing import Any, Protocol

from interlock.common.config import get_settings

logger = logging.getLogger(__name__)


class ConflictError(RuntimeError):
    """Raised when an optimistic-concurrency guard rejects a write."""


class DocumentStore(Protocol):
    async def get(self, collection: str, doc_id: str) -> dict[str, Any] | None: ...
    async def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None: ...
    async def patch(self, collection: str, doc_id: str, data: dict[str, Any]) -> None: ...
    async def delete(self, collection: str, doc_id: str) -> None: ...
    async def query(
        self,
        collection: str,
        *,
        where: Iterable[tuple[str, str, Any]] = (),
        order_by: str | None = None,
        descending: bool = False,
        limit: int | None = None,
    ) -> list[dict[str, Any]]: ...
    async def transact(self, fn: Callable[..., Any]) -> Any: ...


# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------


class MemoryStore:
    """Process-local store with the same contract as the Firestore one."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict[str, Any]]] = {}
        self._lock = threading.RLock()

    async def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            doc = self._data.get(collection, {}).get(doc_id)
            return copy.deepcopy(doc) if doc is not None else None

    async def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self._data.setdefault(collection, {})[doc_id] = copy.deepcopy(data)

    async def patch(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            existing = self._data.setdefault(collection, {}).setdefault(doc_id, {})
            existing.update(copy.deepcopy(data))

    async def delete(self, collection: str, doc_id: str) -> None:
        with self._lock:
            self._data.get(collection, {}).pop(doc_id, None)

    async def query(
        self,
        collection: str,
        *,
        where: Iterable[tuple[str, str, Any]] = (),
        order_by: str | None = None,
        descending: bool = False,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        ops = {
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
            ">": lambda a, b: a is not None and a > b,
            ">=": lambda a, b: a is not None and a >= b,
            "<": lambda a, b: a is not None and a < b,
            "<=": lambda a, b: a is not None and a <= b,
            "in": lambda a, b: a in b,
        }
        with self._lock:
            rows = [copy.deepcopy(d) for d in self._data.get(collection, {}).values()]
        for field, op, value in where:
            fn = ops[op]
            rows = [r for r in rows if fn(r.get(field), value)]
        if order_by:
            rows.sort(key=lambda r: (r.get(order_by) is None, r.get(order_by)), reverse=descending)
        return rows[:limit] if limit else rows

    async def transact(self, fn: Callable[..., Any]) -> Any:
        # The global lock gives serialisable semantics, which is stricter than
        # Firestore but never less correct. The body is handed a synchronous
        # view so that transaction code is identical across both backends.
        with self._lock:
            result = fn(_MemoryTransactionalView(self._data))
            if asyncio.iscoroutine(result):
                raise TypeError("transaction body must be synchronous")
            return result


class _MemoryTransactionalView:
    """Synchronous read/write view over the in-memory store, mirroring
    `_TransactionalView` so transaction bodies are backend-agnostic."""

    def __init__(self, data: dict[str, dict[str, dict[str, Any]]]) -> None:
        self._data = data

    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        doc = self._data.get(collection, {}).get(doc_id)
        return copy.deepcopy(doc) if doc is not None else None

    def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        self._data.setdefault(collection, {})[doc_id] = copy.deepcopy(data)

    def patch(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        existing = self._data.setdefault(collection, {}).setdefault(doc_id, {})
        existing.update(copy.deepcopy(data))


# ---------------------------------------------------------------------------
# Firestore implementation
# ---------------------------------------------------------------------------


class FirestoreStore:
    """Firestore-backed store. All calls run off the event loop thread."""

    def __init__(self, project_id: str, database: str = "(default)") -> None:
        from google.cloud import firestore

        self._firestore = firestore
        self._client = firestore.Client(project=project_id, database=database)

    @property
    def client(self) -> Any:
        return self._client

    async def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        def _get() -> dict[str, Any] | None:
            snap = self._client.collection(collection).document(doc_id).get()
            return snap.to_dict() if snap.exists else None

        return await asyncio.to_thread(_get)

    async def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        await asyncio.to_thread(
            lambda: self._client.collection(collection).document(doc_id).set(data)
        )

    async def patch(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        await asyncio.to_thread(
            lambda: self._client.collection(collection).document(doc_id).set(data, merge=True)
        )

    async def delete(self, collection: str, doc_id: str) -> None:
        await asyncio.to_thread(
            lambda: self._client.collection(collection).document(doc_id).delete()
        )

    async def query(
        self,
        collection: str,
        *,
        where: Iterable[tuple[str, str, Any]] = (),
        order_by: str | None = None,
        descending: bool = False,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        def _query() -> list[dict[str, Any]]:
            from google.cloud.firestore_v1.base_query import FieldFilter

            q: Any = self._client.collection(collection)
            for field, op, value in where:
                q = q.where(filter=FieldFilter(field, op, value))
            if order_by:
                direction = (
                    self._firestore.Query.DESCENDING
                    if descending
                    else self._firestore.Query.ASCENDING
                )
                q = q.order_by(order_by, direction=direction)
            if limit:
                q = q.limit(limit)
            return [d.to_dict() for d in q.stream()]

        return await asyncio.to_thread(_query)

    async def transact(self, fn: Callable[..., Any]) -> Any:
        def _run() -> Any:
            transaction = self._client.transaction()

            @self._firestore.transactional
            def _inner(txn: Any) -> Any:
                return fn(_TransactionalView(self._client, txn))

            return _inner(transaction)

        return await asyncio.to_thread(_run)


class _TransactionalView:
    """Synchronous read/write view bound to an open Firestore transaction."""

    def __init__(self, client: Any, txn: Any) -> None:
        self._client = client
        self._txn = txn

    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        ref = self._client.collection(collection).document(doc_id)
        snap = ref.get(transaction=self._txn)
        return snap.to_dict() if snap.exists else None

    def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        ref = self._client.collection(collection).document(doc_id)
        self._txn.set(ref, data)

    def patch(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        ref = self._client.collection(collection).document(doc_id)
        self._txn.set(ref, data, merge=True)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_store: DocumentStore | None = None
_store_lock = threading.Lock()


def get_store() -> DocumentStore:
    """Return the process-wide store, choosing Firestore when configured."""
    global _store
    with _store_lock:
        if _store is not None:
            return _store
        settings = get_settings()
        if settings.project_id:
            try:
                _store = FirestoreStore(settings.project_id, settings.firestore_database)
                logger.info("using Firestore store (project=%s)", settings.project_id)
            except Exception as exc:
                logger.warning("Firestore unavailable (%s); falling back to in-memory store", exc)
                _store = MemoryStore()
        else:
            logger.info("INTERLOCK_PROJECT_ID not set; using in-memory store")
            _store = MemoryStore()
        return _store


def set_store(store: DocumentStore) -> None:
    """Override the store. Used by tests and by the local harness."""
    global _store
    with _store_lock:
        _store = store
