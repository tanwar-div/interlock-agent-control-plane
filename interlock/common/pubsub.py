"""Pub/Sub publishing and push-message decoding.

Phases are dispatched as messages rather than executed inside the request that
triggered them. That decoupling is what lets an incident span hours without
holding a connection open, survive an instance being recycled mid-flight, and
retry a failed phase without replaying the ones that already succeeded.
"""
from __future__ import annotations

import base64
import json
import logging
from typing import Any

from interlock.common.config import get_settings

logger = logging.getLogger(__name__)

_publisher: Any | None = None


def _client() -> Any | None:
    global _publisher
    if _publisher is not None:
        return _publisher
    settings = get_settings()
    if not settings.project_id:
        return None
    try:
        from google.cloud import pubsub_v1

        _publisher = pubsub_v1.PublisherClient()
        return _publisher
    except Exception as exc:
        logger.warning("Pub/Sub publisher unavailable: %s", exc)
        return None


def publish(topic: str, payload: dict[str, Any], **attributes: str) -> str | None:
    """Publish one JSON message. Returns the message id, or None if disabled."""
    client = _client()
    if client is None:
        return None
    settings = get_settings()
    try:
        future = client.publish(
            settings.topic_path(topic),
            json.dumps(payload).encode("utf-8"),
            **{k: str(v) for k, v in attributes.items()},
        )
        return future.result(timeout=30)
    except Exception as exc:
        logger.error("failed to publish to %s: %s", topic, exc)
        return None


def decode_push(body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Decode a Pub/Sub push envelope into (payload, attributes).

    Accepts a bare payload too, so the same endpoint can be driven directly
    during local testing.
    """
    message = body.get("message")
    if not isinstance(message, dict):
        return body, {}

    attributes = {str(k): str(v) for k, v in (message.get("attributes") or {}).items()}
    data = message.get("data")
    if not data:
        return {}, attributes
    try:
        decoded = base64.b64decode(data).decode("utf-8")
        payload = json.loads(decoded)
        return (payload if isinstance(payload, dict) else {"value": payload}), attributes
    except Exception as exc:
        logger.error("could not decode Pub/Sub message: %s", exc)
        return {}, attributes


def parse_monitoring_alert(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalise a Cloud Monitoring notification into our Alert shape."""
    incident = payload.get("incident") or {}
    if not incident:
        return payload

    resource = incident.get("resource", {}) or {}
    labels = {**(resource.get("labels") or {}), **(incident.get("metric", {}).get("labels") or {})}
    service = (
        labels.get("service_name")
        or labels.get("configuration_name")
        or incident.get("resource_display_name", "")
    )
    return {
        "source": "cloud-monitoring",
        "title": incident.get("condition_name") or incident.get("summary", "Monitoring alert"),
        "description": incident.get("summary", ""),
        "resource_type": resource.get("type", "cloud_run_revision"),
        "resource_name": service,
        "severity": (incident.get("severity") or "WARNING").upper(),
        "labels": {str(k): str(v) for k, v in labels.items()},
        "raw": payload,
    }
