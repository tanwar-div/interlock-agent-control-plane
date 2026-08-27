"""OpenTelemetry wiring.

ADK emits spans for agent runs, model calls and tool executions following the
GenAI semantic conventions. Exporting them to Cloud Trace turns an incident
into a waterfall showing exactly which agent called which tool, in what order,
and where the time went — which is the difference between an audit trail that
says what happened and one that shows it.

Interlock adds its own spans around the governance decisions so that a policy
denial appears in the same trace as the tool call it prevented.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_configured = False


def configure_telemetry(service_name: str) -> None:
    """Install a tracer provider once per process."""
    global _configured
    if _configured:
        return

    from interlock.common.config import get_settings

    settings = get_settings()
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create(
            {
                "service.name": service_name,
                "service.namespace": settings.trace_service_namespace,
                "deployment.environment": settings.environment,
            }
        )
        provider = TracerProvider(resource=resource)

        if settings.enable_cloud_trace and settings.project_id:
            from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter

            provider.add_span_processor(
                BatchSpanProcessor(CloudTraceSpanExporter(project_id=settings.project_id))
            )
            logger.info("exporting traces to Cloud Trace (project=%s)", settings.project_id)
        elif os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"):
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            logger.info("exporting traces via OTLP")
        else:
            logger.info("tracing configured without an exporter")

        trace.set_tracer_provider(provider)
        _configured = True
    except Exception as exc:  # noqa: BLE001 - telemetry must never break the service
        logger.warning("could not configure telemetry: %s", exc)


def get_tracer(name: str = "interlock") -> Any:
    from opentelemetry import trace

    return trace.get_tracer(name)


def instrument_fastapi(app: Any) -> None:
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz")
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not instrument FastAPI: %s", exc)


def configure_logging() -> None:
    from interlock.common.config import get_settings

    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
    )
    # These are chatty and drown out the interesting lines.
    for noisy in ("google.auth", "urllib3", "google.api_core", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
