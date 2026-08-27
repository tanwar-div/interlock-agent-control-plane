# Interlock control plane.
# A single image serves the gateway, the console and the Pub/Sub push handlers;
# which role an instance plays is decided by configuration, not by the build.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so that application edits do not invalidate this layer.
COPY pyproject.toml README.md ./
COPY interlock ./interlock
RUN pip install --no-cache-dir .

# Cloud Run injects PORT; default keeps local runs identical to deployed ones.
ENV PORT=8080
EXPOSE 8080

# Run as a non-root user.
RUN useradd --create-home --uid 1000 interlock && chown -R interlock:interlock /app
USER interlock

CMD exec uvicorn interlock.gateway.app:app --host 0.0.0.0 --port ${PORT} --workers 1
