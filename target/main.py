"""checkout-api — a small service that exists to be broken on purpose.

Interlock needs something real to diagnose and repair. This is it: a genuine
Cloud Run service with two behaviours selected by an environment variable, so a
deploy can introduce a real regression and the fleet has to find it from logs
and metrics rather than from anything we tell it.

  RELEASE=healthy  — serves normally
  RELEASE=broken   — fails a fixed share of requests with 503, the way a bad
                     release usually does: not everything, just enough
"""
from __future__ import annotations

import logging
import os
import random
import time

from fastapi import FastAPI, Response

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("checkout-api")

RELEASE = os.environ.get("RELEASE", "healthy").lower()
FAILURE_RATE = float(os.environ.get("FAILURE_RATE", "0.65"))
REVISION = os.environ.get("K_REVISION", "local")

app = FastAPI(title="checkout-api")

_orders = {"count": 0}


@app.get("/")
async def root() -> dict:
    return {"service": "checkout-api", "release": RELEASE, "revision": REVISION}


@app.get("/healthz")
async def healthz() -> dict:
    # Readiness stays green deliberately. A release that fails its own health
    # check gets rolled back by the platform and never becomes an incident;
    # the interesting failures are the ones that look healthy from outside.
    return {"status": "ok", "revision": REVISION}


# response_model=None: this handler returns either a dict or a raw Response,
# which FastAPI cannot turn into a single response model.
@app.post("/checkout", response_model=None)
@app.get("/checkout", response_model=None)
async def checkout():
    _orders["count"] += 1

    if RELEASE == "broken" and random.random() < FAILURE_RATE:
        # A regression in the payment client: the connection pool was sized for
        # the old synchronous client and is exhausted under normal load.
        logger.error(
            "checkout failed: payment client connection pool exhausted "
            "(max_connections=8 reached); upstream connect timeout after 30000ms "
            "[revision=%s]",
            REVISION,
        )
        return Response(
            content='{"error":"payment upstream unavailable"}',
            status_code=503,
            media_type="application/json",
        )

    time.sleep(0.01)
    logger.info("checkout ok order=%d revision=%s", _orders["count"], REVISION)
    return {"ok": True, "order": _orders["count"], "revision": REVISION}
