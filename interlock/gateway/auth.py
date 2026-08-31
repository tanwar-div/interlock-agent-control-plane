"""Application-level authorization for the gateway.

Until now the gateway had no authorization of its own: it ran private on Cloud
Run, and IAM decided who could reach it at all. That is sound while every
caller is a service account, and useless the moment any part of the surface
needs to be reachable by a person who does not have one.

Two properties are wanted at once. Anyone should be able to ask what the fuse
would do -- read the catalogue, read the policy rules, score a hypothetical
action -- because a governance layer nobody can inspect is a claim rather than a
control. Nobody unauthenticated should be able to open an incident, decide an
approval, resume a run, erase memory, or read what real incidents contain.

So the read-only face is public and everything else requires proof, with the
Cloud Run IAM boundary kept underneath as the outer layer when it is enabled.
Enforcement is deny-by-default: a path is protected unless it appears in one of
the two sets below, so a route added later is protected by omission rather than
exposed by it.
"""
from __future__ import annotations

import logging
import time
from collections import deque

from fastapi import Request
from fastapi.responses import JSONResponse

from interlock.common.config import get_settings

logger = logging.getLogger(__name__)

# Readable by anyone. None of these disclose incident content, and none mutate.
PUBLIC_GET = frozenset({
    "/", "/health", "/healthz", "/readyz",
    "/v1/catalog",   # the action catalogue -- the trust root, and the point
    "/v1/policy",    # the named rules, in evaluation order
})

# Costs a model call, so it is public but rate limited.
PUBLIC_POST = frozenset({"/v1/simulate"})

_PREFIX_ALLOW = ("/static/", "/assets/", "/docs", "/openapi.json", "/redoc")

# The project site references its assets relatively, so they are served from the
# root alongside the API. Extensions rather than paths, because the site is a
# directory of files rather than a fixed list. Nothing under /v1 ends in any of
# these, so no API route can be reached through this.
_STATIC_SUFFIXES = (
    ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".svg", ".gif",
    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".mp4", ".webm", ".txt",
)


class _RateLimiter:
    """Fixed-window limiter, per client, in process.

    Cloud Run runs many instances, so this bounds abuse per instance rather
    than globally. That is the right trade here: it needs no shared state, and
    the thing being protected is a model budget, not a correctness property.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        seen = self._hits.setdefault(key, deque())
        while seen and now - seen[0] > self._window:
            seen.popleft()
        if len(seen) >= self._limit:
            return False
        seen.append(now)
        if len(self._hits) > 4096:  # bound memory against distributed callers
            for stale in [k for k, v in self._hits.items() if not v or now - v[-1] > self._window]:
                self._hits.pop(stale, None)
        return True


def _client(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_public(method: str, path: str) -> bool:
    if any(path.startswith(prefix) for prefix in _PREFIX_ALLOW):
        return True
    if method in ("GET", "HEAD"):
        if path.lower().endswith(_STATIC_SUFFIXES):
            return True
        return path in PUBLIC_GET
    if method == "POST":
        return path in PUBLIC_POST
    return False


def _authorized(request: Request) -> bool:
    """A caller is authorized if it presents the admin token.

    Google-signed OIDC tokens on the Pub/Sub push paths are verified by Cloud
    Run itself before the request arrives, which is why those paths are not
    listed as public here: with the IAM boundary in place they never reach this
    check unauthenticated, and without it they must present the token like
    anything else.
    """
    settings = get_settings()
    expected = settings.admin_token
    if not expected:
        return False
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return False
    # Constant-time comparison: an equality check on a secret leaks its prefix.
    import hmac

    return hmac.compare_digest(value, expected)


def install(app) -> None:
    """Install the authorization middleware on the app."""
    settings = get_settings()
    limiter = _RateLimiter(
        limit=settings.public_rate_limit,
        window_seconds=settings.public_rate_window_seconds,
    )

    @app.middleware("http")
    async def authorize(request: Request, call_next):
        if not get_settings().public_readonly_enabled:
            return await call_next(request)

        path = request.url.path.rstrip("/") or "/"
        public = _is_public(request.method, path)

        if public and request.method == "POST" and not limiter.allow(_client(request)):
            logger.info("rate limited %s on %s", _client(request), path)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "rate limit exceeded for anonymous scoring; "
                              "authenticate for unthrottled access"
                },
            )

        if not public and not _authorized(request):
            return JSONResponse(status_code=401, content={"detail": "authorization required"})

        return await call_next(request)


__all__ = ["PUBLIC_GET", "PUBLIC_POST", "install"]
