"""The gateway's application-level authorization.

The read-only face is public so that anyone can inspect what the fuse would do.
Everything that opens incidents, decides approvals or reads incident content
must refuse an unauthenticated caller. These tests exist because that boundary
is the only thing standing between a public URL and an open control plane.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from interlock.common.config import get_settings
from interlock.gateway import auth


@pytest.fixture
def build(monkeypatch):
    """An app carrying the middleware and one route per protection class."""

    def _build(**settings):
        for key, value in settings.items():
            monkeypatch.setenv(f"INTERLOCK_{key.upper()}", str(value))
        get_settings.cache_clear()
        app = FastAPI()
        auth.install(app)

        @app.get("/v1/catalog")
        async def catalogue():
            return {"public": True}

        @app.post("/v1/simulate")
        async def simulate():
            return {"scored": True}

        @app.get("/v1/incidents")
        async def incidents():
            return {"secret": True}

        @app.post("/v1/alerts")
        async def alerts():
            return {"opened": True}

        @app.get("/v1/some-route-added-later")
        async def later():
            return {"secret": True}

        return TestClient(app)

    yield _build
    get_settings.cache_clear()


def test_disabled_by_default_changes_nothing(build):
    client = build(public_readonly_enabled=False)
    assert client.get("/v1/incidents").status_code == 200
    assert client.post("/v1/alerts").status_code == 200


def test_public_reads_need_no_credentials(build):
    client = build(public_readonly_enabled=True, admin_token="s3cret")
    assert client.get("/v1/catalog").status_code == 200
    assert client.post("/v1/simulate").status_code == 200


def test_everything_else_refuses_an_anonymous_caller(build):
    client = build(public_readonly_enabled=True, admin_token="s3cret")
    assert client.get("/v1/incidents").status_code == 401
    assert client.post("/v1/alerts").status_code == 401


def test_the_admin_token_opens_the_protected_surface(build):
    client = build(public_readonly_enabled=True, admin_token="s3cret")
    ok = {"Authorization": "Bearer s3cret"}
    assert client.get("/v1/incidents", headers=ok).status_code == 200
    assert client.post("/v1/alerts", headers=ok).status_code == 200


@pytest.mark.parametrize(
    "header",
    ["Bearer wrong", "Bearer ", "Basic s3cret", "s3cret", "Bearer s3cre", "Bearer s3cretX"],
)
def test_a_wrong_credential_is_refused(build, header):
    client = build(public_readonly_enabled=True, admin_token="s3cret")
    assert client.get("/v1/incidents", headers={"Authorization": header}).status_code == 401


def test_an_unset_admin_token_refuses_rather_than_admits(build):
    """Misconfiguration must fail closed. An empty expected secret must never
    match an empty presented one."""
    client = build(public_readonly_enabled=True, admin_token="")
    assert client.get("/v1/incidents").status_code == 401
    assert client.get("/v1/incidents", headers={"Authorization": "Bearer "}).status_code == 401


def test_a_route_added_later_is_protected_by_omission(build):
    """Deny-by-default. Someone adding a route should have to opt into exposing
    it, not remember to protect it."""
    client = build(public_readonly_enabled=True, admin_token="s3cret")
    assert client.get("/v1/some-route-added-later").status_code == 401


def test_anonymous_scoring_is_rate_limited(build):
    client = build(public_readonly_enabled=True, admin_token="s3cret",
                   public_rate_limit=3, public_rate_window_seconds=60)
    codes = [client.post("/v1/simulate").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429]


def test_the_limit_is_per_caller(build):
    client = build(public_readonly_enabled=True, admin_token="s3cret",
                   public_rate_limit=2, public_rate_window_seconds=60)
    first = {"X-Forwarded-For": "203.0.113.1"}
    second = {"X-Forwarded-For": "203.0.113.2"}
    assert [client.post("/v1/simulate", headers=first).status_code for _ in range(3)] == [200, 200, 429]
    # A different caller is unaffected by the first one's exhaustion.
    assert client.post("/v1/simulate", headers=second).status_code == 200


def test_public_reads_are_not_rate_limited(build):
    """Throttling exists to bound a model budget, and reading the catalogue
    costs nothing."""
    client = build(public_readonly_enabled=True, admin_token="s3cret",
                   public_rate_limit=2, public_rate_window_seconds=60)
    assert all(client.get("/v1/catalog").status_code == 200 for _ in range(6))
