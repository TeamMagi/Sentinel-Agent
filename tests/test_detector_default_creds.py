"""DefaultCredentialsDetector — vendor-default kimlik bilgisi denemesi. B7."""
import json

import httpx
import pytest

from pentestai.detector.default_creds import DefaultCredentialsDetector
from pentestai.models import Actor, Scope
from pentestai.net.burst import BurstHarness
from pentestai.net import SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A"))
    detector = DefaultCredentialsDetector(BurstHarness(PolicyEngine(scope)), BASE)
    return store, detector, session


@pytest.mark.asyncio
async def test_confirmed_when_default_creds_work():
    def handler(request):
        body = json.loads(request.content or b"{}")
        if body.get("email") == "admin" and body.get("password") == "admin123":
            return httpx.Response(200, json={"authentication": {"token": "abc"}})
        return httpx.Response(401, json={"error": "invalid"})

    store, detector, session = _setup(handler)
    findings = await detector.scan(session, f"{BASE}/rest/user/login")
    assert len(findings) == 1
    assert findings[0].verdict == "CONFIRMED"
    assert "admin123" not in findings[0].evidence.leaked_markers[0]   # şifre redakte
    await store.aclose_all()


@pytest.mark.asyncio
async def test_no_finding_when_all_rejected():
    def handler(request):
        return httpx.Response(401, json={"error": "invalid"})

    store, detector, session = _setup(handler)
    findings = await detector.scan(session, f"{BASE}/rest/user/login")
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_stops_at_first_success():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        body = json.loads(request.content or b"{}")
        if body.get("email") == "admin" and body.get("password") == "admin":
            return httpx.Response(200, json={"token": "xyz"})
        return httpx.Response(401, json={"error": "invalid"})

    store, detector, session = _setup(handler)
    findings = await detector.scan(session, f"{BASE}/rest/user/login")
    assert len(findings) == 1
    assert calls["n"] == 1   # ilk çift (admin/admin) tuttu — devam etmedi
    await store.aclose_all()
