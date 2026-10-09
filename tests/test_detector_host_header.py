"""HostHeaderInjectionDetector — TIER_C.md C5: parola-sıfırlama Host/X-Forwarded-Host enjeksiyonu
(password reset poisoning). Network'süz (CLAUDE.md §6): `httpx.MockTransport`.
"""
import json

import httpx
import pytest

from pentestai.detector.host_header import HostHeaderInjectionDetector
from pentestai.models import Actor, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="POST", path_template="/forgot-password")


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                allowed_methods=["GET", "POST"], destructive_tests=True)


def _setup(handler, *, payload=None):
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A")
    session = store.create(A)
    detector = HostHeaderInjectionDetector(Replayer(PolicyEngine(_scope())), BASE, payload=payload)
    return detector, store, session


@pytest.mark.asyncio
async def test_confirmed_when_host_reflected_in_body():
    async def handler(request):
        host = request.headers.get("host", "")
        return httpx.Response(200, json={
            "message": "check your email",
            "debug_link": f"https://{host}/reset?token=abc123",
        })

    detector, store, session = _setup(handler)
    findings = await detector.run(EP, session, finding_id="F-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.parameter == "Host"
    assert f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_via_x_forwarded_host_fallback():
    """Uygulama `Host`'u YOK SAYAR ama reverse-proxy arkasında `X-Forwarded-Host`'a güvenir —
    yalnızca ikinci vektör (fallback) yansımalı."""
    async def handler(request):
        xfh = request.headers.get("x-forwarded-host", "")
        if not xfh:
            return httpx.Response(200, json={"message": "ok"})
        return httpx.Response(200, json={"link": f"https://{xfh}/reset?token=abc"})

    detector, store, session = _setup(handler)
    findings = await detector.run(EP, session, finding_id="F-1")
    assert findings[0].verdict == base.CONFIRMED
    assert findings[0].parameter == "X-Forwarded-Host"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_via_location_header_reflection():
    async def handler(request):
        host = request.headers.get("host", "")
        return httpx.Response(303, headers={"Location": f"https://{host}/check-email"})

    detector, store, session = _setup(handler)
    findings = await detector.run(EP, session, finding_id="F-1")
    assert findings[0].verdict == base.CONFIRMED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_host_never_reflected():
    async def handler(request):
        return httpx.Response(200, json={
            "message": "check your email",
            "link": "https://trusted.example.com/reset?token=abc123",
        })

    detector, store, session = _setup(handler)
    findings = await detector.run(EP, session, finding_id="F-1")
    assert findings[0].verdict == base.REJECTED
    assert not findings[0].evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_optional_payload_is_sent_as_json_body():
    seen_body = {}

    async def handler(request):
        seen_body["body"] = json.loads(request.content or b"{}")
        return httpx.Response(200, json={"message": "ok"})

    detector, store, session = _setup(handler, payload={"email": "probe@test.local"})
    await detector.run(EP, session, finding_id="F-1")
    assert seen_body["body"] == {"email": "probe@test.local"}
    await store.aclose_all()
