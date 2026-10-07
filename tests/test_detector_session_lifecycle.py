"""SessionLifecycleDetector — fixation, logout sonrası geçerlilik, expiration. B3."""
import base64
import json

import httpx
import pytest

from pentestai.detector.session_lifecycle import SessionLifecycleDetector
from pentestai.models import Actor, AuthState, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _fake_jwt(payload: dict) -> str:
    return f'{_b64({"alg": "HS256", "typ": "JWT"})}.{_b64(payload)}.fakesig'


def _setup(handler, *, methods=("GET", "HEAD", "POST")):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=list(methods), destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    detector = SessionLifecycleDetector(Replayer(PolicyEngine(scope)), BASE)
    return store, detector


@pytest.mark.asyncio
async def test_logout_invalidation_confirmed_when_token_still_works():
    def handler(request):
        if request.url.path == "/logout":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"secret": "still here"})   # logout sonrası da 200

    store, detector = _setup(handler)
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"})))
    findings = await detector.check_logout_invalidation(
        session, f"{BASE}/logout", f"{BASE}/api/profile")
    assert len(findings) == 1 and findings[0].verdict == "CONFIRMED"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_logout_invalidation_no_finding_when_properly_invalidated():
    state = {"logged_out": False}

    def handler(request):
        if request.url.path == "/logout":
            state["logged_out"] = True
            return httpx.Response(200, json={"status": "ok"})
        if state["logged_out"]:
            return httpx.Response(401, json={"error": "invalid session"})
        return httpx.Response(200, json={"secret": "still here"})

    store, detector = _setup(handler)
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"})))
    findings = await detector.check_logout_invalidation(
        session, f"{BASE}/logout", f"{BASE}/api/profile")
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_logout_invalidation_no_finding_when_never_accessible():
    def handler(request):
        return httpx.Response(403, json={"error": "forbidden"})

    store, detector = _setup(handler)
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"})))
    findings = await detector.check_logout_invalidation(
        session, f"{BASE}/logout", f"{BASE}/api/profile")
    assert findings == []
    await store.aclose_all()


def test_expiration_claim_confirmed_when_missing():
    store, detector = _setup(lambda r: httpx.Response(200))
    token = _fake_jwt({"sub": "user_A"})   # exp YOK
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": f"Bearer {token}"})))
    findings = detector.check_token_expiration_claim(session)
    assert len(findings) == 1 and findings[0].verdict == "CONFIRMED"


def test_expiration_claim_no_finding_when_present():
    store, detector = _setup(lambda r: httpx.Response(200))
    token = _fake_jwt({"sub": "user_A", "exp": 9999999999})
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": f"Bearer {token}"})))
    findings = detector.check_token_expiration_claim(session)
    assert findings == []


def test_expiration_claim_no_finding_when_not_jwt():
    store, detector = _setup(lambda r: httpx.Response(200))
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer opaque-token-123"})))
    findings = detector.check_token_expiration_claim(session)
    assert findings == []


@pytest.mark.asyncio
async def test_fixation_confirmed_when_cookie_unchanged():
    def handler(request):
        return httpx.Response(200, json={"status": "ok"})

    store, detector = _setup(handler)
    session = store.create(Actor(name="user_A"))
    session.client.cookies.set("session_id", "abc123")
    findings = await detector.check_session_fixation(
        session, f"{BASE}/login", {"email": "a@test.local", "password": "x"})
    assert len(findings) == 1 and findings[0].verdict == "CONFIRMED"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_fixation_no_finding_without_pre_login_cookie():
    store, detector = _setup(lambda r: httpx.Response(200, json={"status": "ok"}))
    session = store.create(Actor(name="user_A"))   # cookie yok — saf JWT bearer senaryosu
    findings = await detector.check_session_fixation(
        session, f"{BASE}/login", {"email": "a@test.local", "password": "x"})
    assert findings == []
    await store.aclose_all()
