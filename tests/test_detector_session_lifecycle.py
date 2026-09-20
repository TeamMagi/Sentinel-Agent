"""SessionLifecycleDetector — fixation, logout sonrası geçerlilik, expiration. B3."""
import base64
import json

import httpx
import pytest

from pentestai.detector.session_lifecycle import SessionLifecycleDetector
from pentestai.models import Actor, AuthState, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle.base import INCONCLUSIVE
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
        if "authorization" in request.headers:
            return httpx.Response(200, json={"secret": "still here"})   # logout sonrası da 200
        return httpx.Response(403, json={"error": "forbidden"})   # anonim erişim GERÇEKTEN kapalı

    store, detector = _setup(handler)
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"})))
    anon = store.create(Actor(name="anonymous", role="anonymous"))
    findings = await detector.check_logout_invalidation(
        session, f"{BASE}/logout", f"{BASE}/api/profile", anon_session=anon)
    assert len(findings) == 1 and findings[0].verdict == "CONFIRMED"
    assert findings[0].evidence.negative_control is True
    await store.aclose_all()


@pytest.mark.asyncio
async def test_logout_invalidation_inconclusive_when_endpoint_is_public():
    # protected_url tasarımca public — anonim istek de 200 döner. Negatif kontrol başarısız
    # olmalı ve "hâlâ 200" sinyali yanlış CONFIRMED üretmemeli (bkz. kod-tarama-raporu.md #1).
    def handler(request):
        if request.url.path == "/logout":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"products": []})   # her zaman 200, auth'tan bağımsız

    store, detector = _setup(handler)
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"})))
    anon = store.create(Actor(name="anonymous", role="anonymous"))
    findings = await detector.check_logout_invalidation(
        session, f"{BASE}/logout", f"{BASE}/rest/products/search", anon_session=anon)
    assert len(findings) == 1
    assert findings[0].verdict == INCONCLUSIVE
    assert findings[0].evidence.negative_control is False
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


@pytest.mark.asyncio
async def test_fixation_allows_login_post_even_when_destructive_tests_off():
    # scope yalnızca GET/HEAD'e izin veriyor VE destructive_tests=False — login POST yine de
    # purpose="auth" ile geçmeli (Faz 3 öncesi session.client.post kapıyı hiç görmüyordu).
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"status": "ok"})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD"], destructive_tests=False)
    store = SessionStore(transport=httpx.MockTransport(handler))
    detector = SessionLifecycleDetector(Replayer(PolicyEngine(scope)), BASE)
    session = store.create(Actor(name="user_A"))
    session.client.cookies.set("session_id", "abc123")
    findings = await detector.check_session_fixation(
        session, f"{BASE}/login", {"email": "a@test.local", "password": "x"})
    assert len(findings) == 1 and findings[0].verdict == "CONFIRMED"
    assert calls == [f"{BASE}/login"]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_fixation_denied_by_scope_never_reaches_transport():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"status": "ok"})

    store, detector = _setup(handler)
    session = store.create(Actor(name="user_A"))
    session.client.cookies.set("session_id", "abc123")
    # login_url scope dışı bir host'u gösteriyor — istek hiç gönderilmemeli.
    findings = await detector.check_session_fixation(
        session, "http://evil.example/login", {"email": "a@test.local", "password": "x"})
    assert findings == []
    assert calls == []
    await store.aclose_all()
