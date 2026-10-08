"""RateLimitDetector — rate limit eksikliği / brute force / weak password policy. B4."""
import httpx
import pytest

from pentestai.detector.rate_limit import RateLimitDetector
from pentestai.models import Actor, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.net.burst import BurstHarness
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _setup(handler, *, methods=("GET", "HEAD"), **burst_kwargs):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=list(methods), destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A"))
    detector = RateLimitDetector(BurstHarness(PolicyEngine(scope), **burst_kwargs), BASE)
    return store, detector, session


@pytest.mark.asyncio
async def test_endpoint_confirmed_when_no_throttling():
    def always_ok(request):
        return httpx.Response(200, json={"ok": True})

    store, detector, session = _setup(always_ok)
    ep = Endpoint(method="GET", path_template="/api/products", id_param="id")
    findings = await detector.scan_endpoint(session, ep)
    assert len(findings) == 1
    assert findings[0].verdict == "CONFIRMED" and findings[0].type == "rate_limit"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_endpoint_no_finding_when_second_burst_throttles():
    # kod-tarama-raporu.md #7: ilk burst throttle GÖRMESE de, negatif kontrol için atılan
    # İKİNCİ burst'te throttle görülürse "eksiklik" iddiası yanlış çıkar — bulgu üretilmemeli.
    calls = {"n": 0}

    def throttles_on_second_burst(request):
        calls["n"] += 1
        return httpx.Response(429 if calls["n"] > 20 else 200, json={})

    store, detector, session = _setup(throttles_on_second_burst)
    ep = Endpoint(method="GET", path_template="/api/products", id_param="id")
    findings = await detector.scan_endpoint(session, ep)
    assert findings == []
    assert calls["n"] > 20   # ikinci burst gerçekten atıldı
    await store.aclose_all()


@pytest.mark.asyncio
async def test_endpoint_no_finding_when_throttled():
    calls = {"n": 0}

    def throttles(request):
        calls["n"] += 1
        return httpx.Response(429 if calls["n"] > 3 else 200, json={})

    store, detector, session = _setup(throttles)
    ep = Endpoint(method="GET", path_template="/api/products", id_param="id")
    findings = await detector.scan_endpoint(session, ep)
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_brute_force_confirmed_when_no_lockout():
    def login_always_401(request):
        return httpx.Response(401, json={"error": "invalid credentials"})

    store, detector, session = _setup(login_always_401, methods=("GET", "HEAD", "POST"))
    findings = await detector.scan_login_brute_force(
        session, f"{BASE}/rest/user/login", email="victim@test.local",
        wrong_passwords=["a1", "a2", "a3", "a4", "a5"])
    assert len(findings) == 1
    assert findings[0].verdict == "CONFIRMED"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_brute_force_no_finding_when_locked_out():
    calls = {"n": 0}

    def locks_after_3(request):
        calls["n"] += 1
        if calls["n"] > 3:
            return httpx.Response(403, json={"error": "account temporarily locked"})
        return httpx.Response(401, json={"error": "invalid credentials"})

    store, detector, session = _setup(locks_after_3, methods=("GET", "HEAD", "POST"))
    findings = await detector.scan_login_brute_force(
        session, f"{BASE}/rest/user/login", email="victim@test.local",
        wrong_passwords=["a1", "a2", "a3", "a4", "a5"])
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_weak_password_confirmed_when_accepted():
    def register_accepts_anything(request):
        return httpx.Response(201, json={"id": 1})

    store, detector, session = _setup(register_accepts_anything, methods=("GET", "HEAD", "POST"))
    findings = await detector.scan_weak_password_policy(session, f"{BASE}/api/Users")
    assert len(findings) == 1
    assert findings[0].verdict == "CONFIRMED"
    assert "123456" in findings[0].evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_weak_password_no_finding_when_all_rejected():
    def register_rejects_weak(request):
        return httpx.Response(400, json={"error": "password too weak"})

    store, detector, session = _setup(register_rejects_weak, methods=("GET", "HEAD", "POST"))
    findings = await detector.scan_weak_password_policy(session, f"{BASE}/api/Users")
    assert findings == []
    await store.aclose_all()
