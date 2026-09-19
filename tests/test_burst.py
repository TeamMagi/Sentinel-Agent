"""BurstHarness — kontrollü, budget-farkında burst + kill-switch. B4."""
import httpx
import pytest

from pentestai.models import Actor, CapturedRequest, Scope
from pentestai.net import SessionStore
from pentestai.net.burst import BurstHarness
from pentestai.net.limits import BudgetExceeded, BudgetTracker
from pentestai.net.replay import ScopeError
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _setup(handler, **harness_kwargs):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A"))
    harness = BurstHarness(PolicyEngine(scope), **harness_kwargs)
    return store, harness, session


@pytest.mark.asyncio
async def test_no_rate_limit_fires_full_count():
    def always_ok(request):
        return httpx.Response(200, json={"ok": True})

    store, harness, session = _setup(always_ok)
    req = CapturedRequest(method="GET", url=f"{BASE}/api/x")
    results = await harness.fire(req, session, count=10)
    assert len(results) == 10
    assert all(r.status == 200 for r in results)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_kill_switch_stops_after_consecutive_blocks():
    calls = {"n": 0}

    def rate_limits_after_5(request):
        calls["n"] += 1
        if calls["n"] > 5:
            return httpx.Response(429, json={"error": "too many requests"})
        return httpx.Response(200, json={"ok": True})

    store, harness, session = _setup(rate_limits_after_5, kill_switch_after=3)
    req = CapturedRequest(method="GET", url=f"{BASE}/api/x")
    results = await harness.fire(req, session, count=20)
    # 5 başarılı + 3 art arda 429 → dur (8 istek), 20'ye kadar devam etmedi
    assert len(results) == 8
    assert [r.status for r in results[-3:]] == [429, 429, 429]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_max_burst_hard_cap_overrides_requested_count():
    def always_ok(request):
        return httpx.Response(200, json={"ok": True})

    store, harness, session = _setup(always_ok, max_burst=5)
    req = CapturedRequest(method="GET", url=f"{BASE}/api/x")
    results = await harness.fire(req, session, count=100)
    assert len(results) == 5
    await store.aclose_all()


@pytest.mark.asyncio
async def test_scope_error_on_out_of_scope_request():
    def always_ok(request):
        return httpx.Response(200, json={"ok": True})

    store, harness, session = _setup(always_ok)
    req = CapturedRequest(method="GET", url="http://evil.example.com/x")
    with pytest.raises(ScopeError):
        await harness.fire(req, session, count=3)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_budget_exceeded_propagates():
    def always_ok(request):
        return httpx.Response(200, json={"ok": True})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(always_ok))
    session = store.create(Actor(name="user_A"))
    harness = BurstHarness(PolicyEngine(scope), budget=BudgetTracker(max_total_requests=3))
    req = CapturedRequest(method="GET", url=f"{BASE}/api/x")
    with pytest.raises(BudgetExceeded):
        await harness.fire(req, session, count=10)
    await store.aclose_all()
