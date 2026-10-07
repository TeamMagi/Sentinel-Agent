"""RetryPolicy + BudgetTracker (kill-switch). DESIGN.md §10.11, §14 (milestone 0.9)."""
import httpx
import pytest

from pentestai.models import Actor, AuthState, CapturedRequest, Scope
from pentestai.net import BudgetExceeded, BudgetTracker, Replayer, RetryPolicy, SessionStore
from pentestai.policy import PolicyEngine


def _scope(methods=("GET", "HEAD"), destructive_tests=False):
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                 allowed_path_prefixes=["/"], allowed_methods=list(methods),
                 destructive_tests=destructive_tests)


def _store(handler):
    return SessionStore(transport=httpx.MockTransport(handler))


URL = "http://localhost:3000/api/x"


@pytest.mark.asyncio
async def test_retry_on_5xx_then_success():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200 if calls["n"] >= 3 else 500, json={"ok": True})

    store = _store(handler)
    s = store.create(Actor(name="a", auth=AuthState()))
    replayer = Replayer(PolicyEngine(_scope()), retry=RetryPolicy(max_retries=2, backoff_base=0))
    resp = await replayer.replay(CapturedRequest(method="GET", url=URL), s)
    assert resp.status == 200
    assert calls["n"] == 3            # 2 retry + 1 başarı
    await store.aclose_all()


@pytest.mark.asyncio
async def test_retry_respects_429_retry_after():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json={"ok": True})

    store = _store(handler)
    s = store.create(Actor(name="a", auth=AuthState()))
    replayer = Replayer(PolicyEngine(_scope()), retry=RetryPolicy(max_retries=2, backoff_base=0))
    resp = await replayer.replay(CapturedRequest(method="GET", url=URL), s)
    assert resp.status == 200 and calls["n"] == 2
    await store.aclose_all()


@pytest.mark.asyncio
async def test_no_retry_on_state_changing():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(500)

    store = _store(handler)
    s = store.create(Actor(name="a", auth=AuthState()))
    replayer = Replayer(PolicyEngine(_scope(methods=("GET", "POST"), destructive_tests=True)),
                        retry=RetryPolicy(max_retries=3, backoff_base=0))
    resp = await replayer.replay(CapturedRequest(method="POST", url=URL), s)
    assert resp.status == 500 and calls["n"] == 1   # state-changing → retry YOK
    await store.aclose_all()


@pytest.mark.asyncio
async def test_budget_kill_switch():
    def handler(request):
        return httpx.Response(200, json={"ok": True})

    store = _store(handler)
    s = store.create(Actor(name="a", auth=AuthState()))
    replayer = Replayer(PolicyEngine(_scope()),
                        budget=BudgetTracker(max_total_requests=2, max_wall_clock_sec=900))
    await replayer.replay(CapturedRequest(method="GET", url=URL), s)
    await replayer.replay(CapturedRequest(method="GET", url=URL), s)
    with pytest.raises(BudgetExceeded):
        await replayer.replay(CapturedRequest(method="GET", url=URL), s)
    await store.aclose_all()
