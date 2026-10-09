"""RaceHarness — TIER_C.md C4: `asyncio.Barrier` ile GERÇEK eşzamanlı istek gönderimi.
`httpx.MockTransport` (network'süz, CLAUDE.md §6) — handler'lar gerçek eşzamanlılığı GÖZLEMLEMEK
için async `asyncio.sleep` kullanır (MockTransport async handler'ı destekler)."""
import asyncio

import httpx
import pytest

from pentestai.models import Actor, AuthState, CapturedRequest, Scope
from pentestai.net.limits import BudgetExceeded, BudgetTracker
from pentestai.net.race import RaceHarness
from pentestai.net.replay import ScopeError
from pentestai.net.session_store import SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _scope(*, destructive_tests: bool = True) -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                allowed_methods=["GET", "POST"], destructive_tests=destructive_tests)


@pytest.mark.asyncio
async def test_fires_all_requests_truly_concurrently():
    """Sıralı-ama-hızlı DEĞİL: N görev AYNI ANDA aktif olmalı (max eşzamanlı sayaç == N)."""
    state = {"active": 0, "max_active": 0}

    async def handler(request):
        state["active"] += 1
        state["max_active"] = max(state["max_active"], state["active"])
        await asyncio.sleep(0.05)   # TOCTOU penceresini simüle eder
        state["active"] -= 1
        return httpx.Response(200, json={"ok": True})

    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A")
    session = store.create(A)
    harness = RaceHarness(PolicyEngine(_scope()))
    req = CapturedRequest(method="POST", url=f"{BASE}/redeem")
    results = await harness.fire_concurrent(req, session, count=8)
    assert len(results) == 8
    assert all(r.status == 200 for r in results)
    assert state["max_active"] == 8   # hepsi GERÇEKTEN aynı anda aktifti
    await store.aclose_all()


@pytest.mark.asyncio
async def test_injects_bearer_auth_header_on_every_request():
    seen_auth: list[str] = []

    async def handler(request):
        seen_auth.append(request.headers.get("authorization", ""))
        return httpx.Response(200)

    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer tok-123"}))
    session = store.create(A)
    harness = RaceHarness(PolicyEngine(_scope()))
    req = CapturedRequest(method="POST", url=f"{BASE}/redeem")
    await harness.fire_concurrent(req, session, count=5)
    assert len(seen_auth) == 5
    assert all(h == "Bearer tok-123" for h in seen_auth)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_scope_denied_raises_without_sending_any_request():
    sent = {"count": 0}

    async def handler(request):
        sent["count"] += 1
        return httpx.Response(200)

    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A")
    session = store.create(A)
    scope = Scope(allowed_hosts=["other.test.local"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    harness = RaceHarness(PolicyEngine(scope))
    req = CapturedRequest(method="POST", url=f"{BASE}/redeem")
    with pytest.raises(ScopeError):
        await harness.fire_concurrent(req, session, count=5)
    assert sent["count"] == 0
    await store.aclose_all()


@pytest.mark.asyncio
async def test_budget_exceeded_prevents_any_request_upfront():
    """Bütçe barrier'dan ÖNCE, TEK SEFERDE sayılır — kısmi ateşleme/deadlock riski yok."""
    sent = {"count": 0}

    async def handler(request):
        sent["count"] += 1
        return httpx.Response(200)

    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A")
    session = store.create(A)
    harness = RaceHarness(PolicyEngine(_scope()), budget=BudgetTracker(max_total_requests=3))
    req = CapturedRequest(method="POST", url=f"{BASE}/redeem")
    with pytest.raises(BudgetExceeded):
        await harness.fire_concurrent(req, session, count=10)
    assert sent["count"] == 0   # hiçbiri barrier'a ULAŞMADI
    await store.aclose_all()


@pytest.mark.asyncio
async def test_count_is_capped_at_max_concurrency():
    sent = {"count": 0}

    async def handler(request):
        sent["count"] += 1
        return httpx.Response(200)

    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A")
    session = store.create(A)
    harness = RaceHarness(PolicyEngine(_scope()), max_concurrency=5)
    req = CapturedRequest(method="POST", url=f"{BASE}/redeem")
    results = await harness.fire_concurrent(req, session, count=100)
    assert len(results) == 5
    assert sent["count"] == 5
    await store.aclose_all()
