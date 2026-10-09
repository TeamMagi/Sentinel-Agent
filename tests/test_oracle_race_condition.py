"""RaceConditionOracle — TIER_C.md C4: TOCTOU race condition kanıtı.

`httpx.MockTransport` ile iki sahte backend simüle edilir: check-then-set arasında `await
asyncio.sleep` (TOCTOU penceresi) bırakan SAVUNMASIZ bir "kupon kullan" uç noktası, ve
check-and-set'i atomik yapan (kilit) GÜVENLİ bir sürümü. Network'süz (CLAUDE.md §6).
"""
import asyncio

import httpx
import pytest

from pentestai.models import Actor, Endpoint, Scope
from pentestai.net.race import RaceHarness
from pentestai.net.session_store import SessionStore
from pentestai.oracle import base
from pentestai.oracle.race_condition import RaceConditionOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="POST", path_template="/coupons/{id}/redeem", id_param="id")


def _vulnerable_redeem_handler():
    """TOCTOU: check (oku) ile set (yaz) arasında `await` var — N eşzamanlı istek HEPSİ
    'kullanılmamış' okur, HEPSİ başarılı olur (gerçek dünyadaki klasik kupon-çoklu-kullanım açığı)."""
    used = {"flag": False}

    async def handler(request):
        if used["flag"]:
            return httpx.Response(409, json={"error": "already used"})
        await asyncio.sleep(0.02)   # DB round-trip'i simüle eder — TOCTOU penceresi
        used["flag"] = True
        return httpx.Response(200, json={"ok": True})

    return handler


def _safe_redeem_handler():
    """Atomik check-and-set (kilit) — yalnızca BİR istek başarılı olabilir."""
    used = {"flag": False}
    lock = asyncio.Lock()

    async def handler(request):
        async with lock:
            if used["flag"]:
                return httpx.Response(409, json={"error": "already used"})
            used["flag"] = True
            return httpx.Response(200, json={"ok": True})

    return handler


def _already_used_handler():
    async def handler(request):
        return httpx.Response(409, json={"error": "already used"})

    return handler


def _scope(*, destructive_tests: bool = True) -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                allowed_methods=["GET", "POST"], destructive_tests=destructive_tests)


def _setup(handler, *, destructive_tests: bool = True, concurrency: int = 8):
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", own_object_ids={"coupons": "C-1"})
    session = store.create(A)
    harness = RaceHarness(PolicyEngine(_scope(destructive_tests=destructive_tests)))
    oracle = RaceConditionOracle(harness, BASE, concurrency=concurrency)
    return oracle, store, session


@pytest.mark.asyncio
async def test_confirmed_when_toctou_window_allows_multiple_success():
    oracle, store, session = _setup(_vulnerable_redeem_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers
    assert "8/8" in f.evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_properly_serialized():
    oracle, store, session = _setup(_safe_redeem_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.REJECTED
    assert not f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_resource_already_invalid():
    oracle, store, session = _setup(_already_used_handler())
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_id_missing():
    oracle, store, session = _setup(_vulnerable_redeem_handler())
    session.actor.own_object_ids.clear()
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_destructive_tests_disabled():
    oracle, store, session = _setup(_vulnerable_redeem_handler(), destructive_tests=False)
    f = await oracle.run(EP, session, resource_key="coupons", finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
