"""İleri server-side dedektörler (B8) — Prototype Pollution + Web Cache Poisoning.

Prototype pollution: sahte hedef __proto__ payload'ını "prototip" duruma merge eder ve
sonraki GET'lerde bu anahtarları döndürür (kalıtım simülasyonu). Cache poisoning: sahte hedef
path bazlı önbellek tutar; keyed olmayan header'ı yansıtıp önbelleğe alır. Network yok.
"""
import json

import httpx
import pytest

from pentestai.detector.server_side import CacheDetector, PrototypePollutionDetector
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="GET", path_template="/api/profile")


def _store(handler, *, destructive=False):
    methods = ["GET", "HEAD"] + (["POST", "PUT"] if destructive else [])
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=methods, destructive_tests=destructive)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, s, Replayer(PolicyEngine(scope))


# --- Prototype Pollution ---

def _proto_handler():
    proto: dict = {}

    def handler(request):
        if request.method in ("POST", "PUT"):
            try:
                data = json.loads(request.content.decode() or "{}")
            except ValueError:
                data = {}
            inner = data.get("__proto__") or data.get("constructor", {}).get("prototype", {})
            if isinstance(inner, dict):
                proto.update(inner)          # prototip kirlendi (kalıtım simülasyonu)
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(200, json={"user": "x", **proto})   # GET → kirli anahtarlar sızar
    return handler


@pytest.mark.asyncio
async def test_prototype_pollution_confirmed():
    store, s, replayer = _store(_proto_handler(), destructive=True)
    fs = await PrototypePollutionDetector(replayer, BASE).run(EP, s)
    await store.aclose_all()
    assert fs[0].type == "prototype_pollution" and fs[0].verdict == base.CONFIRMED
    assert fs[0].evidence.leaked_markers


@pytest.mark.asyncio
async def test_prototype_pollution_rejected_when_clean():
    store, s, replayer = _store(
        lambda r: httpx.Response(200, json={"user": "x"}), destructive=True)   # kirlenmez
    fs = await PrototypePollutionDetector(replayer, BASE).run(EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.REJECTED


@pytest.mark.asyncio
async def test_prototype_pollution_inconclusive_when_write_blocked():
    store, s, replayer = _store(_proto_handler(), destructive=False)   # POST bloklu
    fs = await PrototypePollutionDetector(replayer, BASE).run(EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.INCONCLUSIVE


# --- Web Cache Poisoning ---

def _cache_handler(*, cacheable: bool, reflect: bool):
    cache: dict = {}

    def handler(request):
        path = request.url.path
        if cacheable and path in cache:
            return httpx.Response(200, text=cache[path])   # önbellekten (kirli olabilir)
        xfh = request.headers.get("x-forwarded-host", "")
        body = f"<link href=https://{xfh}/a.css>" if (reflect and xfh) else "<link href=https://localhost/a.css>"
        if cacheable:
            cache[path] = body
        return httpx.Response(200, text=body)
    return handler


@pytest.mark.asyncio
async def test_cache_poisoning_confirmed():
    store, s, replayer = _store(_cache_handler(cacheable=True, reflect=True))
    fs = await CacheDetector(replayer, BASE).run(EP, s)
    await store.aclose_all()
    assert fs[0].type == "cache_poisoning" and fs[0].verdict == base.CONFIRMED


@pytest.mark.asyncio
async def test_cache_poisoning_likely_when_reflected_not_cached():
    store, s, replayer = _store(_cache_handler(cacheable=False, reflect=True))
    fs = await CacheDetector(replayer, BASE).run(EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.LIKELY


@pytest.mark.asyncio
async def test_cache_poisoning_rejected_when_no_reflection():
    store, s, replayer = _store(_cache_handler(cacheable=True, reflect=False))
    fs = await CacheDetector(replayer, BASE).run(EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.REJECTED
