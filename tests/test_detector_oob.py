"""OOB dedektörleri (B6) — SSRF · XXE · RFI + InMemoryOOBCollector.

In-band: sahte hedef payload URL'ini görünce metadata/dosya imzası yansıtır.
Blind: sahte hedef, hedefin geri-çağrısını simüle etmek için collector.record() çağırır.
Kanıt: in-band imza VEYA token'a düşen isabet. Network yok.
"""
from urllib.parse import unquote

import httpx
import pytest

from pentestai.detector.oob_probes import RfiDetector, SsrfDetector, XxeDetector
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oob import InMemoryOOBCollector
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
GET_EP = Endpoint(method="GET", path_template="/api/fetch")
POST_EP = Endpoint(method="POST", path_template="/api/import")


def _store(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, s, Replayer(PolicyEngine(scope))


# --- SSRF (in-band metadata) ---

def ssrf_inband(request):
    raw = unquote(str(request.url))
    if "169.254.169.254" in raw:   # hedef metadata'yı çekti ve yansıttı
        return httpx.Response(200, text='{"ami-id":"ami-123","instance-id":"i-abc"}')
    return httpx.Response(200, json={"ok": True})


@pytest.mark.asyncio
async def test_ssrf_confirmed_inband_metadata():
    store, s, replayer = _store(ssrf_inband)
    fs = await SsrfDetector(replayer, BASE).run(GET_EP, s)
    await store.aclose_all()
    assert fs[0].type == "ssrf" and fs[0].verdict == base.CONFIRMED


# --- SSRF (blind OOB) ---

@pytest.mark.asyncio
async def test_ssrf_confirmed_blind_oob():
    collector = InMemoryOOBCollector()

    def handler(request):
        raw = unquote(str(request.url))
        # Hedefin geri-çağrısını simüle et: payload URL'indeki token'a isabet kaydet.
        tok = _token_of(raw, collector)
        if tok:
            collector.record(tok)
        return httpx.Response(200, json={"ok": True})

    store, s, replayer = _store(handler)
    fs = await SsrfDetector(replayer, BASE, collector=collector).run(GET_EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.CONFIRMED
    assert fs[0].evidence.leaked_markers


@pytest.mark.asyncio
async def test_ssrf_rejected_when_no_fetch():
    collector = InMemoryOOBCollector()
    store, s, replayer = _store(lambda r: httpx.Response(200, json={"ok": True}))
    fs = await SsrfDetector(replayer, BASE, collector=collector).run(GET_EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.REJECTED


# --- RFI (blind OOB) ---

@pytest.mark.asyncio
async def test_rfi_confirmed_blind_oob():
    collector = InMemoryOOBCollector()

    def handler(request):
        tok = _token_of(unquote(str(request.url)), collector)
        if tok:
            collector.record(tok)
        return httpx.Response(200, text="ok")

    store, s, replayer = _store(handler)
    fs = await RfiDetector(replayer, BASE, collector=collector).run(GET_EP, s)
    await store.aclose_all()
    assert fs[0].type == "rfi" and fs[0].verdict == base.CONFIRMED


@pytest.mark.asyncio
async def test_rfi_inconclusive_without_collector():
    store, s, replayer = _store(lambda r: httpx.Response(200, text="ok"))
    fs = await RfiDetector(replayer, BASE).run(GET_EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.INCONCLUSIVE   # OOB olmadan kanıtlanamaz


# --- XXE (in-band file read) ---

def xxe_inband(request):
    body = (request.content or b"").decode("utf-8", "replace")
    if "file:///etc/passwd" in body:
        return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")
    return httpx.Response(200, text="ok")


@pytest.mark.asyncio
async def test_xxe_confirmed_inband_file_read():
    store, s, replayer = _store(xxe_inband)
    fs = await XxeDetector(replayer, BASE).run(POST_EP, s)
    await store.aclose_all()
    assert fs[0].type == "xxe" and fs[0].verdict == base.CONFIRMED


@pytest.mark.asyncio
async def test_xxe_blind_oob():
    collector = InMemoryOOBCollector()

    def handler(request):
        body = (request.content or b"").decode("utf-8", "replace")
        tok = _token_of(body, collector)
        if tok:
            collector.record(tok)
        return httpx.Response(200, text="ok")

    store, s, replayer = _store(handler)
    fs = await XxeDetector(replayer, BASE, collector=collector).run(POST_EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.CONFIRMED


@pytest.mark.asyncio
async def test_xxe_inconclusive_when_post_blocked():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_path_prefixes=["/"])   # destructive_tests=false → POST bloklu
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    s = store.create(Actor(name="user_A"))
    fs = await XxeDetector(Replayer(PolicyEngine(scope)), BASE).run(POST_EP, s)
    await store.aclose_all()
    assert fs[0].verdict == base.INCONCLUSIVE


# --- yardımcılar ---

def _token_of(text: str, collector: InMemoryOOBCollector) -> str | None:
    """Metinde collector.host geçen bir alt-alan token'ı bul (payload_url biçimi)."""
    marker = "." + collector.host
    for part in text.replace("/", " ").replace('"', " ").replace(">", " ").split():
        if marker in part:
            return part.split(marker)[0].split("//")[-1]
    return None
