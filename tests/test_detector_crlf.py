"""CRLF / yanıt başlığı enjeksiyonu dedektörü — response splitting.

Sahte hedef, parametre değerindeki CRLF'i süzer ya da süzmeden başlığa yansıtır.
Kanıt = enjekte edilen nonce-başlığının cevapta görünmesi. Network yok: httpx.MockTransport.
"""
import httpx
import pytest

from pentestai.detector.crlf import CrlfInjectionDetector
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

ENDPOINT = Endpoint(method="GET", path_template="/redirect", id_location="query")
BASE = "http://localhost:3000"


def _setup(handler, **kw):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, CrlfInjectionDetector(Replayer(PolicyEngine(scope)), BASE, **kw), s


async def _run(handler, **kw):
    store, det, s = _setup(handler, **kw)
    fs = await det.run(ENDPOINT, s)
    await store.aclose_all()
    return fs


def crlf_vuln(request):
    """Parametre değerindeki CRLF'i süzmeden: CRLF'ten sonraki kısmı gerçek yanıt başlığı yapar."""
    for _, v in request.url.params.multi_items():
        if "\r\n" in v:
            after = v.split("\r\n", 1)[1]        # "X-Crlf-<nonce>: injected<nonce>"
            name, _, val = after.partition(": ")
            return httpx.Response(200, headers={name: val}, text="ok")
    return httpx.Response(200, text="ok")


def crlf_safe(request):
    """CRLF'i süzen/yok sayan güvenli sunucu — değeri asla başlığa koymaz."""
    return httpx.Response(200, text="ok")


@pytest.mark.asyncio
async def test_crlf_confirmed_when_header_injected():
    fs = await _run(crlf_vuln)
    f = fs[0]
    assert f.type == "crlf_injection"
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers   # enjekte edilen başlık imzası kaydedildi


@pytest.mark.asyncio
async def test_crlf_rejected_when_stripped():
    fs = await _run(crlf_safe)
    assert fs[0].verdict == base.REJECTED


@pytest.mark.asyncio
async def test_crlf_rejected_does_not_false_positive_on_echo_body():
    # Değeri GÖVDEYE yansıtan ama başlığa koymayan sunucu FP üretmemeli (yalnızca başlık sayılır).
    def echo_body(request):
        v = next((val for _, val in request.url.params.multi_items()), "")
        return httpx.Response(200, text=f"you sent: {v}")
    fs = await _run(echo_body)
    assert fs[0].verdict == base.REJECTED
