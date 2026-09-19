"""InjectionOracle — reflected XSS + error-based SQLi. DESIGN.md §14.

Sahte hedef, path'e enjekte edilen değeri yansıtır/hata verir. Kanıt gözlenendir.
"""
import html
from urllib.parse import unquote

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.injection import InjectionOracle
from pentestai.policy import PolicyEngine

ENDPOINT = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
BASE = "http://localhost:3000"


def _injected(request):
    return unquote(str(request.url)).split("/api/orders/", 1)[-1]


def xss_vuln(request):       # ham yansıma, HTML
    return httpx.Response(200, headers={"content-type": "text/html"},
                         text=f"<html>Aranan: {_injected(request)}</html>")


def xss_safe(request):       # escape edilmiş
    return httpx.Response(200, headers={"content-type": "text/html"},
                         text=f"<html>Aranan: {html.escape(_injected(request))}</html>")


def sqli_vuln(request):      # tek tırnakta SQL hatası
    val = _injected(request)
    if "'" in val:
        return httpx.Response(500, text='SQLITE_ERROR: near "\'": syntax error')
    return httpx.Response(200, json={"id": val})


def sqli_safe(request):
    return httpx.Response(200, json={"id": _injected(request)})


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, InjectionOracle(Replayer(PolicyEngine(scope)), BASE), s


async def _find(handler, vtype):
    store, oracle, s = _setup(handler)
    fs = await oracle.test_param(ENDPOINT, s, param="id", location="path")
    await store.aclose_all()
    return next(f for f in fs if f.type == vtype)


@pytest.mark.asyncio
async def test_xss_confirmed_when_reflected_unescaped():
    f = await _find(xss_vuln, "xss")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers   # yansıyan marker kaydedildi


@pytest.mark.asyncio
async def test_xss_rejected_when_escaped():
    f = await _find(xss_safe, "xss")
    assert f.verdict == base.REJECTED


@pytest.mark.asyncio
async def test_sqli_confirmed_on_error_differential():
    f = await _find(sqli_vuln, "sqli")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.negative_control is True   # benign temizdi, tırnak hata verdi


@pytest.mark.asyncio
async def test_sqli_rejected_without_error():
    f = await _find(sqli_safe, "sqli")
    assert f.verdict == base.REJECTED
