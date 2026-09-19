"""InjectionOracle — reflected XSS + error-based SQLi. DESIGN.md §14.

Sahte hedef, path'e enjekte edilen değeri yansıtır/hata verir. Kanıt gözlenendir.
"""
import html
import re
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


# --- NoSQL (operatör enjeksiyonu, error-based differential) ---

def nosql_vuln(request):
    val = _injected(request)
    if "$ne" in val or "$gt" in val:
        return httpx.Response(500, text="MongoError: unknown operator: $ne")
    return httpx.Response(200, json={"id": val})


def nosql_safe(request):
    return httpx.Response(200, json={"id": _injected(request)})


@pytest.mark.asyncio
async def test_nosql_confirmed_on_operator_error_differential():
    f = await _find(nosql_vuln, "nosqli")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.negative_control is True   # benign temizdi, operatör hata verdi


@pytest.mark.asyncio
async def test_nosql_rejected_without_error():
    f = await _find(nosql_safe, "nosqli")
    assert f.verdict == base.REJECTED


# --- SSTI (aritmetik değerlendirme kanıtı) ---

_MUL = re.compile(r"(\d{3,})\D{1,3}(\d{3,})")  # {{a*b}} / ${a*b} / #{a*b} içinden a,b


def ssti_vuln(request):
    m = _MUL.search(_injected(request))
    if m:
        product = int(m.group(1)) * int(m.group(2))
        return httpx.Response(200, text=f"<html>Sonuc: {product}</html>")  # ifade DEĞİL çarpım
    return httpx.Response(200, text="<html>yok</html>")


def ssti_safe(request):
    return httpx.Response(200, text=f"<html>Sonuc: {_injected(request)}</html>")  # ham yansıma


@pytest.mark.asyncio
async def test_ssti_confirmed_when_expression_evaluated():
    f = await _find(ssti_vuln, "ssti")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers


@pytest.mark.asyncio
async def test_ssti_rejected_when_only_reflected():
    f = await _find(ssti_safe, "ssti")
    assert f.verdict == base.REJECTED


# --- Path Traversal / LFI (sistem dosyası imzası) ---

def lfi_vuln(request):
    val = _injected(request).lower()
    if "passwd" in val or "win.ini" in val or "%2e" in val:
        return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon")
    return httpx.Response(200, text="ok")


def lfi_safe(request):
    return httpx.Response(200, text="ok")   # dosya sızıntısı yok


@pytest.mark.asyncio
async def test_traversal_confirmed_on_passwd_signature():
    f = await _find(lfi_vuln, "path_traversal")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.leaked_markers   # yalnızca imza etiketi (ham içerik değil)


@pytest.mark.asyncio
async def test_traversal_rejected_without_signature():
    f = await _find(lfi_safe, "path_traversal")
    assert f.verdict == base.REJECTED
