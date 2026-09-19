"""Response-inspection dedektörleri (A3) — Open Redirect / CORS / güvenlik header'ları.

Sahte hedef, imza üretir/üretmez; kanıt gözlenendir (Location, ACAO, eksik header).
Network yok: httpx.MockTransport.
"""
import httpx
import pytest

from pentestai.detector.response_inspect import (
    CorsDetector, OpenRedirectDetector, SecurityHeadersDetector,
)
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

ENDPOINT = Endpoint(method="GET", path_template="/login", id_location="query")
BASE = "http://localhost:3000"


def _setup(handler, detector_cls, **kw):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, detector_cls(Replayer(PolicyEngine(scope)), BASE, **kw), s


async def _run(handler, detector_cls, **kw):
    store, det, s = _setup(handler, detector_cls, **kw)
    fs = await det.run(ENDPOINT, s)
    await store.aclose_all()
    return fs


# --- Open Redirect ---

def redirect_vuln(request):
    """Herhangi bir URL-benzeri query değerini Location'a yansıtan açık yönlendirme."""
    for _, v in request.url.params.multi_items():
        if v.startswith("http") or v.startswith("//"):
            return httpx.Response(302, headers={"location": v})
    return httpx.Response(200, text="ok")


def redirect_safe(request):
    """Parametre ne olursa olsun her zaman kendi origin'ine yönlendirir (güvenli)."""
    return httpx.Response(302, headers={"location": "/dashboard"})


@pytest.mark.asyncio
async def test_open_redirect_confirmed_when_location_reflects_attacker():
    fs = await _run(redirect_vuln, OpenRedirectDetector)
    f = next(x for x in fs if x.type == "open_redirect")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers   # hedef host imzası kaydedildi


@pytest.mark.asyncio
async def test_open_redirect_rejected_when_same_origin():
    fs = await _run(redirect_safe, OpenRedirectDetector)
    f = next(x for x in fs if x.type == "open_redirect")
    assert f.verdict == base.REJECTED


# --- CORS ---

def cors_credentialed(request):
    origin = request.headers.get("origin", "")
    return httpx.Response(200, headers={
        "access-control-allow-origin": origin,
        "access-control-allow-credentials": "true",
    }, json={"ok": True})


def cors_reflect_only(request):
    origin = request.headers.get("origin", "")
    return httpx.Response(200, headers={"access-control-allow-origin": origin}, json={"ok": True})


def cors_safe(request):
    return httpx.Response(200, headers={
        "access-control-allow-origin": "https://trusted.example",
    }, json={"ok": True})


@pytest.mark.asyncio
async def test_cors_confirmed_reflect_with_credentials():
    fs = await _run(cors_credentialed, CorsDetector)
    f = fs[0]
    assert f.type == "cors" and f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers


@pytest.mark.asyncio
async def test_cors_likely_reflect_without_credentials():
    fs = await _run(cors_reflect_only, CorsDetector)
    assert fs[0].verdict == base.LIKELY


@pytest.mark.asyncio
async def test_cors_rejected_when_fixed_origin():
    fs = await _run(cors_safe, CorsDetector)
    assert fs[0].verdict == base.REJECTED


# --- Güvenlik header'ları / Clickjacking ---

def headers_all_missing(request):
    return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>x</html>")


def headers_protected(request):
    return httpx.Response(200, headers={
        "content-type": "text/html",
        "x-frame-options": "DENY",
        "content-security-policy": "frame-ancestors 'none'",
        "strict-transport-security": "max-age=63072000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    }, text="<html>x</html>")


@pytest.mark.asyncio
async def test_clickjacking_confirmed_when_no_frame_protection():
    fs = await _run(headers_all_missing, SecurityHeadersDetector)
    cj = next(x for x in fs if x.type == "clickjacking")
    assert cj.verdict == base.CONFIRMED
    sh = next(x for x in fs if x.type == "security_headers")
    assert sh.verdict == base.LIKELY and sh.evidence.leaked_markers   # eksik header ADLARI


@pytest.mark.asyncio
async def test_clickjacking_rejected_and_headers_ok_when_protected():
    fs = await _run(headers_protected, SecurityHeadersDetector)
    cj = next(x for x in fs if x.type == "clickjacking")
    assert cj.verdict == base.REJECTED
    sh = next(x for x in fs if x.type == "security_headers")
    assert sh.verdict == base.REJECTED
