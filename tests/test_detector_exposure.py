"""ExposureScanner — bilinen path + imza taraması. A4 (Tier A).

SPA/catch-all yanlış-pozitif savunması: rastgele (bogus) path İLE imza-eşleşen path AYNI
cevabı verirse (gerçek catch-all) CONFIRMED üretilmez — yalnızca birbirinden AYIRT EDİLEBİLEN
ve İMZASI eşleşen path'ler raporlanır.
"""
import httpx
import pytest

from pentestai.detector.exposure import ExposureScanner
from pentestai.models import Actor, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def vulnerable_handler(request):
    path = request.url.path
    if path == "/.env":
        return httpx.Response(200, text="DB_PASSWORD=supersecret123\nAPI_KEY=abcdef\n")
    if path == "/uploads/":
        return httpx.Response(
            200, text="<html><title>Index of /uploads</title><body>Index of /uploads/</body></html>")
    return httpx.Response(404, text="not found")


def clean_handler(request):
    return httpx.Response(404, json={"error": "not found"})


def catchall_handler(request):
    # SPA/reverse-proxy catch-all: bogus dahil HERHANGİ bir path AYNI cevabı döner ve bu
    # cevap tesadüfen bir imza deseniyle eşleşir — CONFIRMED üretilMEMELİ.
    return httpx.Response(200, text="API_KEY=abc123\n")


def old_version_handler(request):
    path = request.url.path
    if path == "/api/v1/orders":
        return httpx.Response(200, json=[{"id": "1"}])   # eski sürüm hâlâ açık
    return httpx.Response(404, json={"error": "not found"})   # v2 + bogus dahil


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", role="user"))
    scanner = ExposureScanner(Replayer(PolicyEngine(scope)), BASE)
    return store, scanner, session


@pytest.mark.asyncio
async def test_confirms_env_and_directory_listing():
    store, scanner, session = _setup(vulnerable_handler)
    findings = await scanner.scan(session)
    types = {f.endpoint for f in findings}
    assert "/.env" in types and "/uploads/" in types
    assert all(f.verdict == "CONFIRMED" and f.type == "exposure" for f in findings)
    # ham sır evidence'a yazılmaz — yalnızca imza/kategori adı
    env_finding = next(f for f in findings if f.endpoint == "/.env")
    assert "supersecret123" not in env_finding.evidence.leaked_markers[0]
    assert "DB_PASSWORD" not in env_finding.evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_clean_app_yields_no_findings():
    store, scanner, session = _setup(clean_handler)
    findings = await scanner.scan(session)
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_catchall_spa_does_not_false_positive():
    store, scanner, session = _setup(catchall_handler)
    findings = await scanner.scan(session)
    assert findings == []   # bogus'la ayırt edilemiyor → CONFIRMED üretilmedi
    await store.aclose_all()


@pytest.mark.asyncio
async def test_old_api_version_detected():
    store, scanner, session = _setup(old_version_handler)
    endpoints = [Endpoint(method="GET", path_template="/api/v3/orders/{id}", id_param="id")]
    findings = await scanner.scan_old_api_versions(session, endpoints)
    assert len(findings) == 1
    assert findings[0].endpoint == "/api/v1/orders"
    assert findings[0].verdict == "CONFIRMED"
    await store.aclose_all()
