"""Komşu-id enumerasyon IDOR oracle'ı (recall) — FP-güvenli. Ağsız (MockTransport)."""
from __future__ import annotations

import asyncio

import httpx

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import IdorEnumerationOracle
from pentestai.oracle.base import CONFIRMED, INCONCLUSIVE, LIKELY, REJECTED
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")


def _run(handler, *, own_id="100"):
    async def _go():
        store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
        A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
                  own_object_ids={"order": own_id})
        oracle = IdorEnumerationOracle(Replayer(PolicyEngine(
            Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"]))),
            BASE, span=3)
        try:
            return await oracle.run(EP, store.create(A), resource_key="order")
        finally:
            await store.aclose_all()
    return asyncio.run(_go())


def _oid(request) -> str:
    return request.url.path.rsplit("/", 1)[-1]


def test_likely_when_neighbor_leaks_foreign_pii():
    """Komşu id başkasının PII'sini döndürüyor → LIKELY (CONFIRMED DEĞİL: tek-aktör yetkisizliği
    kanıtlayamaz; CONFIRMED barı deterministik iki-aktör kanıtına ayrılmış kalır)."""
    def handler(request):
        oid = _oid(request)
        if oid == "100":
            return httpx.Response(200, json={"id": 100, "email": "me@t.local", "total": 5})
        if oid == "999999999":
            return httpx.Response(404, json={"error": "nf"})
        if oid == "101":                                          # komşu → BAŞKASININ PII'si
            return httpx.Response(200, json={"id": 101, "email": "victim@t.local", "total": 9})
        return httpx.Response(404, json={"error": "nf"})
    f = _run(handler)
    assert f.verdict == LIKELY and f.verdict != CONFIRMED
    assert any("victim@t.local" in m for m in f.evidence.leaked_markers)


def test_rejected_public_catalog_without_owner_private_fields():
    """Komşular owner-private ALAN taşımıyorsa (public ürün kataloğu) → CONFIRMED değil."""
    def handler(request):
        oid = _oid(request)
        if oid == "999999999":
            return httpx.Response(404)
        # her id → owner-private alan İÇERMEYEN public ürün (email/telefon yok)
        return httpx.Response(200, json={"id": int(oid), "name": f"Product {oid}", "price": 1.0})
    assert _run(handler).verdict == REJECTED


def test_rejected_when_neighbors_not_accessible():
    def handler(request):
        oid = _oid(request)
        if oid == "100":
            return httpx.Response(200, json={"id": 100, "email": "me@t.local"})
        return httpx.Response(403, json={"error": "forbidden"})   # komşular korumalı
    assert _run(handler).verdict == REJECTED


def test_inconclusive_when_id_not_sequential_int():
    f = _run(lambda r: httpx.Response(200, json={"email": "x@t"}), own_id="A-100-uuidish")
    assert f.verdict == INCONCLUSIVE


def test_inconclusive_when_bogus_not_distinguished():
    """Sunucu bogus id'yi ayırt etmiyorsa (her şeye aynı 200) negative control geçmez → INCONCLUSIVE."""
    f = _run(lambda r: httpx.Response(200, json={"email": "same@t.local", "id": 1}))
    assert f.verdict == INCONCLUSIVE


async def test_scanner_enumerate_ids_flag_finds_neighbor_pii():
    """Uçtan-uca: run_recon_scan(enumerate_ids=True) komşu-id PII sızıntısını LIKELY olarak bulur."""
    from pentestai.models import BudgetConfig
    from pentestai.scanner import Scanner

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))

    def handler(request):
        oid = _oid(request)
        if oid == "100":
            return httpx.Response(200, json={"id": 100, "email": "me@t.local"})
        if oid == "999999999":
            return httpx.Response(404)
        if oid == "101":
            return httpx.Response(200, json={"id": 101, "email": "victim@t.local"})
        return httpx.Response(404)

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    ep = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
    rk = ep.resource_key
    A = store.create(Actor(name="user_A", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={rk: "100"}))
    findings = await scanner.run_recon_scan(
        [A], [ep], bootstrap=False, exposure_scan=False, info_leak_scan=False,
        rate_limit_scan=False, cve_scan=False, template_scan=False, tls_scan=False,
        enumerate_ids=True)
    assert any(f.type == "idor" and f.verdict == "LIKELY" for f in findings)
    await store.aclose_all()


def test_own_neighbor_same_content_not_confirmed():
    """Komşu attacker'ın KENDİ verisiyle aynı içerik dönerse (kendi objesi) CONFIRMED olmaz."""
    def handler(request):
        oid = _oid(request)
        if oid == "999999999":
            return httpx.Response(404)
        return httpx.Response(200, json={"id": 100, "email": "me@t.local"})   # hep aynı (kendi) içerik
    # bogus 404 → negative geçer; ama komşular own ile AYNI içerik → atlanır → REJECTED
    assert _run(handler).verdict == REJECTED
