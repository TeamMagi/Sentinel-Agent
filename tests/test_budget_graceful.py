"""Bütçe (kill-switch) nazik durma: BudgetExceeded tüm taramayı çökertmemeli.

Önceden run_scan'ın rate_limit fazındaki BudgetExceeded tüm taramayı traceback'le çökertiyordu.
Artık: (1) run_hypotheses hipotezler-arası nazikçe durur, (2) run_recon_scan faz aşımını yakalayıp
o ana dek toplanan bulgularla son-işlemeye devam eder. Network yok: httpx.MockTransport.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Hypothesis, Scope
from pentestai.net import BudgetTracker, SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


def test_budget_tracker_remaining_does_not_raise():
    b = BudgetTracker(max_total_requests=3, max_wall_clock_sec=900)
    assert b.remaining == 3
    b.check_and_count()
    b.check_and_count()
    assert b.remaining == 1
    b.check_and_count()
    assert b.remaining == 0          # bitti ama raise ETMEDİ (proaktif kontrol için)


def _authed_handler(request):
    if "authorization" in {k.lower() for k in request.headers}:
        return httpx.Response(200, json={"id": "1"})
    return httpx.Response(401, json={"error": "auth required"})


@pytest.mark.asyncio
async def test_run_hypotheses_stops_gracefully_when_budget_low():
    # Küçük bütçe: guard (remaining < 12) ilk birkaç hipotezden sonra YENİ hipoteze başlamaz.
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_total_requests=13, max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_authed_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "1"}))
    scanner.anon = store.create(Actor(name="anonymous", role="anonymous"))

    hyps = [Hypothesis(type="unauthorized_access",
                       endpoint=Endpoint(method="GET", path_template=f"/api/orders{i}/{{id}}", id_param="id"),
                       rationale="r") for i in range(8)]
    # Çökmemeli (BudgetExceeded raise olmamalı) ve kısmi sonuç dönmeli (hepsi değil).
    findings = await scanner.run_hypotheses([A], hyps)
    assert isinstance(findings, list)
    assert len(findings) < len(hyps)          # bütçe guard'ı erken durdurdu
    await store.aclose_all()


@pytest.mark.asyncio
async def test_run_recon_scan_survives_budget_exhaustion():
    # Çok küçük bütçe + tüm fazlar açık: eskiden rate_limit fazında çökerdi; artık kısmi sonuçla döner.
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_methods=["GET", "HEAD"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_total_requests=20, max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_authed_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "1"}))
    endpoints = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]

    # Hiç exception fırlatmadan dönmeli (çökme yok); sonuç bir liste.
    findings = await scanner.run_recon_scan([A], endpoints)
    assert isinstance(findings, list)
    await store.aclose_all()
