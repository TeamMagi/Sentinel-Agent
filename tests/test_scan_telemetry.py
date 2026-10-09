"""Canlı faz telemetrisi — scanner on_phase callback (V1). Ağsız (MockTransport)."""
from __future__ import annotations

import httpx

from pentestai.models import Actor, AuthState, BudgetConfig, Scope
from pentestai.net import SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"


async def test_on_phase_fires_per_phase_with_findings():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))

    def handler(request):
        return httpx.Response(404, json={})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer A"})))
    seen: list[tuple[str, int]] = []
    await scanner.run_recon_scan(
        [A], [], bootstrap=False, exposure_scan=True, info_leak_scan=False,
        rate_limit_scan=False, cve_scan=False, template_scan=False, tls_scan=False,
        on_phase=lambda name, fs: seen.append((name, len(fs))),
    )
    names = [n for n, _ in seen]
    assert "access-control (oracle)" in names     # ana faz her zaman emit eder
    assert "exposure" in names                    # açık olan detector fazı da emit etti
    await store.aclose_all()


async def test_on_phase_is_optional_backward_compatible():
    """on_phase verilmezse davranış değişmez (hata yok, tarama tamamlanır)."""
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    A = store.create(Actor(name="user_A", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer A"})))
    findings = await scanner.run_recon_scan(
        [A], [], bootstrap=False, exposure_scan=False, info_leak_scan=False,
        rate_limit_scan=False, cve_scan=False, template_scan=False, tls_scan=False)
    assert isinstance(findings, list)
    await store.aclose_all()
