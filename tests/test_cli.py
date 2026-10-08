"""pentestai.cli — R-D3 (GOREVLER.md, ROADMAP.md Eksen D): kurulabilir CLI + scan modları.

Scan modları bütçeyi (max_total_requests/max_wall_clock_sec) ve tarama genişliğini ölçekler;
erken durdurma (`BudgetTracker` kill-switch, DESIGN.md §10.11 — zaten var olan altyapı) `test_limits.py`
tarafında kanıtlı. Burada: mod → bütçe/genişlik eşlemesi + CLI'nin geriye dönük uyumluluğu.
"""
import httpx
import pytest

from pentestai.cli import SCAN_PROFILES, _apply_scan_profile, add_scan_arguments, main, scan_main
from pentestai.models import Actor, AuthState, BudgetConfig, CapturedRequest, Scope
from pentestai.net import BudgetTracker, Replayer, ResponseNormalizer, SessionStore
from pentestai.policy import PolicyEngine


def _args(scan_mode=None, **overrides):
    import argparse
    p = argparse.ArgumentParser()
    add_scan_arguments(p)
    argv = ["--scope", "x", "--actors", "y"]
    if scan_mode:
        argv += ["--scan-mode", scan_mode]
    for k, v in overrides.items():
        argv.append(f"--{k.replace('_', '-')}")
    return p.parse_args(argv)


def test_no_scan_mode_keeps_scope_yaml_budget_unchanged():
    budget = BudgetConfig(max_total_requests=2000, max_wall_clock_sec=900)
    out, breadth = _apply_scan_profile(budget, _args())
    assert out.max_total_requests == 2000 and out.max_wall_clock_sec == 900
    assert breadth == {"exposure_scan": True, "info_leak_scan": True, "rate_limit_scan": True,
                        "cve_scan": True, "enumerate_more": False}


def test_quick_mode_scales_down_budget_and_breadth():
    budget = BudgetConfig(max_total_requests=2000, max_wall_clock_sec=900)
    out, breadth = _apply_scan_profile(budget, _args(scan_mode="quick"))
    assert out.max_total_requests == 40 and out.max_wall_clock_sec == 300
    assert breadth["exposure_scan"] is False and breadth["cve_scan"] is False


def test_deep_mode_scales_up_budget_and_enables_enumeration():
    budget = BudgetConfig(max_total_requests=2000, max_wall_clock_sec=900)
    out, breadth = _apply_scan_profile(budget, _args(scan_mode="deep"))
    assert out.max_total_requests > 2000
    assert breadth["enumerate_more"] is True


def test_explicit_no_scan_flags_always_win_over_profile():
    # deep modu exposure_scan'i AÇAR ama kullanıcı --no-exposure-scan verdiyse KAPALI kalmalı.
    budget = BudgetConfig()
    out, breadth = _apply_scan_profile(budget, _args(scan_mode="deep", no_exposure_scan=True))
    assert breadth["exposure_scan"] is False


def test_enumerate_flag_wins_even_in_quick_mode():
    budget = BudgetConfig()
    out, breadth = _apply_scan_profile(budget, _args(scan_mode="quick", enumerate=True))
    assert breadth["enumerate_more"] is True   # quick varsayılanı False ama kullanıcı istedi


def test_all_profiles_present_and_ordered_by_size():
    assert set(SCAN_PROFILES) == {"quick", "standard", "deep"}
    sizes = [SCAN_PROFILES[m]["max_total_requests"] for m in ("quick", "standard", "deep")]
    assert sizes == sorted(sizes) and sizes[0] < sizes[-1]


def test_scan_main_rejects_unknown_scan_mode():
    with pytest.raises(SystemExit):
        scan_main(["--scope", "x", "--actors", "y", "--scan-mode", "ultra"])


def test_sentinel_main_requires_scan_subcommand():
    with pytest.raises(SystemExit):
        main([])   # subparsers required=True → argparse SystemExit(2)


@pytest.mark.asyncio
async def test_quick_mode_budget_actually_stops_early_end_to_end():
    """Bütçe SADECE mod'dan geliyor; scaled BudgetTracker gerçek bir Replayer'da kill-switch'i tetikliyor."""
    def handler(request):
        return httpx.Response(200, json={"ok": True})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    budget_cfg, _ = _apply_scan_profile(BudgetConfig(max_total_requests=2000), _args(scan_mode="quick"))
    tracker = BudgetTracker(budget_cfg.max_total_requests, budget_cfg.max_wall_clock_sec)
    replayer = Replayer(PolicyEngine(scope), normalizer=ResponseNormalizer(), budget=tracker)
    store = SessionStore(transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="a", auth=AuthState()))

    for _ in range(budget_cfg.max_total_requests):
        await replayer.replay(CapturedRequest(method="GET", url="http://localhost:3000/x"), s)
    with pytest.raises(Exception):   # BudgetExceeded — quick modun 40 istek eşiği aşıldı
        await replayer.replay(CapturedRequest(method="GET", url="http://localhost:3000/x"), s)
    await store.aclose_all()
