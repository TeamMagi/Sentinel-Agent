"""pentestai.cli — R-D3 (GOREVLER.md, ROADMAP.md Eksen D): kurulabilir CLI + scan modları.

Scan modları bütçeyi (max_total_requests/max_wall_clock_sec) ve tarama genişliğini ölçekler;
erken durdurma (`BudgetTracker` kill-switch, DESIGN.md §10.11 — zaten var olan altyapı) `test_limits.py`
tarafında kanıtlı. Burada: mod → bütçe/genişlik eşlemesi + CLI'nin geriye dönük uyumluluğu.
"""
import argparse
import json
from pathlib import Path

import httpx
import pytest

from pentestai import cli
from pentestai.airgap import AirgapViolation
from pentestai.cli import (
    SCAN_PROFILES,
    _apply_scan_profile,
    _build_llm,
    _fail_exit,
    _resolve_endpoints,
    add_scan_arguments,
    main,
    scan_main,
)
from pentestai.llm import AnthropicLLMClient, GeminiLLMClient, OllamaLLMClient
from pentestai.models import (
    Actor,
    AuthState,
    BudgetConfig,
    CapturedRequest,
    Evidence,
    Finding,
    Scope,
)
from pentestai.net import BudgetExceeded, BudgetTracker, Replayer, ResponseNormalizer, SessionStore
from pentestai.policy import PolicyEngine


def _args(scan_mode=None, **overrides):
    import argparse
    p = argparse.ArgumentParser()
    add_scan_arguments(p)
    argv = ["--scope", "x", "--actors", "y"]
    if scan_mode:
        argv += ["--scan-mode", scan_mode]
    for k, _v in overrides.items():
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


def _llm_args(**over):
    base = {"llm": None, "llm_config": None, "llm_model": None, "offline": False}
    base.update(over)
    return argparse.Namespace(**base)


def test_build_llm_none_by_default():
    assert _build_llm(_llm_args()) is None


def test_build_llm_gemini():
    client = _build_llm(_llm_args(llm="gemini", llm_model="gemini-x"))
    assert isinstance(client, GeminiLLMClient)
    assert client.model == "gemini-x"


def test_build_llm_anthropic():
    client = _build_llm(_llm_args(llm="anthropic"))
    assert isinstance(client, AnthropicLLMClient)


def test_build_llm_ollama():
    client = _build_llm(_llm_args(llm="ollama", llm_model="qwen2.5:14b-instruct"))
    assert isinstance(client, OllamaLLMClient)
    assert client.model == "qwen2.5:14b-instruct"


def test_build_llm_offline_blocks_cloud_provider():
    with pytest.raises(AirgapViolation):
        _build_llm(_llm_args(llm="gemini", offline=True))


def test_build_llm_offline_allows_ollama():
    client = _build_llm(_llm_args(llm="ollama", offline=True))
    assert isinstance(client, OllamaLLMClient)


def test_build_llm_reads_from_config_file(tmp_path):
    cfg = tmp_path / "llm.yaml"
    cfg.write_text("llm:\n  provider: ollama\n  model: qwen3.8:27b\n", encoding="utf-8")
    client = _build_llm(_llm_args(llm_config=str(cfg)))
    assert isinstance(client, OllamaLLMClient)
    assert client.model == "qwen3.8:27b"


def test_build_llm_cli_flag_overrides_config_file(tmp_path):
    cfg = tmp_path / "llm.yaml"
    cfg.write_text("llm:\n  provider: ollama\n", encoding="utf-8")
    client = _build_llm(_llm_args(llm="anthropic", llm_config=str(cfg)))
    assert isinstance(client, AnthropicLLMClient)


# --------------------------- _fail_exit ---------------------------

def _finding(verdict="CONFIRMED", severity="High", baseline_status=None):
    return Finding(id="F-001", type="idor", endpoint="/x/{id}", verdict=verdict,
                   severity=severity, baseline_status=baseline_status, evidence=Evidence())


def test_fail_exit_none_threshold_always_zero():
    assert _fail_exit([_finding()], "none") == 0
    assert _fail_exit([_finding()], "") == 0


def test_fail_exit_unknown_threshold_returns_zero():
    assert _fail_exit([_finding()], "not-a-real-severity") == 0


def test_fail_exit_confirmed_at_or_above_threshold_triggers():
    assert _fail_exit([_finding(severity="High")], "medium") == 2
    assert _fail_exit([_finding(severity="Critical")], "high") == 2


def test_fail_exit_below_threshold_does_not_trigger():
    assert _fail_exit([_finding(severity="Low")], "high") == 0


def test_fail_exit_non_confirmed_does_not_trigger():
    assert _fail_exit([_finding(verdict="LIKELY", severity="Critical")], "low") == 0


def test_fail_exit_known_baseline_finding_is_exempt():
    assert _fail_exit([_finding(severity="Critical", baseline_status="known")], "low") == 0


# --------------------------- _resolve_endpoints ---------------------------

def test_resolve_endpoints_requires_a_source():
    args = argparse.Namespace(openapi=None, har=None, endpoints=None)
    with pytest.raises(SystemExit):
        _resolve_endpoints(args, ["localhost"])


def test_resolve_endpoints_from_yaml_file(tmp_path):
    p = tmp_path / "endpoints.yaml"
    p.write_text("endpoints:\n  - method: GET\n    path_template: /x/{id}\n", encoding="utf-8")
    args = argparse.Namespace(openapi=None, har=None, endpoints=str(p))
    eps = _resolve_endpoints(args, ["localhost"])
    assert eps[0].path_template == "/x/{id}"


def test_resolve_endpoints_uses_har_when_given(tmp_path):
    har = tmp_path / "session.har"
    har.write_text(json.dumps({"log": {"entries": [
        {"request": {"method": "GET", "url": "http://localhost:3000/api/orders/123"},
         "response": {"content": {"mimeType": "application/json"}}},
    ]}}), encoding="utf-8")
    args = argparse.Namespace(openapi=None, har=str(har), endpoints=None)
    eps = _resolve_endpoints(args, ["localhost"])
    assert any(ep.path_template == "/api/orders/{id}" for ep in eps)


def test_resolve_endpoints_prefers_openapi_when_given(tmp_path):
    spec = tmp_path / "spec.yaml"
    spec.write_text(
        "paths:\n  /items/{itemId}:\n    get: {}\n",
        encoding="utf-8",
    )
    # hem --openapi hem --endpoints verilse bile openapi öncelikli (kod sırası).
    endpoints_yaml = tmp_path / "endpoints.yaml"
    endpoints_yaml.write_text("endpoints:\n  - path_template: /should-not-be-used\n", encoding="utf-8")
    args = argparse.Namespace(openapi=str(spec), har=None, endpoints=str(endpoints_yaml))
    eps = _resolve_endpoints(args, ["localhost"])
    assert any(ep.path_template == "/items/{itemId}" for ep in eps)


# --------------------------- _run (CLI orkestrasyon katmanı, ağsız) ---------------------------
#
# Gerçek Scanner.build_sessions() DNS çözer + gerçek transport'a bağlanır (network gerektirir) —
# scan_manager.py'deki ScannerRunner/FakeRunner ayrımıyla AYNI mantıkla, burada da CLI glue'unu
# (dry-run/passive/agent/loop/standard dallanması, baseline, sarif, fail-on) izole etmek için
# Scanner'ın kendisi sahte bir çiftle DEĞİŞTİRİLİR — motorlar kendi test dosyalarında kanıtlı.

def _write_min_config(tmp_path: Path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "target:\n  base_url: http://localhost:3000\n"
        "scope:\n  allowed_hosts: [localhost]\n  allowed_ports: [3000]\n",
        encoding="utf-8",
    )
    actors = tmp_path / "actors.yaml"
    actors.write_text(
        "actors:\n"
        "  - name: user_A\n    auth: {type: static, headers: {Authorization: 'Bearer a'}}\n"
        "  - name: user_B\n    auth: {type: static, headers: {Authorization: 'Bearer b'}}\n",
        encoding="utf-8",
    )
    endpoints = tmp_path / "endpoints.yaml"
    endpoints.write_text("endpoints:\n  - method: GET\n    path_template: /x/{id}\n", encoding="utf-8")
    return scope, actors, endpoints


def _full_args(scope, actors, endpoints, **flags):
    p = argparse.ArgumentParser()
    add_scan_arguments(p)
    argv = ["--scope", str(scope), "--actors", str(actors), "--endpoints", str(endpoints)]
    for k, v in flags.items():
        flag = "--" + k.replace("_", "-")
        if v is True:
            argv.append(flag)
        elif v is False:
            continue
        else:
            argv += [flag, str(v)]
    return p.parse_args(argv)


def _confirmed_finding(severity="High"):
    return Finding(id="F-001", type="idor", endpoint="/x/{id}", verdict="CONFIRMED",
                   severity=severity, evidence=Evidence())


class _FakeSession:
    def __init__(self, name):
        self.actor = argparse.Namespace(name=name)


class _FakeScanner:
    """`_run()`'ın çağırdığı Scanner yüzeyinin ağsız test çifti (bkz. yukarıdaki not)."""

    instances: list = []

    def __init__(self, target, scope, budget_cfg, out_dir="runs/", *, llm=None, templates_dir=None, **kw):
        self.target = target
        self.out_dir = Path(out_dir)
        self.llm = llm
        self.anon = _FakeSession("anonymous")
        self.executor = object()
        self.planner = object()
        self.dry_run_called = False
        self.passive_called = False
        self.bootstrap_called = False
        self.saved = None
        self.closed = False
        self.findings_to_return = [_confirmed_finding()]
        _FakeScanner.instances.append(self)

    async def build_sessions(self, actor_pairs):
        return [_FakeSession(a.name) for a, _ in actor_pairs]

    async def _bootstrap_ids(self, sessions, endpoints):
        self.bootstrap_called = True

    def dry_run(self, actor_pairs, endpoints):
        self.dry_run_called = True

    def passive(self, endpoints):
        self.passive_called = True

    async def run_recon_scan(self, sessions, endpoints, **kw):
        return list(self.findings_to_return)

    def save(self, findings, mode, *, trace=None, sessions=None, anon_handles=False):
        self.saved = {"findings": findings, "mode": mode, "trace": trace, "anon_handles": anon_handles}
        root = self.out_dir / "run-fake"
        root.mkdir(parents=True, exist_ok=True)
        (root / "report.sarif").write_text("{}", encoding="utf-8")
        return "run-fake", root

    async def aclose(self):
        self.closed = True


class _FakeAgentTrace:
    def __init__(self):
        self.steps = ["s1", "s2"]
        self.wall_sec = 1.23


class _FakeAgentResult:
    def __init__(self, findings):
        self.findings = findings


class _FakeAgent:
    def __init__(self, *a, **kw):
        self.trace = _FakeAgentTrace()

    async def run(self, by_name):
        assert "anonymous" in by_name   # BFLA/unauthorized_access için anon oturum enjekte edilmeli
        return _FakeAgentResult([_confirmed_finding()])


class _FakePipeline:
    def __init__(self, *a, **kw):
        self.transitions = ["EXPAND:x", "STOP"]

    async def run(self, sessions):
        return _FakeAgentResult([_confirmed_finding()])


@pytest.mark.asyncio
async def test_run_dry_run_mode_calls_scanner_dry_run(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"), dry_run=True)
    rc = await cli._run(args)
    assert rc == 0
    fs = _FakeScanner.instances[-1]
    assert fs.dry_run_called is True
    assert fs.saved is None


@pytest.mark.asyncio
async def test_run_passive_mode_calls_scanner_passive(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"), mode="passive")
    rc = await cli._run(args)
    assert rc == 0
    assert _FakeScanner.instances[-1].passive_called is True


@pytest.mark.asyncio
async def test_run_standard_active_mode_saves_and_prints_done(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"))
    rc = await cli._run(args)
    assert rc == 0
    fs = _FakeScanner.instances[-1]
    assert fs.saved is not None and fs.saved["mode"] == "active"
    assert fs.closed is True
    out = capsys.readouterr().out
    assert "[done]" in out and "CONFIRMED" in out


@pytest.mark.asyncio
async def test_run_fail_on_triggers_exit_code_2(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"), fail_on="medium")
    rc = await cli._run(args)
    assert rc == 2


@pytest.mark.asyncio
async def test_run_sarif_flag_copies_report(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    dest = tmp_path / "out.sarif"
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"), sarif=str(dest))
    rc = await cli._run(args)
    assert rc == 0
    assert dest.exists()


@pytest.mark.asyncio
async def test_run_baseline_flag_marks_known_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(
        json.dumps([_confirmed_finding().model_dump(mode="json")]), encoding="utf-8")
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"), baseline=str(baseline_file))
    rc = await cli._run(args)
    assert rc == 0
    fs = _FakeScanner.instances[-1]
    assert fs.saved["findings"][0].baseline_status == "known"


@pytest.mark.asyncio
async def test_run_loop_mode_uses_pipeline(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    monkeypatch.setattr(cli, "Pipeline", _FakePipeline)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"), loop=True)
    rc = await cli._run(args)
    assert rc == 0
    assert "[loop]" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_run_agent_mode_uses_agentic_orchestrator(tmp_path, monkeypatch, capsys):
    import pentestai.orchestrator as orch_mod
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    monkeypatch.setattr(orch_mod, "AgenticOrchestrator", _FakeAgent)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"), agent=True)
    rc = await cli._run(args)
    assert rc == 0
    fs = _FakeScanner.instances[-1]
    assert fs.bootstrap_called is True   # --no-bootstrap verilmedi → varsayılan bootstrap çalışır
    assert "[agent]" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_run_agent_scouts_uses_parallel_orchestrator(tmp_path, monkeypatch):
    import pentestai.orchestrator as orch_mod
    monkeypatch.setattr(cli, "Scanner", _FakeScanner)
    monkeypatch.setattr(orch_mod, "ParallelOrchestrator", _FakeAgent)
    _FakeScanner.instances.clear()
    scope, actors, endpoints = _write_min_config(tmp_path)
    args = _full_args(scope, actors, endpoints, out=str(tmp_path / "out"), agent=True, scouts=3)
    rc = await cli._run(args)
    assert rc == 0


# --------------------------- scan_main / main (argparse → _run delegasyonu) ---------------------------

def test_scan_main_delegates_to_run_and_propagates_exit_code(monkeypatch, tmp_path):
    scope, actors, endpoints = _write_min_config(tmp_path)
    seen = {}

    async def fake_run(args):
        seen["args"] = args
        return 7

    monkeypatch.setattr(cli, "_run", fake_run)
    rc = scan_main(["--scope", str(scope), "--actors", str(actors), "--endpoints", str(endpoints)])
    assert rc == 7
    assert seen["args"].scope == str(scope)


def test_sentinel_main_scan_subcommand_delegates_to_run(monkeypatch, tmp_path):
    scope, actors, endpoints = _write_min_config(tmp_path)

    async def fake_run(args):
        return 3

    monkeypatch.setattr(cli, "_run", fake_run)
    rc = main(["scan", "--scope", str(scope), "--actors", str(actors), "--endpoints", str(endpoints)])
    assert rc == 3


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
    with pytest.raises(BudgetExceeded):   # quick modun 40 istek eşiği aşıldı
        await replayer.replay(CapturedRequest(method="GET", url="http://localhost:3000/x"), s)
    await store.aclose_all()
