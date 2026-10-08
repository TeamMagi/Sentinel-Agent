"""Web UI katmanı — ağsız testler (CLAUDE.md §6).

Sahte `ScanRunner` enjekte edilerek gerçek ağa/Scanner'a çıkılmadan: istek→domain köprüsü,
çözüm önerisi kataloğu, iş yönetimi, HTTP yönlendirme, redaction değişmezi ve gerçek soket
uçtan-uca doğrulanır.
"""
from __future__ import annotations

import json
import socket
import threading
import time

import httpx
import pytest

from pentestai.models import (
    BudgetConfig,
    CapturedRequest,
    Evidence,
    Finding,
    NormalizedResponse,
    Scope,
)
from pentestai.webui import (
    ActorSpec,
    AuthSpec,
    BudgetSpec,
    EndpointSpec,
    RemediationCatalog,
    RequestGuard,
    ScanBusyError,
    ScanManager,
    ScanOutcome,
    ScanRequest,
    ScanRunner,
    ScopeSpec,
    WebApp,
    WebServer,
    narrow_budget,
    narrow_scope,
)

_HOST = "127.0.0.1:8787"
_GET = {"host": _HOST}
_JSON = {"host": _HOST, "content-type": "application/json"}


# --------------------------- yardımcılar ---------------------------

def _finding_with_token() -> Finding:
    """Saldırı isteğinde ham Bearer token taşıyan CONFIRMED IDOR bulgusu (redaction testi için)."""
    ev = Evidence(
        baseline_request=CapturedRequest(method="GET", url="http://localhost:3000/rest/basket/1"),
        baseline_response=NormalizedResponse(status=200, body_text='{"id":1}'),
        attack_request=CapturedRequest(
            method="GET", url="http://localhost:3000/rest/basket/2",
            headers={"Authorization": "Bearer SECRETTOKEN123"}),
        attack_response=NormalizedResponse(status=200, body_text='{"id":2,"email":"victim@x.com"}'),
        positive_control=True, negative_control=True, baseline_stable=True,
        leaked_markers=["victim@x.com"],
    )
    return Finding(id="F-001", type="idor", endpoint="/rest/basket/{id}", method="GET",
                   parameter="id", verdict="CONFIRMED", confidence="high",
                   status="confirmed", evidence=ev)


class FakeRunner(ScanRunner):
    """Ağsız koşucu — canlı bulgu döndürür veya hata fırlatır."""

    def __init__(self, findings=None, raise_msg: str | None = None):
        self.findings = findings if findings is not None else [_finding_with_token()]
        self.raise_msg = raise_msg
        self.seen: ScanRequest | None = None

    def run(self, request: ScanRequest, on_progress) -> ScanOutcome:
        self.seen = request
        on_progress("sahte tarama çalışıyor…")
        if self.raise_msg:
            raise RuntimeError(self.raise_msg)
        return ScanOutcome(run_id="run-test-0001", root="runs/run-test-0001",
                           findings=list(self.findings))


def _valid_request(**over) -> ScanRequest:
    data = {
        "target": "http://localhost:3000",
        "scope": ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000]),
        "actors": [ActorSpec(name="user_A", auth=AuthSpec(
            login_url="http://localhost:3000/rest/user/login", email="a@x", password="p"))],
        "endpoints": [EndpointSpec(path_template="/rest/basket/{id}")],
    }
    data.update(over)
    return ScanRequest(**data)


def _wait(manager: ScanManager, job_id: str, timeout: float = 3.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        snap = manager.snapshot(job_id)
        if snap and snap.state in ("done", "error"):
            return
        time.sleep(0.02)
    raise AssertionError("iş zamanında tamamlanmadı")


# --------------------------- api_models ---------------------------

def test_authspec_to_cfg_token():
    cfg = AuthSpec(type="token", login_url="http://h/login", email="a@x", password="p").to_cfg()
    assert cfg["type"] == "token"
    assert cfg["credentials"] == {"email": "a@x", "password": "p"}
    assert cfg["token_location"]["kind"] == "bearer"


def test_authspec_to_cfg_storagestate_and_static():
    ss = AuthSpec(type="storagestate", storagestate_path="/x.json").to_cfg()
    assert ss == {"type": "storagestate", "storagestate_path": "/x.json"}
    st = AuthSpec(type="static", headers={"Authorization": "Bearer T"}).to_cfg()
    assert st["type"] == "static" and st["headers"]["Authorization"] == "Bearer T"


def test_actorspec_to_pair_and_redacted():
    spec = ActorSpec(name="u", own_object_ids={"basket": 6},
                     auth=AuthSpec(email="a@x", password="secret"))
    actor, cfg = spec.to_pair()
    assert actor.name == "u" and actor.own_object_ids == {"basket": "6"}
    assert cfg["credentials"]["password"] == "secret"
    red = spec.redacted()
    assert red.auth.password == "<REDACTED>"      # sır maskeli
    assert spec.auth.password == "secret"         # orijinal değişmedi


def test_scanrequest_validate_scope_and_actors():
    assert _valid_request().validate_request() is None
    # host scope dışında
    bad = _valid_request(scope=ScopeSpec(allowed_hosts=["example.com"], allowed_ports=[3000]))
    assert "scope.allowed_hosts" in (bad.validate_request() or "")
    # aktör yok
    noact = _valid_request(actors=[])
    assert "aktör" in (noact.validate_request() or "")
    # endpoint yok
    noep = _valid_request(endpoints=[])
    assert "endpoint" in (noep.validate_request() or "")


def test_scanrequest_redacted_hides_password():
    req = _valid_request()
    dumped = json.dumps(req.redacted(), ensure_ascii=False)
    assert "<REDACTED>" in dumped and '"p"' not in dumped


# --------------------------- remediation ---------------------------

def test_remediation_known_type():
    g = RemediationCatalog().guide_for({"type": "idor"})
    assert g["source"] == "catalog"
    assert g["steps"] and g["references"]
    assert "IDOR" in g["title"]


def test_remediation_unknown_type_falls_back():
    g = RemediationCatalog().guide_for({"type": "totally_new_thing"})
    assert g["type"] == "totally_new_thing"
    assert g["steps"]     # genel rehber boş değil


def test_remediation_llm_override():
    g = RemediationCatalog().guide_for({"type": "idor", "remediation": "Sahiplik kontrolü ekle."})
    assert g["source"] == "llm"
    assert g["fix_summary"] == "Sahiplik kontrolü ekle."
    assert g["steps"]     # adımlar yine katalogdan


# --------------------------- scan_manager ---------------------------

def test_manager_runs_job_to_done():
    mgr = ScanManager(FakeRunner())
    jid = mgr.start(_valid_request())
    _wait(mgr, jid)
    snap = mgr.snapshot(jid)
    assert snap.state == "done"
    assert snap.run_id == "run-test-0001"
    assert len(snap.findings) == 1


def test_manager_records_error():
    mgr = ScanManager(FakeRunner(raise_msg="patladı"))
    jid = mgr.start(_valid_request())
    _wait(mgr, jid)
    snap = mgr.snapshot(jid)
    assert snap.state == "error"
    assert "patladı" in snap.error


def test_manager_snapshot_redacts_request():
    mgr = ScanManager(FakeRunner())
    jid = mgr.start(_valid_request())
    snap = mgr.snapshot(jid)
    assert "<REDACTED>" in json.dumps(snap.request_redacted, ensure_ascii=False)


def test_manager_snapshot_unknown_job_returns_none():
    mgr = ScanManager(FakeRunner())
    assert mgr.snapshot("does-not-exist") is None


class _SlowRunner(ScanRunner):
    """`run()` bir Event'e kadar bloke olur — eşzamanlılık sınırını gerçek thread'lerle test eder."""

    def __init__(self):
        self.release = threading.Event()
        self.started = threading.Event()

    def run(self, request: ScanRequest, on_progress) -> ScanOutcome:
        self.started.set()
        self.release.wait(timeout=5)
        return ScanOutcome(run_id="run-slow", root="runs/run-slow", findings=[])


def test_manager_raises_scan_busy_error_at_real_concurrency_limit():
    runner = _SlowRunner()
    mgr = ScanManager(runner, max_running=1)
    mgr.start(_valid_request())
    assert runner.started.wait(timeout=5)   # ilk iş gerçekten "running" oldu
    try:
        with pytest.raises(ScanBusyError):
            mgr.start(_valid_request())
    finally:
        runner.release.set()


def test_manager_update_on_evicted_job_is_a_noop():
    # _update, iş evict edildikten SONRA (ör. arka planda hâlâ koşan eski bir thread'den)
    # çağrılırsa sessizce hiçbir şey yapmamalı — KeyError/crash yok.
    mgr = ScanManager(FakeRunner())
    mgr._update("hic-var-olmadi", state="running")   # sadece crash etmediğini doğrula


def test_manager_evicts_oldest_job_beyond_max_jobs():
    mgr = ScanManager(FakeRunner(), max_jobs=2)
    j1 = mgr.start(_valid_request())
    _wait(mgr, j1)
    j2 = mgr.start(_valid_request())
    _wait(mgr, j2)
    j3 = mgr.start(_valid_request())
    _wait(mgr, j3)
    assert mgr.snapshot(j1) is None          # en eski düştü
    assert mgr.snapshot(j2) is not None
    assert mgr.snapshot(j3) is not None


# --------------------------- WebApp (saf yönlendirme) ---------------------------

def _server_scope(**over) -> Scope:
    base = dict(
        allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
        allowed_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
        destructive_tests=True, external_network=True,
    )
    base.update(over)
    return Scope(**base)


def _app(tmp_path, runner=None, *, guard=None, server_scope=..., server_budget=None,
        secrets_dir=None):
    mgr = ScanManager(runner or FakeRunner())
    return WebApp(
        mgr, runs_dir=str(tmp_path), config_dir=str(tmp_path),
        guard=guard or RequestGuard([_HOST]),
        server_scope=_server_scope() if server_scope is ... else server_scope,
        server_budget=server_budget if server_budget is not None else BudgetConfig(),
        secrets_dir=str(secrets_dir) if secrets_dir is not None else str(tmp_path / ".secrets"),
    )


def test_app_serves_index(tmp_path):
    resp = _app(tmp_path).handle("GET", "/", {}, b"", _GET)
    assert resp.status == 200 and resp.content_type.startswith("text/html")
    assert b"Sentinel-Agent" in resp.body


def test_app_health(tmp_path):
    resp = _app(tmp_path).handle("GET", "/api/health", {}, b"", _GET)
    assert resp.status == 200 and json.loads(resp.body)["ok"] is True


def test_app_scan_rejects_invalid(tmp_path):
    body = json.dumps({"target": "http://evil.com", "scope": {"allowed_hosts": ["localhost"],
                      "allowed_ports": [3000]}, "actors": [], "endpoints": []}).encode()
    resp = _app(tmp_path).handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 400
    assert "error" in json.loads(resp.body)


def test_app_scan_flow_enriches_and_redacts(tmp_path):
    app = _app(tmp_path)
    body = json.dumps(_valid_request().model_dump(mode="json")).encode()
    start = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert start.status == 202
    jid = json.loads(start.body)["job_id"]
    _wait(app.manager, jid)
    status = app.handle("GET", "/api/scan/" + jid, {}, b"", _GET)
    payload = json.loads(status.body)
    assert payload["state"] == "done"
    f = payload["findings"][0]
    # çözüm önerisi eklenmiş
    assert f["remediation_guide"]["type"] == "idor"
    # redaction: ham token gitmedi
    raw = json.dumps(payload, ensure_ascii=False)
    assert "SECRETTOKEN123" not in raw
    assert "<REDACTED>" in raw


def test_app_runs_listing_and_traversal_guard(tmp_path):
    # sahte bir geçmiş koşum yaz
    run_dir = tmp_path / "run-20260101-000000"
    run_dir.mkdir()
    (run_dir / "findings.json").write_text(json.dumps([
        {"id": "F-001", "type": "idor", "endpoint": "/x", "verdict": "CONFIRMED"}]), encoding="utf-8")
    (run_dir / "config.snapshot.json").write_text(
        json.dumps({"target": "http://localhost:3000", "generated_at": "2026-01-01"}), encoding="utf-8")
    app = _app(tmp_path)
    runs = json.loads(app.handle("GET", "/api/runs", {}, b"", _GET).body)["runs"]
    assert runs and runs[0]["id"] == "run-20260101-000000"
    # açınca çözüm önerisi eklenir
    got = json.loads(app.handle("GET", "/api/runs/run-20260101-000000", {}, b"", _GET).body)
    assert got["findings"][0]["remediation_guide"]["type"] == "idor"
    # path traversal reddi
    bad = app.handle("GET", "/api/runs/..%2f..%2fetc", {}, b"", _GET)
    assert bad.status == 400


def test_app_defaults_never_leak_password(tmp_path):
    # config klasörü boş → gömülü varsayılan; parola alanı boş olmalı
    defaults = json.loads(_app(tmp_path).handle("GET", "/api/config/defaults", {}, b"", _GET).body)
    for actor in defaults.get("actors", []):
        assert actor["auth"].get("password", "") == ""


def test_app_handle_catches_unexpected_exception_and_hides_detail(tmp_path):
    # _route içindeki beklenmedik bir istisna 500'e düşmeli, ayrıntısı UI'ya SIZMAMALI (CLAUDE.md §5.5).
    app = _app(tmp_path)

    def boom(_job_id):
        raise RuntimeError("iç yığın izi burada olmamalı")

    app.manager.snapshot = boom
    resp = app.handle("GET", "/api/scan/whatever", {}, b"", _GET)
    assert resp.status == 500
    assert json.loads(resp.body) == {"error": "sunucu hatası"}
    assert b"ya\xc4\x9f\xc4\xb1n izi" not in resp.body


def test_app_scan_rejects_malformed_json_body(tmp_path):
    resp = _app(tmp_path).handle("POST", "/api/scan", {}, b"{not json", _JSON)
    assert resp.status == 400
    assert "JSON" in json.loads(resp.body)["error"]


def test_app_scan_rejects_missing_required_fields(tmp_path):
    resp = _app(tmp_path).handle("POST", "/api/scan", {}, b"{}", _JSON)
    assert resp.status == 400
    assert "geçersiz tarama isteği" in json.loads(resp.body)["error"]


def test_app_scan_status_unknown_job_404(tmp_path):
    resp = _app(tmp_path).handle("GET", "/api/scan/does-not-exist", {}, b"", _GET)
    assert resp.status == 404


def test_app_runs_listing_missing_dir_returns_empty(tmp_path):
    app = _app(tmp_path / "henuz-yok")
    assert json.loads(app.handle("GET", "/api/runs", {}, b"", _GET).body)["runs"] == []


def test_app_runs_listing_skips_invalid_entries(tmp_path):
    (tmp_path / "not-a-dir.txt").write_text("x", encoding="utf-8")
    (tmp_path / "run-no-findings").mkdir()
    broken = tmp_path / "run-broken"
    broken.mkdir()
    (broken / "findings.json").write_text("{bozuk json", encoding="utf-8")
    ok = tmp_path / "run-ok"
    ok.mkdir()
    (ok / "findings.json").write_text("[]", encoding="utf-8")

    app = _app(tmp_path)
    runs = json.loads(app.handle("GET", "/api/runs", {}, b"", _GET).body)["runs"]
    assert {r["id"] for r in runs} == {"run-ok"}


def test_app_get_run_dotdot_traversal_rejected(tmp_path):
    # ".." regex'i geçer (yalnızca nokta) ama runs_dir.resolve() dışına çıktığı için relative_to
    # ValueError fırlatır — traversal koruması ikinci katmanda yakalanır.
    resp = _app(tmp_path).handle("GET", "/api/runs/..", {}, b"", _GET)
    assert resp.status == 400


def test_app_get_run_not_found(tmp_path):
    resp = _app(tmp_path).handle("GET", "/api/runs/run-does-not-exist", {}, b"", _GET)
    assert resp.status == 404


def test_app_read_snapshot_ignores_corrupt_json(tmp_path):
    # config.snapshot.json bozuksa çökme yerine {} — /api/runs listelemesi yine de çalışmalı.
    run_dir = tmp_path / "run-corrupt-snap"
    run_dir.mkdir()
    (run_dir / "findings.json").write_text("[]", encoding="utf-8")
    (run_dir / "config.snapshot.json").write_text("{bozuk", encoding="utf-8")
    runs = json.loads(_app(tmp_path).handle("GET", "/api/runs", {}, b"", _GET).body)["runs"]
    assert runs[0]["id"] == "run-corrupt-snap"
    assert runs[0]["target"] == ""   # snapshot okunamadı → boş, crash yok


def test_app_defaults_reads_real_config_files(tmp_path):
    (tmp_path / "scope.yaml").write_text(
        "target:\n  base_url: http://real-target:9999\n"
        "scope:\n  allowed_hosts: [real-target]\n  allowed_ports: [9999]\n",
        encoding="utf-8",
    )
    (tmp_path / "actors.yaml").write_text(
        "actors:\n"
        "  - name: user_A\n"
        "    role: user\n"
        "    own_object_ids: {basket: 1}\n"
        "    auth:\n"
        "      type: token\n"
        "      login_url: http://real-target:9999/login\n"
        "      credentials: {email: a@x, password: secret}\n"
        "      token_location: {from: 'json:token'}\n",
        encoding="utf-8",
    )
    (tmp_path / "endpoints.yaml").write_text(
        "endpoints:\n  - method: GET\n    path_template: /rest/basket/{id}\n",
        encoding="utf-8",
    )
    defaults = json.loads(_app(tmp_path).handle("GET", "/api/config/defaults", {}, b"", _GET).body)
    assert defaults["target"] == "http://real-target:9999"
    assert defaults["scope"]["allowed_hosts"] == ["real-target"]
    actor = defaults["actors"][0]
    assert actor["name"] == "user_A"
    assert actor["auth"]["email"] == "a@x"
    assert actor["auth"]["password"] == ""   # sır asla UI'ya gitmez
    assert actor["auth"]["token_from"] == "json:token"
    ep = defaults["endpoints"][0]
    assert ep["path_template"] == "/rest/basket/{id}"
    assert ep["id_param"] == "id"   # verilmedi → varsayılana düştü


def test_app_load_yaml_ignores_unreadable_file(tmp_path):
    # scope.yaml bir DOSYA değil dizinse read_text() OSError (IsADirectoryError) fırlatır —
    # _load_yaml bunu yutup {} döner (crash yok), scope güvenli varsayılana düşer.
    (tmp_path / "scope.yaml").mkdir()
    (tmp_path / "actors.yaml").write_text("actors: []\n", encoding="utf-8")
    (tmp_path / "endpoints.yaml").write_text("endpoints: []\n", encoding="utf-8")
    defaults = json.loads(_app(tmp_path).handle("GET", "/api/config/defaults", {}, b"", _GET).body)
    assert defaults["scope"]["allowed_hosts"] == ["localhost"]


# --------------------------- RequestGuard (CSRF/DNS-rebinding) ---------------------------

def test_guard_rejects_unknown_host(tmp_path):
    resp = _app(tmp_path).handle("GET", "/api/health", {}, b"", {"host": "evil.example"})
    assert resp.status == 403


def test_guard_rejects_missing_host(tmp_path):
    resp = _app(tmp_path).handle("GET", "/api/health", {}, b"", {})
    assert resp.status == 403


def test_guard_rejects_non_json_post_content_type(tmp_path):
    # text/plain tarayıcının "simple request" saydığı tiplerden — preflight'sız gönderilebilir,
    # bu yüzden CSRF'e açık; yalnızca application/json kabul edilir.
    body = json.dumps(_valid_request().model_dump(mode="json")).encode()
    resp = _app(tmp_path).handle("POST", "/api/scan", {}, body, {"host": _HOST, "content-type": "text/plain"})
    assert resp.status == 415


def test_guard_rejects_mismatched_origin(tmp_path):
    body = json.dumps(_valid_request().model_dump(mode="json")).encode()
    headers = {**_JSON, "origin": "https://evil.example"}
    resp = _app(tmp_path).handle("POST", "/api/scan", {}, body, headers)
    assert resp.status == 403


def test_guard_allows_same_origin(tmp_path):
    body = json.dumps(_valid_request().model_dump(mode="json")).encode()
    headers = {**_JSON, "origin": f"http://{_HOST}"}
    resp = _app(tmp_path).handle("POST", "/api/scan", {}, body, headers)
    assert resp.status == 202


def test_guard_rejects_oversized_body(tmp_path):
    guard = RequestGuard([_HOST], max_body_bytes=10)
    resp = _app(tmp_path, guard=guard).handle("POST", "/api/scan", {}, b"x" * 11, _JSON)
    assert resp.status == 413


def test_guard_check_rejects_negative_content_length():
    # WebApp.handle() her zaman len(body)>=0 gönderir; bu dal yalnızca RequestGuard.check()'in
    # doğrudan çağrıldığı (server.py'nin ValueError sonrası length=-1 verdiği) durum için savunma.
    guard = RequestGuard([_HOST])
    denial = guard.check("GET", "/api/health", {"host": _HOST}, -1)
    assert denial == (400, "geçersiz Content-Length")


def test_guard_origin_without_hostname_does_not_match(tmp_path):
    # "null" origin (sandboxed iframe/redirect) veya şema-dışı bir Origin — hostname yok,
    # Host ile asla eşleşmemeli (_origin_matches_host False dönmeli, izin verilmemeli).
    body = json.dumps(_valid_request().model_dump(mode="json")).encode()
    headers = {**_JSON, "origin": "null"}
    resp = _app(tmp_path).handle("POST", "/api/scan", {}, body, headers)
    assert resp.status == 403


# --------------------------- scope kilidi (server-side scope) ---------------------------

def test_scan_denied_when_server_scope_unconfigured(tmp_path):
    app = _app(tmp_path, server_scope=None)
    body = json.dumps(_valid_request().model_dump(mode="json")).encode()
    resp = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 503


def test_scan_request_cannot_widen_server_scope(tmp_path):
    # sunucu yalnızca GET/HEAD'e izin veriyor; istek DELETE eklemeye çalışıyor.
    app = _app(tmp_path, server_scope=_server_scope(allowed_methods=["GET", "HEAD"]))
    req = _valid_request(scope=ScopeSpec(
        allowed_hosts=["localhost"], allowed_ports=[3000],
        allowed_methods=["GET", "HEAD", "DELETE"], destructive_tests=True))
    body = json.dumps(req.model_dump(mode="json")).encode()
    resp = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 400
    assert "allowed_methods" in json.loads(resp.body)["error"]


def test_scan_request_can_narrow_server_scope(tmp_path, runner=None):
    fake = FakeRunner()
    app = _app(tmp_path, runner=fake, server_scope=_server_scope())
    req = _valid_request(scope=ScopeSpec(
        allowed_hosts=["localhost"], allowed_ports=[3000], allowed_methods=["GET"],
        destructive_tests=False))
    body = json.dumps(req.model_dump(mode="json")).encode()
    resp = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 202
    _wait(app.manager, json.loads(resp.body)["job_id"])
    assert fake.seen.scope.allowed_methods == ["GET"]   # koşucuya giden, daraltılmış scope


def test_scan_request_cannot_exceed_server_budget(tmp_path):
    app = _app(tmp_path, server_budget=BudgetConfig(max_total_requests=100))
    req = _valid_request(budget={"max_total_requests": 5000})
    body = json.dumps(req.model_dump(mode="json")).encode()
    resp = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 400
    assert "budget" in json.loads(resp.body)["error"]


def test_narrow_scope_pure_function():
    server = _server_scope(allowed_hosts=["localhost", "127.0.0.1"])
    ok = narrow_scope(server, ScopeSpec(allowed_hosts=["localhost"], allowed_ports=[3000]))
    assert isinstance(ok, ScopeSpec)
    bad = narrow_scope(server, ScopeSpec(allowed_hosts=["evil.example"], allowed_ports=[3000]))
    assert isinstance(bad, str) and "allowed_hosts" in bad


def test_narrow_budget_pure_function():
    server = BudgetConfig(max_total_requests=100)
    ok = narrow_budget(server, BudgetSpec(max_total_requests=50))
    assert isinstance(ok, BudgetSpec)
    bad = narrow_budget(server, BudgetSpec(max_total_requests=500))
    assert isinstance(bad, str) and "max_total_requests" in bad


def test_narrow_budget_rejects_rps_and_wall_clock():
    server = BudgetConfig(max_total_requests=5000, max_rps_per_host=5.0, max_wall_clock_sec=300)
    bad_rps = narrow_budget(server, BudgetSpec(max_total_requests=100, max_rps_per_host=50.0,
                                                max_wall_clock_sec=60))
    assert isinstance(bad_rps, str) and "max_rps_per_host" in bad_rps
    bad_wall = narrow_budget(server, BudgetSpec(max_total_requests=100, max_rps_per_host=1.0,
                                                 max_wall_clock_sec=9999))
    assert isinstance(bad_wall, str) and "max_wall_clock_sec" in bad_wall


def test_narrow_scope_rejects_every_axis():
    server = _server_scope(
        allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/api"],
        allowed_methods=["GET"], destructive_tests=False, external_network=False,
        max_payload_bytes=1000,
    )

    def req(**over):
        base = dict(allowed_hosts=["localhost"], allowed_ports=[3000],
                    allowed_path_prefixes=["/api"], allowed_methods=["GET"])
        base.update(over)
        return narrow_scope(server, ScopeSpec(**base))

    assert "allowed_ports" in req(allowed_ports=[3000, 9999])
    assert "destructive_tests" in req(destructive_tests=True)
    assert "external_network" in req(external_network=True)
    assert "allowed_path_prefixes" in req(allowed_path_prefixes=["/other"])
    assert "max_payload_bytes" in req(max_payload_bytes=999_999)


def test_authspec_to_cfg_header_token_kind():
    cfg = AuthSpec(type="token", token_kind="header", token_header="X-Api-Key",
                   token_from="json:token").to_cfg()
    assert cfg["token_location"] == {"kind": "header", "from": "json:token", "header": "X-Api-Key"}


def test_actorspec_stringify_ids_passthrough_for_non_dict():
    # "before" validator'ı: dict-olmayan girdiyi olduğu gibi bırakır — dict geldiğinde stringify eder,
    # aksi halde pydantic'in kendi tip doğrulamasına bırakır.
    assert ActorSpec._stringify_ids("not-a-dict") == "not-a-dict"


def test_authspec_redacted_masks_headers_and_cookies():
    auth = AuthSpec(type="static", headers={"Authorization": "Bearer T"}, cookies={"session": "abc"})
    red = auth.redacted()
    assert red.headers == {"Authorization": "<REDACTED>"}
    assert red.cookies == {"session": "<REDACTED>"}
    assert auth.headers["Authorization"] == "Bearer T"   # orijinal değişmedi


def test_endpointspec_to_endpoint():
    ep = EndpointSpec(method="post", path_template="/x/{id}", id_param="id",
                       id_location="body").to_endpoint()
    assert ep.method == "POST" and ep.path_template == "/x/{id}" and ep.id_location == "body"


def test_scopespec_to_scope():
    scope = ScopeSpec(allowed_hosts=["h"], allowed_ports=[80], allowed_methods=["get"]).to_scope()
    assert scope.allowed_hosts == ["h"] and scope.allowed_methods == ["GET"]


def test_budgetspec_to_budget():
    budget = BudgetSpec(max_total_requests=10, max_rps_per_host=1.5, max_wall_clock_sec=60).to_budget()
    assert budget.max_total_requests == 10 and budget.max_rps_per_host == 1.5


def test_scanrequest_validate_empty_and_malformed_target():
    empty = _valid_request(target="")
    assert "hedef" in (empty.validate_request() or "").lower()
    malformed = _valid_request(target="not a url")
    assert "hedef" in (malformed.validate_request() or "").lower()


# --------------------------- storageState path kısıtı ---------------------------

def test_storagestate_path_must_stay_inside_secrets_dir(tmp_path):
    (tmp_path / ".secrets").mkdir()
    app = _app(tmp_path, secrets_dir=tmp_path / ".secrets")
    req = _valid_request(actors=[ActorSpec(
        name="user_A", auth=AuthSpec(type="storagestate", storagestate_path="../outside.json"))])
    body = json.dumps(req.model_dump(mode="json")).encode()
    resp = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 400
    assert "storagestate_path" in json.loads(resp.body)["error"]


def test_storagestate_path_rejects_non_json_shape(tmp_path):
    # regex'e hiç uymayan bir değer (.json ile bitmiyor) — relative_to'ya varmadan reddedilir.
    app = _app(tmp_path)
    req = _valid_request(actors=[ActorSpec(
        name="user_A", auth=AuthSpec(type="storagestate", storagestate_path="notjson.txt"))])
    body = json.dumps(req.model_dump(mode="json")).encode()
    resp = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 400
    assert "yalnızca .json" in json.loads(resp.body)["error"]


def test_storagestate_path_inside_secrets_dir_is_allowed(tmp_path):
    secrets = tmp_path / ".secrets"
    secrets.mkdir()
    fake = FakeRunner()
    app = _app(tmp_path, runner=fake, secrets_dir=secrets)
    req = _valid_request(actors=[ActorSpec(
        name="user_A", auth=AuthSpec(type="storagestate", storagestate_path="user_A.json"))])
    body = json.dumps(req.model_dump(mode="json")).encode()
    resp = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 202


# --------------------------- eşzamanlılık sınırı ---------------------------

def test_scan_returns_429_when_manager_is_busy(tmp_path):
    class BusyManager(ScanManager):
        def start(self, request):
            raise ScanBusyError("dolu")

    app = _app(tmp_path)
    app.manager = BusyManager(FakeRunner())
    body = json.dumps(_valid_request().model_dump(mode="json")).encode()
    resp = app.handle("POST", "/api/scan", {}, body, _JSON)
    assert resp.status == 429


# --------------------------- WebServer (gerçek soket, tek istek) ---------------------------

def test_server_end_to_end_health(tmp_path):
    app = _app(tmp_path)
    with WebServer(app, host="127.0.0.1", port=0) as srv:
        port = srv.bound_port
        app.guard = RequestGuard([f"127.0.0.1:{port}"])   # gerçek porta göre güncelle
        t = threading.Thread(target=srv.handle_request, daemon=True)
        t.start()
        r = httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=5)
        t.join(timeout=5)
    assert r.status_code == 200 and r.json()["ok"] is True


def test_server_end_to_end_post_and_head(tmp_path):
    # do_POST + do_HEAD dispatch — gerçek soket üzerinden, gövde sızmaz (HEAD).
    fake = FakeRunner()
    app = _app(tmp_path, runner=fake, server_scope=_server_scope())
    with WebServer(app, host="127.0.0.1", port=0) as srv:
        port = srv.bound_port
        app.guard = RequestGuard([f"127.0.0.1:{port}"])
        req = _valid_request(scope=ScopeSpec(
            allowed_hosts=["localhost"], allowed_ports=[3000], allowed_methods=["GET"],
            destructive_tests=False))
        body = json.dumps(req.model_dump(mode="json")).encode()

        t = threading.Thread(target=srv.handle_request, daemon=True)
        t.start()
        r_post = httpx.post(f"http://127.0.0.1:{port}/api/scan", content=body,
                             headers={"content-type": "application/json"}, timeout=5)
        t.join(timeout=5)

        t2 = threading.Thread(target=srv.handle_request, daemon=True)
        t2.start()
        r_head = httpx.head(f"http://127.0.0.1:{port}/api/health", timeout=5)
        t2.join(timeout=5)
    assert r_post.status_code == 202
    # _route yalnızca GET'i eşler (HEAD ayrı yönlendirilmez) → do_HEAD yine de 404 üretir,
    # ama _write hiçbir durumda HEAD gövdesi yazmaz (RFC 7231 §4.3.2) — bunu doğrula.
    assert r_head.status_code == 404 and r_head.content == b""


def test_server_rejects_oversized_content_length_header(tmp_path):
    # Gövdeyi belleğe okumadan ÖNCE Content-Length denetlenir — dev bir gövde hiç gönderilmese
    # bile (yalnızca başlık) sunucu erken 413 ile reddeder ve bağlantıyı kapatır.
    app = _app(tmp_path)
    with WebServer(app, host="127.0.0.1", port=0) as srv:
        port = srv.bound_port
        app.guard = RequestGuard([f"127.0.0.1:{port}"])
        t = threading.Thread(target=srv.handle_request, daemon=True)
        t.start()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            req = (
                f"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {app.max_body_bytes + 1}\r\n\r\n"
            ).encode()
            sock.sendall(req)
            resp = sock.recv(4096)
        t.join(timeout=5)
    assert b"413" in resp.split(b"\r\n", 1)[0]


def test_server_rejects_invalid_content_length_header(tmp_path):
    # Sayısal olmayan Content-Length → ValueError yakalanır, length=-1'e düşer → 400.
    app = _app(tmp_path)
    with WebServer(app, host="127.0.0.1", port=0) as srv:
        port = srv.bound_port
        app.guard = RequestGuard([f"127.0.0.1:{port}"])
        t = threading.Thread(target=srv.handle_request, daemon=True)
        t.start()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            req = (
                f"POST /api/scan HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                f"Content-Type: application/json\r\nContent-Length: not-a-number\r\n\r\n"
            ).encode()
            sock.sendall(req)
            resp = sock.recv(4096)
        t.join(timeout=5)
    assert b"400" in resp.split(b"\r\n", 1)[0]


def test_server_serve_forever_binds_serves_and_closes(tmp_path):
    # serve_forever gerçek bir bind+loop çalıştırır (context manager __enter__/__exit__'in dışı);
    # bir istek atıp shutdown() ile döngüyü durdurarak bind→serve→close yolunun tamamını geçer.
    app = _app(tmp_path)
    srv = WebServer(app, host="127.0.0.1", port=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        for _ in range(50):
            if srv._httpd is not None:
                break
            time.sleep(0.05)
        port = srv.bound_port
        app.guard = RequestGuard([f"127.0.0.1:{port}"])
        r = httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=5)
        assert r.status_code == 200
    finally:
        srv._httpd.shutdown()
        t.join(timeout=5)
    assert srv._httpd is None
