"""Web UI katmanı — ağsız testler (CLAUDE.md §6).

Sahte `ScanRunner` enjekte edilerek gerçek ağa/Scanner'a çıkılmadan: istek→domain köprüsü,
çözüm önerisi kataloğu, iş yönetimi, HTTP yönlendirme, redaction değişmezi ve gerçek soket
uçtan-uca doğrulanır.
"""
from __future__ import annotations

import json
import threading
import time

import httpx

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
