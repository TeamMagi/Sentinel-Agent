"""Bulgu triyaj durumu + notu — store (W1) + web UI route handler'ları. Ağsız."""
from __future__ import annotations

import json

import pytest

from pentestai.report.triage_state import STATUSES, TriageStore
from pentestai.webui.app import WebApp
from pentestai.webui.scan_manager import ScanManager, ScanOutcome, ScanRunner


# --- Store birim testleri ---

def test_set_and_load_roundtrip(tmp_path):
    store = TriageStore(tmp_path)
    assert store.load() == {}
    entry = store.set("F-001", "investigating", "kurban PII sızıyor, doğrulandı")
    assert entry["status"] == "investigating" and entry["note"].startswith("kurban")
    assert store.load()["F-001"]["status"] == "investigating"


def test_invalid_status_raises(tmp_path):
    with pytest.raises(ValueError):
        TriageStore(tmp_path).set("F-001", "kapatıldı")     # STATUSES dışında


def test_all_statuses_accepted(tmp_path):
    store = TriageStore(tmp_path)
    for s in STATUSES:
        store.set("F-001", s)
        assert store.load()["F-001"]["status"] == s


def test_note_is_truncated(tmp_path):
    entry = TriageStore(tmp_path).set("F-001", "new", "x" * 9000)
    assert len(entry["note"]) <= 4000


# --- Web UI route handler'ları (HTTP'siz, doğrudan çağrı) ---

class _NullRunner(ScanRunner):
    def run(self, request, on_progress) -> ScanOutcome:
        return ScanOutcome(run_id="x", root="", findings=[])


def _app_with_run(tmp_path) -> tuple[WebApp, str]:
    (tmp_path / "run-1").mkdir()
    (tmp_path / "run-1" / "findings.json").write_text("[]", encoding="utf-8")
    app = WebApp(ScanManager(_NullRunner()), runs_dir=str(tmp_path), config_dir=str(tmp_path))
    return app, "run-1"


def test_get_triage_empty_then_set(tmp_path):
    app, run_id = _app_with_run(tmp_path)
    r = app._get_triage(run_id)
    assert r.status == 200 and json.loads(r.body)["triage"] == {}

    body = json.dumps({"finding_id": "F-001", "status": "resolved", "note": "düzeltildi"}).encode()
    r2 = app._set_triage(run_id, body)
    assert r2.status == 200 and json.loads(r2.body)["entry"]["status"] == "resolved"

    r3 = app._get_triage(run_id)
    assert json.loads(r3.body)["triage"]["F-001"]["status"] == "resolved"


def test_set_triage_invalid_status_400(tmp_path):
    app, run_id = _app_with_run(tmp_path)
    body = json.dumps({"finding_id": "F-001", "status": "bogus"}).encode()
    assert app._set_triage(run_id, body).status == 400


def test_triage_unknown_run_404(tmp_path):
    app, _ = _app_with_run(tmp_path)
    assert app._get_triage("does-not-exist").status == 404


def test_triage_run_id_traversal_blocked(tmp_path):
    app, _ = _app_with_run(tmp_path)
    assert app._get_triage("../../etc").status in (400, 404)   # traversal reddedilir
