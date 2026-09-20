"""Sürüm bütünlüğü doğrulayıcı (AS-7). Network YOK, model YOK, import YOK — yalnız stdlib.

Kabul: temiz depoda çıkış kodu 0; bozulmuş/tahrif edilmiş artefaktta non-zero.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from scripts import verify_release as vr


@pytest.fixture
def fake_repo(tmp_path, monkeypatch):
    """İzole sahte bir depo: bütünlük-kritik bir artefakt + manifest."""
    (tmp_path / "benchmarks").mkdir()
    (tmp_path / "templates").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "provenance").mkdir()
    (tmp_path / "benchmarks" / "x.expected.yaml").write_text("cases: []\n", encoding="utf-8")
    (tmp_path / "templates" / "t.yaml").write_text("id: t\n", encoding="utf-8")
    (tmp_path / "src" / "m.py").write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr(vr, "REPO", tmp_path)
    monkeypatch.setattr(vr, "MANIFEST", tmp_path / "provenance" / "file_manifest.json")
    vr.MANIFEST.write_text(json.dumps(vr.build_manifest(), indent=2), encoding="utf-8")
    return tmp_path


# ---------------- temiz durum ----------------

def test_clean_fake_repo_verifies(fake_repo):
    assert vr.verify(quiet=True) == 0


def test_real_repo_verifies_clean():
    # Depo gerçekten tutarlı mı (manifest güncel, linkler sağlam, kaynaklar ayrıştırılıyor).
    assert vr.main([]) == 0


# ---------------- tahrif / bozulma ----------------

def test_tampered_artifact_fails(fake_repo):
    (fake_repo / "benchmarks" / "x.expected.yaml").write_text("cases: [HACKED]\n", encoding="utf-8")
    errors, _ = vr.check_manifest()
    assert any("hash uyuşmuyor" in e for e in errors)
    assert vr.verify(quiet=True) == 1


def test_missing_artifact_fails(fake_repo):
    (fake_repo / "templates" / "t.yaml").unlink()
    errors, _ = vr.check_manifest()
    assert any("kayıp" in e for e in errors)
    assert vr.verify(quiet=True) == 1


def test_unlisted_new_artifact_fails(fake_repo):
    # Manifeste girmemiş yeni bir yer-gerçeği dosyası = bütünlük boşluğu.
    (fake_repo / "benchmarks" / "yeni.expected.yaml").write_text("cases: []\n", encoding="utf-8")
    errors, _ = vr.check_manifest()
    assert any("eklenmemiş" in e for e in errors)


def test_broken_python_is_reported_without_importing(fake_repo):
    # Bozuk (hatta kötücül) kaynak ÇALIŞTIRILMADAN yakalanır — yalnızca ast.parse.
    (fake_repo / "src" / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    errors, count = vr.check_python_parses()
    assert count >= 2 and any("ayrıştırılamadı" in e for e in errors)


def test_broken_json_is_reported(fake_repo):
    (fake_repo / "benchmarks" / "bozuk.json").write_text("{not json", encoding="utf-8")
    errors, _ = vr.check_json_valid()
    assert any("geçersiz JSON" in e for e in errors)


def test_broken_doc_link_is_reported(fake_repo):
    (fake_repo / "README.md").write_text("bkz [rapor](docs/yok.md)\n", encoding="utf-8")
    errors, _ = vr.check_doc_links()
    assert any("kırık yerel link" in e for e in errors)


def test_external_and_anchor_links_are_skipped(fake_repo):
    (fake_repo / "README.md").write_text(
        "[dış](https://example.com) [çapa](#bolum) [posta](mailto:a@b.c)\n", encoding="utf-8")
    errors, checked = vr.check_doc_links()
    assert errors == [] and checked == 0


def test_report_arithmetic_mismatch_is_reported(fake_repo):
    # counts ile metrics çelişiyor → rapor kendi kendisiyle tutarsız.
    (fake_repo / "benchmarks" / "benchmark_suite.json").write_text(json.dumps({
        "aggregate": {"counts": {"tp": 1, "fn": 1, "fp": 0, "tn": 0},
                      "metrics": {"precision": 1.0, "recall": 0.99, "fp_rate": 0.0}},
    }), encoding="utf-8")
    errors, _ = vr.check_report_arithmetic()
    assert any("rapor aritmetiği tutmuyor" in e and "recall" in e for e in errors)


def test_report_arithmetic_accepts_consistent_report(fake_repo):
    (fake_repo / "benchmarks" / "benchmark_suite.json").write_text(json.dumps({
        "aggregate": {"counts": {"tp": 1, "fn": 1, "fp": 0, "tn": 2},
                      "metrics": {"precision": 1.0, "recall": 0.5, "fp_rate": 0.0}},
    }), encoding="utf-8")
    errors, checked = vr.check_report_arithmetic()
    assert errors == [] and checked >= 1


# ---------------- manifest üretimi ----------------

def test_update_rewrites_manifest(fake_repo):
    (fake_repo / "benchmarks" / "yeni.expected.yaml").write_text("cases: []\n", encoding="utf-8")
    assert vr.main(["--update"]) == 0
    data = json.loads(vr.MANIFEST.read_text(encoding="utf-8"))
    assert "benchmarks/yeni.expected.yaml" in data["files"]
    assert data["algorithm"] == "sha256"
    assert vr.verify(quiet=True) == 0        # güncellemeden sonra temiz
