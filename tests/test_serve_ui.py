"""Web UI paneli ilk açılışta örnek scope üretir (madde 14, GOREVLER.md).

Kabul: `config/scope.yaml` yokken panel elle `cp` gerektirmeden kendi örnek scope'unu
oluşturur; örnek dosya da yoksa sessizce vazgeçer (503 uyarısı çağıran tarafta kalır)."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from scripts.serve_ui import _bootstrap_example_scope  # noqa: E402


def test_bootstrap_copies_example_when_scope_missing(tmp_path):
    example = tmp_path / "scope.example.yaml"
    example.write_text("target:\n  base_url: http://localhost:3000\n", encoding="utf-8")
    scope_path = tmp_path / "scope.yaml"

    _bootstrap_example_scope(scope_path)

    assert scope_path.exists()
    assert scope_path.read_text(encoding="utf-8") == example.read_text(encoding="utf-8")


def test_bootstrap_noop_when_example_also_missing(tmp_path):
    scope_path = tmp_path / "scope.yaml"

    _bootstrap_example_scope(scope_path)

    assert not scope_path.exists()


def test_bootstrap_does_not_overwrite_existing_scope(tmp_path):
    example = tmp_path / "scope.example.yaml"
    example.write_text("target:\n  base_url: http://example-target:3000\n", encoding="utf-8")
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text("target:\n  base_url: http://kullanicinin-kendi-hedefi:9000\n", encoding="utf-8")

    _bootstrap_example_scope(scope_path)   # var olsa da çağrılabilir — no-op olmalı

    assert "kullanicinin-kendi-hedefi" in scope_path.read_text(encoding="utf-8")
