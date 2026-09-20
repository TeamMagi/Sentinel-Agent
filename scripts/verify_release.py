"""Sürüm bütünlüğü doğrulayıcı (AS-7). GOREVLER.md Dalga 6.

RK-9 tek bir BULGUYU imzalı kanıt-paketiyle mühürler; bu araç aynı disiplini **depo/sürüm
düzeyine** taşır: yayımlanan artefaktların hash manifesti + bağımsız tutarlılık kontrolleri.

**Ağsız, hedefsiz, yalnızca standart kütüphane.** Model yüklemez, tarama koşmaz, ağa çıkmaz,
kodu **import ETMEZ** (yalnızca `ast` ile ayrıştırır — bozuk/kötücül bir dosya çalıştırılmaz).
Bu sayede bir güvenlik ekibi, depoyu çalıştırmadan yayının bütünlüğünü doğrulayabilir.

Yapılan kontroller:
  1. **Manifest hash'leri** — `provenance/file_manifest.json`'daki her dosyanın SHA-256'sı tutuyor mu
     (bütünlük-kritik artefaktlar: `benchmarks/` yer gerçeği etiketleri + `templates/` dedektörleri).
     Yer gerçeği etiketlerinin sessizce değişmesi precision/recall iddialarımızı GEÇERSİZ kılar.
  2. **Python ayrıştırma** — `src/` + `scripts/` altındaki her modül `ast.parse` ile ayrıştırılır.
  3. **JSON geçerliliği** — `benchmarks/` + `provenance/` altındaki JSON'lar ayrıştırılır.
  4. **Rapor aritmetiği** — varsa `benchmark*.json` içindeki metrikler sayımlardan yeniden
     hesaplanıp karşılaştırılır (rapor kendi kendisiyle tutarlı mı).
  5. **Yerel doküman linkleri** — Markdown'daki göreli linkler gerçekten var olan dosyaları
     gösteriyor mu (kırık link = eksik/yanlış yayımlanmış artefakt işareti).

Kullanım:
  python -m scripts.verify_release            # doğrula (temiz → 0, bozuksa → 1)
  python -m scripts.verify_release --update   # manifesti yeniden üret (kasıtlı değişiklikten sonra)
  python -m scripts.verify_release --quiet    # yalnız özet
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = REPO / "provenance" / "file_manifest.json"

# Bütünlük-kritik artefaktlar: sessizce değişirlerse yayımlanmış iddialar geçersiz olur.
MANIFEST_GLOBS: tuple[str, ...] = ("benchmarks/*.yaml", "templates/*.yaml")

# Ayrıştırılacak (import EDİLMEYECEK) kaynak ağaçları.
PYTHON_GLOBS: tuple[str, ...] = ("src/**/*.py", "scripts/**/*.py")

# Geçerliliği kontrol edilecek JSON'lar.
JSON_GLOBS: tuple[str, ...] = ("benchmarks/**/*.json", "provenance/*.json")

# Linkleri çözülecek Markdown'lar.
MARKDOWN_GLOBS: tuple[str, ...] = ("*.md", "docs/*.md")

# [metin](hedef) — http(s)/mailto/çapa olmayan GÖRELİ linkler.
_MD_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _iter(globs: tuple[str, ...]) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for g in globs:
        out.extend(p for p in REPO.glob(g) if p.is_file())
    return sorted(set(out))


def _rel(p: pathlib.Path) -> str:
    return p.relative_to(REPO).as_posix()


def build_manifest() -> dict:
    """Bütünlük-kritik dosyalardan manifest üretir (deterministik: yola göre sıralı)."""
    files = {_rel(p): sha256_of(p) for p in _iter(MANIFEST_GLOBS)}
    return {
        "manifest_version": "1",
        "algorithm": "sha256",
        "description": ("Bütünlük-kritik yayın artefaktları. Yer gerçeği etiketleri (benchmarks/) "
                        "ve dedektör template'leri (templates/) sessizce değişirse precision/recall "
                        "iddiaları ve tarama davranışı geçersizleşir."),
        "files": dict(sorted(files.items())),
    }


# --- kontroller: her biri (hata listesi, kontrol sayısı) döner ---

def check_manifest() -> tuple[list[str], int]:
    if not MANIFEST.is_file():
        return [f"manifest yok: {_rel(MANIFEST)} (--update ile üret)"], 0
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except ValueError as e:
        return [f"manifest ayrıştırılamadı: {e}"], 0

    recorded: dict = data.get("files", {})
    errors: list[str] = []
    for rel, expected in sorted(recorded.items()):
        path = REPO / rel
        if not path.is_file():
            errors.append(f"manifestteki dosya kayıp: {rel}")
            continue
        actual = sha256_of(path)
        if actual != expected:
            errors.append(f"hash uyuşmuyor (tahrif?): {rel}")

    # Manifeste GİRMESİ gerekirken girmemiş yeni artefaktlar da bir bütünlük boşluğudur.
    for path in _iter(MANIFEST_GLOBS):
        if _rel(path) not in recorded:
            errors.append(f"manifeste eklenmemiş artefakt: {_rel(path)} (--update gerekir)")
    return errors, len(recorded)


def check_python_parses() -> tuple[list[str], int]:
    errors: list[str] = []
    files = _iter(PYTHON_GLOBS)
    for path in files:
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as e:
            errors.append(f"ayrıştırılamadı: {_rel(path)} ({type(e).__name__}: {e})")
    return errors, len(files)


def check_json_valid() -> tuple[list[str], int]:
    errors: list[str] = []
    files = _iter(JSON_GLOBS)
    for path in files:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except ValueError as e:
            errors.append(f"geçersiz JSON: {_rel(path)} ({e})")
    return errors, len(files)


def _metrics_consistent(block: dict, where: str) -> list[str]:
    """counts → metrics yeniden hesaplanıp raporlananla karşılaştırılır (tolerans 1e-3)."""
    counts, metrics = block.get("counts"), block.get("metrics")
    if not isinstance(counts, dict) or not isinstance(metrics, dict):
        return []
    tp, fn = counts.get("tp", 0), counts.get("fn", 0)
    fp, tn = counts.get("fp", 0), counts.get("tn", 0)
    expected = {
        "precision": tp / (tp + fp) if (tp + fp) else 1.0,
        "recall": tp / (tp + fn) if (tp + fn) else 1.0,
        "fp_rate": fp / (fp + tn) if (fp + tn) else 0.0,
    }
    errors = []
    for key, want in expected.items():
        got = metrics.get(key)
        if got is not None and abs(float(got) - want) > 1e-3:
            errors.append(f"rapor aritmetiği tutmuyor: {where}.{key}={got}, beklenen {want:.4f}")
    return errors


def check_report_arithmetic() -> tuple[list[str], int]:
    errors: list[str] = []
    files = [p for p in _iter(("benchmarks/**/*.json", "runs/**/benchmark*.json"))
             if p.name.startswith("benchmark")]
    checked = 0
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            continue    # geçersiz JSON zaten check_json_valid'de raporlanır
        for key in ("aggregate", "counts"):
            block = data if key == "counts" else data.get(key)
            if isinstance(block, dict):
                errors += _metrics_consistent(block, f"{_rel(path)}:{key}")
                checked += 1
        gen = data.get("generalization")
        if isinstance(gen, dict):
            for sub in ("calibrated", "holdout"):
                if isinstance(gen.get(sub), dict):
                    errors += _metrics_consistent(gen[sub], f"{_rel(path)}:generalization.{sub}")
                    checked += 1
    return errors, checked


def check_doc_links() -> tuple[list[str], int]:
    errors: list[str] = []
    checked = 0
    for path in _iter(MARKDOWN_GLOBS):
        text = path.read_text(encoding="utf-8")
        for target in _MD_LINK.findall(text):
            target = target.strip().split(" ", 1)[0]
            if (not target or target.startswith(("http://", "https://", "mailto:", "#"))
                    or target.startswith("<")):
                continue
            checked += 1
            resolved = (path.parent / target.split("#", 1)[0]).resolve()
            if not resolved.exists():
                errors.append(f"kırık yerel link: {_rel(path)} → {target}")
    return errors, checked


CHECKS = (
    ("manifest hash'leri", check_manifest),
    ("python ayrıştırma", check_python_parses),
    ("json geçerliliği", check_json_valid),
    ("rapor aritmetiği", check_report_arithmetic),
    ("doküman linkleri", check_doc_links),
)


def verify(quiet: bool = False) -> int:
    total_errors: list[str] = []
    for label, fn in CHECKS:
        errors, count = fn()
        total_errors += errors
        if not quiet:
            mark = "OK " if not errors else "HATA"
            print(f"[{mark}] {label}: {count} kontrol, {len(errors)} hata")
            for e in errors:
                print(f"       - {e}")
    if total_errors:
        print(f"[verify] BAŞARISIZ — {len(total_errors)} hata")
        return 1
    print("[verify] tüm kontroller geçti ✅ (ağsız, import'suz)")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="verify_release",
        description="Sürüm bütünlüğü doğrulayıcı (AS-7) — ağsız, yalnız stdlib")
    p.add_argument("--update", action="store_true",
                   help="manifesti yeniden üret (kasıtlı değişiklikten sonra)")
    p.add_argument("--quiet", action="store_true", help="yalnız özet yazdır")
    args = p.parse_args(argv)

    if args.update:
        manifest = build_manifest()
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
        print(f"[verify] manifest yazıldı: {_rel(MANIFEST)} ({len(manifest['files'])} dosya)")
        return 0
    return verify(quiet=args.quiet)


if __name__ == "__main__":
    raise SystemExit(main())
