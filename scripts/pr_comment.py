"""findings.json → PR yorumu (Markdown). Yalnızca CI'da kullanılır — `pentestai`'yi import
ETMEZ (dast job'ının bu adımı hızlı ve bağımsız kalsın diye); yalnızca `report/baseline.py`'nin
findings.json'a yazdığı `baseline_status` alanını okur (aynı JSON şema, ayrı yorumlayıcı).

Kullanım: python scripts/pr_comment.py runs/run-<id>/findings.json -o pr_comment.md
"""
from __future__ import annotations

import argparse
import json

MARKER = "<!-- sentinel-agent-pr-comment -->"
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_REPORTABLE_VERDICTS = ("CONFIRMED", "LIKELY")


def _sort_key(f: dict) -> tuple:
    sev = _SEVERITY_ORDER.get((f.get("severity") or "").lower(), 4)
    return (sev, f.get("id") or "")


def render(findings: list[dict]) -> str:
    """`baseline_status == "known"` olanlar hariç (R-C1: "no silent drops" — bunlar rapordan
    ÇIKARILMAZ, yalnızca PR gürültüsü yapmaz) CONFIRMED/LIKELY bulguları özetler."""
    new = [
        f for f in findings
        if f.get("baseline_status") != "known" and f.get("verdict") in _REPORTABLE_VERDICTS
    ]
    lines = [MARKER, "### 🛡️ Sentinel-Agent — yetkilendirme taraması"]
    if not new:
        lines.append("Yeni (baseline'da olmayan) CONFIRMED/LIKELY bulgu yok.")
        return "\n".join(lines) + "\n"

    lines.append(f"**{len(new)} yeni bulgu** (baseline'da yok):")
    lines.append("")
    lines.append("| Verdict | Önem | Tür | Endpoint | Bulgu ID |")
    lines.append("|---|---|---|---|---|")
    for f in sorted(new, key=_sort_key):
        endpoint = f"{f.get('method', '')} {f.get('endpoint', '')}".strip()
        lines.append(
            f"| {f.get('verdict')} | {f.get('severity') or '-'} | {f.get('type')} | "
            f"`{endpoint}` | {f.get('id')} |"
        )
    lines.append("")
    lines.append("Ayrıntılı kanıt (evidence/repro_curl) için iş akışının `sentinel-run` "
                 "artefaktına bakın.")
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("findings_json")
    p.add_argument("-o", "--out", help="verilmezse stdout'a yazar")
    args = p.parse_args()

    with open(args.findings_json, encoding="utf-8") as fh:
        findings = json.load(fh)
    body = render(findings)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body)
    else:
        print(body, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
