"""Sentinel-Agent CLI (ince katman → Scanner). DESIGN.md §10.12.

Örnek:
  python -m scripts.run_scan --scope config/scope.yaml --actors config/actors.yaml \
      --endpoints config/endpoints.yaml --mode active --out runs/
  ... --dry-run   # istekleri authorize'dan geçir ama GÖNDERME (plan önizlemesi)
"""
from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys

# Kurulum yapılmadan da çalışsın diye src'yi path'e ekle.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.config import load_actors, load_endpoints, load_scope_config  # noqa: E402
from pentestai.scanner import Scanner  # noqa: E402


async def _run(args) -> int:
    target, scope, budget_cfg = load_scope_config(args.scope)
    actor_pairs = load_actors(args.actors)
    endpoints = load_endpoints(args.endpoints)
    scanner = Scanner(target, scope, budget_cfg, out_dir=args.out)

    if args.dry_run:
        scanner.dry_run(actor_pairs, endpoints)
        return 0
    if args.mode == "passive":
        scanner.passive(endpoints)
        return 0

    try:
        sessions = await scanner.build_sessions(actor_pairs)
        findings = await scanner.run_active(sessions, endpoints)
    finally:
        await scanner.aclose()

    run_id, root = scanner.save(findings, args.mode)
    confirmed = sum(1 for f in findings if f.verdict == "CONFIRMED")
    print(f"[done] {len(findings)} bulgu · {confirmed} CONFIRMED · {root}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="run_scan", description="Sentinel-Agent access-control scanner")
    p.add_argument("--scope", required=True)
    p.add_argument("--actors", required=True)
    p.add_argument("--endpoints", required=True)
    p.add_argument("--mode", choices=["passive", "active"], default="active")
    p.add_argument("--stage", type=int, default=0)
    p.add_argument("--out", default="runs/")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
