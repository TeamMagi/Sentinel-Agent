"""Sentinel-Agent CLI (ince katman → Scanner orchestrator). DESIGN.md §10.12.

Örnek (endpoint dosyasıyla):
  python -m scripts.run_scan --scope config/scope.yaml --actors config/actors.yaml \
      --endpoints config/endpoints.yaml --mode active --out runs/
Örnek (OpenAPI spec'inden keşif):
  python -m scripts.run_scan --scope config/scope.yaml --actors config/actors.yaml \
      --openapi openapi.json --mode active
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
from pentestai.llm import AnthropicLLMClient, GeminiLLMClient, LLMClient  # noqa: E402
from pentestai.models import Endpoint  # noqa: E402
from pentestai.orchestrator import Pipeline  # noqa: E402
from pentestai.recon import HarRecon, OpenApiRecon  # noqa: E402
from pentestai.scanner import Scanner  # noqa: E402


def _build_llm(args) -> LLMClient | None:
    if args.llm == "gemini":
        return GeminiLLMClient(model=args.llm_model) if args.llm_model else GeminiLLMClient()
    if args.llm == "anthropic":
        return AnthropicLLMClient(model=args.llm_model) if args.llm_model else AnthropicLLMClient()
    return None


def _resolve_endpoints(args, allowed_hosts: list[str]) -> list[Endpoint]:
    if args.openapi:
        return OpenApiRecon().load(args.openapi)
    if args.har:
        return HarRecon().load(args.har, allowed_hosts=allowed_hosts)
    if args.endpoints:
        return [ep for ep, _ in load_endpoints(args.endpoints)]
    raise SystemExit("--openapi, --har veya --endpoints ver.")


async def _run(args) -> int:
    target, scope, budget_cfg = load_scope_config(args.scope)
    actor_pairs = load_actors(args.actors)
    endpoints = _resolve_endpoints(args, scope.allowed_hosts)
    scanner = Scanner(target, scope, budget_cfg, out_dir=args.out, llm=_build_llm(args))

    if args.dry_run:
        scanner.dry_run(actor_pairs, endpoints)
        return 0
    if args.mode == "passive":
        scanner.passive(endpoints)
        return 0

    pipeline = None
    try:
        sessions = await scanner.build_sessions(actor_pairs)
        if args.loop:
            pipeline = Pipeline(scanner, endpoints, max_iterations=args.max_iter, enrich=args.enrich)
            findings = (await pipeline.run(sessions)).findings
        else:
            findings = await scanner.run_recon_scan(
                sessions, endpoints, bootstrap=not args.no_bootstrap, enrich=args.enrich)
    finally:
        await scanner.aclose()

    run_id, root = scanner.save(findings, args.mode)
    confirmed = sum(1 for f in findings if f.verdict == "CONFIRMED")
    if pipeline is not None:
        print(f"[loop] {len(pipeline.transitions)} durum geçişi · "
              f"{sum(1 for t in pipeline.transitions if t.startswith('EXPAND'))} pivot")
    print(f"[done] {len(findings)} bulgu · {confirmed} CONFIRMED · {root}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="run_scan", description="Sentinel-Agent access-control scanner")
    p.add_argument("--scope", required=True)
    p.add_argument("--actors", required=True)
    p.add_argument("--endpoints", help="endpoint YAML (veya --openapi)")
    p.add_argument("--openapi", help="OpenAPI/Swagger spec (json/yaml)")
    p.add_argument("--har", help="browser HAR export (endpoint keşfi)")
    p.add_argument("--mode", choices=["passive", "active"], default="active")
    p.add_argument("--stage", type=int, default=1)
    p.add_argument("--out", default="runs/")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-bootstrap", action="store_true", help="per-actor crawl'ı atla")
    p.add_argument("--llm", choices=["none", "gemini", "anthropic"], default="none",
                   help="hipotez üretiminde LLM (anahtar env'den: GEMINI_API_KEY / ANTHROPIC_API_KEY)")
    p.add_argument("--llm-model", help="LLM model adı (ör. gemini-3.6-flash)")
    p.add_argument("--enrich", action="store_true",
                   help="bulguları LLM ile zenginleştir (severity/impact/remediation); --llm gerekir")
    p.add_argument("--loop", action="store_true",
                   help="self-improving orchestrator (CONFIRMED bulgudan pivot hipotezler türet)")
    p.add_argument("--max-iter", type=int, default=60, dest="max_iter",
                   help="--loop için maksimum hipotez iterasyonu")
    args = p.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
