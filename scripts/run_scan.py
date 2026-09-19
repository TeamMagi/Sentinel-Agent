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

from pentestai.config import (  # noqa: E402
    load_actors, load_endpoints, load_llm_config, load_scope_config,
)
from pentestai.llm import (  # noqa: E402
    AnthropicLLMClient, GeminiLLMClient, LLMClient, OllamaLLMClient,
)
from pentestai.models import Endpoint  # noqa: E402
from pentestai.orchestrator import Pipeline  # noqa: E402
from pentestai.recon import HarRecon, OpenApiRecon  # noqa: E402
from pentestai.scanner import Scanner  # noqa: E402


def _drop_none(**kw) -> dict:
    """None değerleri eler → client constructor varsayılanları devreye girsin."""
    return {k: v for k, v in kw.items() if v is not None}


def _build_llm(args) -> LLMClient | None:
    """LLM client'ı config + CLI'dan kurar. CLI flag'i config'i override eder:
    --llm verilirse provider o olur; --llm-model verilirse model o olur."""
    cfg = load_llm_config(args.llm_config) if args.llm_config else {}
    provider = args.llm or cfg.get("provider") or "none"
    model = args.llm_model or cfg.get("model")
    temperature = cfg.get("temperature", 0.0)
    max_tokens = cfg.get("max_tokens", 2048)
    if provider == "gemini":
        return GeminiLLMClient(**_drop_none(model=model, temperature=temperature, max_tokens=max_tokens))
    if provider == "anthropic":
        return AnthropicLLMClient(**_drop_none(model=model, max_tokens=max_tokens))
    if provider == "ollama":
        return OllamaLLMClient(**_drop_none(
            model=model, host=cfg.get("host"), temperature=temperature, max_tokens=max_tokens,
            think=cfg.get("think")))
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
    llm = _build_llm(args)
    scanner = Scanner(target, scope, budget_cfg, out_dir=args.out, llm=llm)

    if args.dry_run:
        scanner.dry_run(actor_pairs, endpoints)
        return 0
    if args.mode == "passive":
        scanner.passive(endpoints)
        return 0

    pipeline = None
    agent = None
    try:
        sessions = await scanner.build_sessions(actor_pairs)
        if args.agent:
            from pentestai.orchestrator import AgenticOrchestrator, ParallelOrchestrator
            if not args.no_bootstrap:
                await scanner._bootstrap_ids(sessions, endpoints)
            by_name = {s.actor.name: s for s in sessions}
            by_name["anonymous"] = scanner.anon   # unauthorized_access için kimlik doğrulamasız oturum
            if args.scouts > 1:
                agent = ParallelOrchestrator(
                    scanner.executor, endpoints, llm=llm, planner=scanner.planner,
                    base_url=target, scouts=args.scouts, max_iterations=args.max_iter)
            else:
                agent = AgenticOrchestrator(
                    scanner.executor, endpoints, llm=llm, planner=scanner.planner,
                    base_url=target, max_iterations=args.max_iter)
            findings = (await agent.run(by_name)).findings
        elif args.loop:
            pipeline = Pipeline(scanner, endpoints, max_iterations=args.max_iter, enrich=args.enrich)
            findings = (await pipeline.run(sessions)).findings
        else:
            findings = await scanner.run_recon_scan(
                sessions, endpoints, bootstrap=not args.no_bootstrap, enrich=args.enrich,
                enumerate_more=args.enumerate, exposure_scan=not args.no_exposure_scan,
                info_leak_scan=not args.no_info_leak_scan,
                rate_limit_scan=not args.no_rate_limit_scan, cve_scan=not args.no_cve_scan,
                login_url=args.login_url, register_url=args.register_url)
    finally:
        await scanner.aclose()

    run_id, root = scanner.save(findings, args.mode,
                                trace=agent.trace if agent is not None else None)
    confirmed = sum(1 for f in findings if f.verdict == "CONFIRMED")
    if pipeline is not None:
        print(f"[loop] {len(pipeline.transitions)} durum geçişi · "
              f"{sum(1 for t in pipeline.transitions if t.startswith('EXPAND'))} pivot")
    if agent is not None:
        print(f"[agent] {len(agent.trace.steps)} aksiyon · {agent.trace.wall_sec}s")
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
    p.add_argument("--enumerate", action="store_true",
                   help="wordlist endpoint enümerasyonu + GraphQL introspection (recon genişletme)")
    p.add_argument("--no-exposure-scan", action="store_true",
                   help="A4 bilinen path/imza taramasını (.env/.git/backup/... + eski API sürümü) atla")
    p.add_argument("--no-info-leak-scan", action="store_true",
                   help="A5 bilgi sızıntısı taramasını (fingerprint + hata tetikleme) atla")
    p.add_argument("--no-rate-limit-scan", action="store_true",
                   help="B4 rate-limit/burst taramasını atla")
    p.add_argument("--no-cve-scan", action="store_true",
                   help="B7 sürüm→CVE eşleme + default-credentials taramasını atla")
    p.add_argument("--login-url",
                   help="B4/B7: brute-force/credential-stuffing + default-credentials taraması "
                        "için login endpoint'i")
    p.add_argument("--register-url", help="B4: zayıf şifre politikası taraması için kayıt endpoint'i")
    p.add_argument("--llm", choices=["none", "gemini", "anthropic", "ollama"], default=None,
                   help="hipotez/enrich LLM'i; --llm-config'i override eder "
                        "(env: GEMINI_API_KEY / ANTHROPIC_API_KEY / OLLAMA_HOST)")
    p.add_argument("--llm-config", help="LLM ayar dosyası (ör. config/llm.yaml); CLI flag'leri kazanır")
    p.add_argument("--llm-model", help="LLM model adı (ör. gemini-3.6-flash, qwen2.5:14b-instruct)")
    p.add_argument("--enrich", action="store_true",
                   help="bulguları LLM ile zenginleştir (severity/impact/remediation); --llm gerekir")
    p.add_argument("--loop", action="store_true",
                   help="self-improving orchestrator (CONFIRMED bulgudan pivot hipotezler türet)")
    p.add_argument("--agent", action="store_true",
                   help="agentic reasoning döngüsü (her turda sıradaki aksiyona karar verir; "
                        "--llm ile LLM, yoksa deterministik seçici)")
    p.add_argument("--scouts", type=int, default=1,
                   help="paralel scout sayısı (--agent ile; >1 → ParallelOrchestrator, tek bütçe/policy paylaşır)")
    p.add_argument("--max-iter", type=int, default=60, dest="max_iter",
                   help="--loop için maksimum hipotez iterasyonu")
    args = p.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
