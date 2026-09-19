"""Sentinel-Agent CLI. DESIGN.md §10.12.

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

import yaml

# Kurulum yapılmadan da çalışsın diye src'yi path'e ekle.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.auth import build_auth_state  # noqa: E402
from pentestai.config import load_actors, load_scope_config  # noqa: E402
from pentestai.evidence import new_run_id, save_run  # noqa: E402
from pentestai.models import Endpoint  # noqa: E402
from pentestai.net.limits import BudgetTracker, RateLimiter  # noqa: E402
from pentestai.net.replay import Session  # noqa: E402
from pentestai.net.session_store import build_client  # noqa: E402
from pentestai.oracle.idor import BOGUS_ID, test_idor  # noqa: E402
from pentestai.policy.authorize import Deny, authorize  # noqa: E402
from pentestai.report import render_md  # noqa: E402


def _load_endpoints(path: str) -> list[tuple[Endpoint, str]]:
    data = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or {}
    out: list[tuple[Endpoint, str]] = []
    for e in data.get("endpoints", []):
        ep = Endpoint(
            method=e.get("method", "GET"),
            path_template=e["path_template"],
            id_param=e.get("id_param", "id"),
            id_location=e.get("id_location", "path"),
        )
        out.append((ep, e.get("resource_key", "id")))
    return out


def _dry_run(target, scope, actor_pairs, endpoints) -> int:
    print(f"[dry-run] target={target}  actors={[a.name for a, _ in actor_pairs]}")
    for ep, rkey in endpoints:
        for actor, _ in actor_pairs:
            oid = actor.own_object_ids.get(rkey, "1")
            req = ep.with_id(oid, target)
            decision = authorize(req, scope)
            tag = "DENY:" + decision.reason if isinstance(decision, Deny) else "ALLOW"
            print(f"  [{tag}] {req.method} {req.url}  (actor={actor.name})")
    return 0


async def _run(args) -> int:
    target, scope, budget_cfg = load_scope_config(args.scope)
    actor_pairs = load_actors(args.actors)
    endpoints = _load_endpoints(args.endpoints)

    if args.dry_run:
        return _dry_run(target, scope, actor_pairs, endpoints)

    if args.mode == "passive":
        print(f"[passive] target={target} — yalnızca listeleme, attack isteği yok.")
        for ep, rkey in endpoints:
            print(f"  endpoint: {ep.method} {ep.path_template} (resource={rkey})")
        return 0

    # --- active: auth acquisition + oracle ---
    budget = BudgetTracker(budget_cfg)
    limiter = RateLimiter(budget_cfg.max_rps_per_host)
    sessions: list[Session] = []
    for actor, auth_cfg in actor_pairs:
        actor.auth = await build_auth_state(auth_cfg)
        sessions.append(Session(actor, build_client(actor, base_url=target)))

    findings = []
    counter = 1
    try:
        for ep, rkey in endpoints:
            for victim in sessions:
                for attacker in sessions:
                    if victim.actor.name == attacker.actor.name:
                        continue
                    f = await test_idor(
                        ep, victim, attacker, scope, target,
                        resource_key=rkey, finding_id=f"F-{counter:03d}",
                        budget=budget, limiter=limiter,
                    )
                    findings.append(f)
                    counter += 1
    finally:
        for s in sessions:
            await s.client.aclose()

    run_id = new_run_id()
    report = render_md(findings, target=target)
    root = save_run(args.out, run_id, findings, report_md=report,
                    config_snapshot={"target": target, "mode": args.mode})
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
