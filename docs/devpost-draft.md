# Devpost Submission Draft — Sentinel-Agent

> Draft for the TLN Cybersecurity Challenge (Sept 19–20, 2026) submission page. Copy each
> section into the matching Devpost field; adjust tone/length to fit the form's character limits.

---

## Project name

**Sentinel-Agent**

## Tagline

An AI-assisted pentest agent that finds broken access control — and proves it, deterministically.

## Inspiration

Broken Object Level Authorization (BOLA) has topped the **OWASP API Security Top 10** as
category **#1** for years, yet it's the class of bug traditional scanners (ZAP, Burp) are worst
at finding — it requires understanding *who owns what*, not just fuzzing inputs. At the same
time, most "AI pentest agent" demos we'd seen let an LLM freely hit a target and simply *assert*
a vulnerability exists, with no reproducible proof. We wanted both: an agent that reasons like a
pentester about *what* to test, and a result you can trust because a deterministic engine — not
the model — decided *whether* it's really exploitable.

## What it does

Sentinel-Agent authenticates as two (or more) real user accounts against a target API, then runs
a **differential test**: it takes an action as attacker A against an object owned by victim B,
and checks — deterministically — whether B's private data leaked into A's response, or whether
A's write/delete request actually mutated B's object. A finding is only marked `CONFIRMED` when:

- a **positive control** proves the attacker's own request path works,
- a **negative control** proves the server does distinguish valid from invalid targets,
- a **baseline-stability** check rules out flaky/non-deterministic responses, and
- a **leaked-marker** (victim-unique data appearing in the attacker's response, or a verified
  persistent mutation on the victim's object) is found.

No leaked marker, no `CONFIRMED` — full stop. Everything short of that is reported as `LIKELY`,
`REJECTED`, or `INCONCLUSIVE`, with the evidence attached either way.

An LLM (Gemini, a local Ollama model, or Anthropic) sits *above* this engine: it looks at the
discovered API surface and proposes which endpoints and vulnerability classes are worth testing
(IDOR/BOLA, BFLA, excessive data exposure, and — as of this hackathon — state-changing
write/delete authorization). It can also write a plain-English explanation of an `INCONCLUSIVE`
result. It never touches the network directly, and it never gets a vote on `CONFIRMED`.

Every finding ships with a redacted, copy-pasteable `curl` repro command and a static HTML report
(request/response diff, highlighted leaked marker, pass/fail on each control) that opens with a
double-click — no server required.

## How we built it

```
recon → hypothesis (LLM-assisted) → authorize(scope) → replay(actor) → oracle → finding → report
              │                          │                  │             │
        deterministic rules       security gate      single choke     differential test +
        + optional LLM             (no LLM here)      point (auth)    3 controls + leaked-marker
```

- **Python 3.11**, fully async (`httpx`), OOP with `ABC`-based extension points: new vulnerability
  class = new `Oracle` subclass, new auth method = new `AuthProvider` subclass — no existing code
  touched (Open/Closed).
- **`PolicyEngine`** is the one place that decides scope: allow-listed hosts/ports/paths/methods,
  DNS-pinning against rebind/SSRF, secret-in-URL blocking, and a `destructive_tests` flag that has
  to be explicitly on before any write/delete request is even sent.
- **`Replayer`** is the single choke point all traffic passes through — it strips and re-injects
  per-actor auth so two sessions can never leak into each other, and enforces a request budget /
  rate limit / retry policy.
- **Multi-provider LLM layer** (Gemini / Ollama / Anthropic) behind one interface, so the
  reasoning layer works with a free cloud model, a fully local model, or is switched off entirely
  (`--llm none`) — the deterministic engine still finds and proves `CONFIRMED` bugs on its own.
- **Self-improving orchestrator** (stage 2): a `CONFIRMED` finding can trigger new pivot
  hypotheses (e.g. "this object ID scheme leaked — check adjacent IDs") without a human back in
  the loop.
- Calibrated end-to-end against **OWASP Juice Shop** — a real `CONFIRMED` BOLA leak on
  `/rest/basket/{id}` and a real `CONFIRMED` state-changing BOLA (a user deleting another user's
  basket item via `DELETE /api/BasketItems/{id}`) were both reproduced live during development.

## Prior work — transparency statement

Sentinel-Agent's core engine (multi-actor sessions, the differential oracle, the policy/scope
gate, IDOR/BFLA/BOPLA/injection oracles, the LLM hypothesis layer, and the self-improving
orchestrator) was **designed and built before this hackathon**, as a personal project exploring
AI-assisted security tooling. What we built **during the Sept 19–20 hackathon window** on top of
that existing codebase:

- a new **state-changing (PUT/DELETE) authorization oracle** — object-level authz testing beyond
  read-only IDOR, gated by a dedicated `destructive_tests` policy flag, with its own network-free
  test suite and a live-validated `CONFIRMED` result against Juice Shop;
- the one-command demo flow (`make demo` — spins up the calibration target, bootstraps test
  accounts, runs a live scan, produces the HTML report) and the polished static report viewer;
- this submission itself (video, write-up, Devpost page).

We're flagging this explicitly per the challenge's prior-work disclosure rules — happy to walk
through git history for verification.

## Challenges we ran into

- Getting **negative controls** right against a real, imperfectly-behaved target: Juice Shop
  returns `500` instead of `404` for some non-existent write targets, which correctly makes our
  oracle refuse to guess (`INCONCLUSIVE`) rather than produce a false `CONFIRMED` — a good
  reminder that "the oracle abstained" is itself a correct, safe outcome, not a bug.
- Keeping the **LLM strictly advisory**: it's tempting to let a capable model just "try things,"
  but the whole trust story collapses if the model can assert a verdict. Every architectural
  decision was filtered through "does this let the LLM decide `CONFIRMED`?" — if yes, redesign.
- Cross-platform dev (Windows + Docker Desktop + WSL2) for a two-person team, without losing file
  watch performance or introducing CRLF/line-ending drift.

## Accomplishments we're proud of

- A real, reproducible `CONFIRMED` finding against a live target with **zero false positives**
  observed — every verdict is backed by evidence a reviewer can independently check.
- A genuinely pluggable oracle system: adding write/delete authorization testing during the
  hackathon required zero changes to existing oracles, the policy engine's core logic, or the
  scanner — just one new class and one new policy check.
- A one-command, judge-friendly demo that goes from a clean checkout to an evidenced finding in
  under two minutes.

## What we learned

Deterministic verification is the hard 20% that makes an "AI pentest agent" trustworthy instead
of a demo. The LLM layer is genuinely useful for triage and hypothesis breadth, but the value
proposition of the whole tool rests entirely on the part that has no model in the loop.

## What's next

- Broaden state-changing coverage (POST/create-time ownership, multi-step business-logic authz).
- Recon from live traffic capture (HAR/proxy) instead of hand-written or OpenAPI-only endpoints.
- Pluggable report sinks (SARIF, GitHub Security tab) for CI integration.

## Built with

Python 3.11 · httpx (async HTTP) · Pydantic · pytest / pytest-asyncio / respx · Google Gemini API
· Ollama (local LLM) · Anthropic API · Docker / Docker Compose · OWASP Juice Shop (calibration
target) · Playwright (storage-state auth capture) · static HTML/CSS/JS (report viewer, no
framework, no server)
