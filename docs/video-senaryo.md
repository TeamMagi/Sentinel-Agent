# Demo Video — Script (≤5 minutes)

> Task 11 draft. The recording (Task 12) follows this script; the timings are rough and are tuned
> in editing. Every step shown on screen is a real, working command — `make demo` is verified end to
> end as of today.

---

## 0. Title card (0:00–0:10) — ~10 s

On screen: project name + one-sentence description.

> **"Sentinel-Agent — an AI-assisted pentest agent that proves every finding."**

Presenter (voice-over): "Access-control bugs — IDOR, BOLA — are number one in the OWASP API Top 10.
But classic scanners can't find them, because they don't understand the question 'who owns what'. We
solved that with a system where the LLM reasons but the decision is never made by the LLM."

## 1. Problem (0:10–0:45) — ~35 s

On screen: the OWASP API Security Top 10 list (static image/slide), with #1 BOLA highlighted.

- What BOLA/IDOR is, a one-sentence example: "instead of /api/orders/42, try /api/orders/43 and see
  someone else's order."
- The problem: most "AI pentest agent" demos — the model attacks the target, then says "found it".
  No proof, no reproducibility, high false-positive risk.

## 2. Architecture (0:45–1:45) — ~60 s

On screen: the flow diagram from DESIGN.md (the visual version of the ASCII diagram in the README):

```
recon → hypothesis (LLM) → authorize(scope) → replay(actor) → oracle → finding → report
                                │                  │             │
                          security gate     single choke point   3 controls + leaked-marker
```

Narration:
- "Here the LLM only answers the question *what should we test* — it looks at the endpoint list and
  says 'this id parameter is a candidate for object-level authorization testing'."
- "But the LLM does not carry out the attack. Every request passes through a single point called the
  `Replayer` — identity injection, scope checks, rate limiting all happen there."
- "The `CONFIRMED` decision is always made by code: never without the positive control + negative
  control + baseline stability passing, and never without the victim's data **actually** appearing
  in the attacker's response."
- Brief screen: a snippet of `PolicyEngine.authorize` code (a scope-rejection example) — "even
  destructive requests are never sent unless the `destructive_tests` flag is on."

## 3. Live run (1:45–3:15) — ~90 s

Screen recording, a real terminal:

```bash
make demo
```

- The logs streaming in the terminal can be sped up (Juice Shop comes up, the calibration accounts
  are created, the scan runs).
- Highlight the output line: `[done] 6 findings · 1 CONFIRMED · runs/run-.../`
- Narration: "One command: it brings up the target, creates two test accounts, runs the scan. From
  zero to a proven finding in under two minutes."

## 4. Showing a finding in the dashboard (3:15–4:15) — ~60 s

Screen: `report.html` open in the browser.

- Findings list → click the `CONFIRMED` IDOR.
- What to highlight:
  - The positive/negative/baseline control badges (green checks).
  - The request/response diff — the line where the item from the victim's basket appears in the
    attacker's response (leaked-marker highlight).
  - The copy-pasteable repro-curl (specifically show the point where the token appears redacted —
    "the real token is never written to a log or report").
- One sentence: "This screen is the full evidence set that a jury or a security team can verify
  manually."

*(Optional, if time allows +15 s: show the `INCONCLUSIVE→CONFIRMED` transition of the state-changing
authz oracle added during the hackathon with the `destructive_tests` flag — "we test write/delete
authorization with the same discipline.")*

## 5. Impact (4:15–4:40) — ~25 s

- "Designed with a zero-false-positive goal: no proof, no `CONFIRMED`."
- "Even with the LLM fully turned off (`--llm none`), the tool keeps working deterministically and
  keeps producing proof — the AI only widens coverage and improves the prose; it is not the
  foundation of the security."

## 6. Tech stack + closing (4:40–5:00) — ~20 s

On screen: the `Built with` strip (Python 3.11 · httpx · Pydantic · pytest · Gemini/Ollama/Anthropic
· Docker · OWASP Juice Shop).

> Closing card: project name + repo/Devpost link.

---

## Recording notes

- Keep the terminal font size large (screen-recording readability).
- Do a "dry run" of `make demo` once beforehand (so the Docker image is cached), so the
  Playwright/Chromium download time doesn't show up in the recording — speed it up in editing if
  needed.
- Both the light and dark theme of the report page can be shown (a quick switch) — for visual
  variety.
- The audio can be recorded separately and synced in editing; the script text above can be read
  verbatim.
