# AI Usage — Transparency Statement

> This document satisfies the TLN Cybersecurity Challenge submission requirement to disclose
> **which AI tools were used and how**. It is intentionally the jury-facing English copy of the
> team's internal note.

Sentinel-Agent uses AI in **two distinct places**. We separate them deliberately, because the whole
security claim of the project rests on that separation: **the LLM reasons, a deterministic engine
proves.**

---

## 1. Build-time — Claude Code (Anthropic)

The codebase was developed with **Claude Code** (Anthropic's CLI agent) in a pair-programming
style. The AI's role during construction:

- Laying out the OOP + modular skeleton (`models → policy → net → oracle → auth → evidence →
  report → scanner`) and writing the `ABC`-based extension points (the `Oracle` / `AuthProvider` /
  `Reporter` subclasses).
- Generating the network-free unit tests (`httpx.MockTransport`) and their edge-case scenarios.
- Preparing documentation (DESIGN.md, README) and the static HTML report viewer.

All AI-generated code was reviewed by humans. The architecture, the security invariants and the
acceptance criteria belong to the team. **AI is an accelerator, not the decision-maker.**

## 2. Run-time — Gemini / Ollama (and optionally Anthropic)

During a scan, an LLM provider (**Google Gemini** cloud API, or a **local open model via Ollama**;
optionally Anthropic) steps in for **advisory reasoning only**:

- **Hypothesis generation:** from the endpoint inventory it proposes which vulnerability classes
  (IDOR/BFLA/excessive-data/injection) are worth trying (`ProposeHypothesis` — a typed action).
- **Finding enrichment:** it adds severity/impact/remediation prose to confirmed findings.
- **INCONCLUSIVE triage:** it writes a human-readable comment on uncertain results.

### Hard limits (what the LLM may **not** do)

This is the single most important design decision, and it is what makes the run-time AI safe:

1. **The LLM never touches the network.** It only proposes typed actions; all traffic passes
   through the deterministic `Replayer`.
2. **Code always decides `CONFIRMED`, never the LLM.** Evidence is produced only by a deterministic
   leaked-marker (the victim's private data appearing in the attacker's response).
3. **No verdict without controls** (positive/negative/stability) — the LLM cannot skip them.
4. **The scope gate is enforced on every request** (`PolicyEngine.authorize`); the LLM's
   suggestions are never trusted.

In short: the LLM answers *"what should we try, and what does the result mean?"* — **code** answers
*"is there actually a vulnerability?"* With the LLM fully disabled (`--llm none`) the tool still
runs deterministically and produces proven, evidence-backed findings — the AI only widens coverage
and improves the prose.

### Data privacy: with a local model (Ollama), target data never leaves the machine

When `--llm ollama` is selected, reasoning runs against a **local** model (Ollama) on your own
machine. In this mode the target data sent for hypothesis generation (the endpoint inventory, the
recon summary) **never goes to any cloud API** — the request stays on `localhost:11434` and no API
key is required. Cloud providers (Gemini/Anthropic) are used only when explicitly selected; the
default is `--llm none`. In every mode, **all traffic to the target** passes only through the
deterministic `Replayer` — the LLM never touches the network.

---

## Summary for the jury

| Question | Answer |
|---|---|
| Which AI tools were used to **build** the project? | Claude Code (Anthropic), under human review. |
| Which AI runs **inside** the tool at scan time? | Optional: Google Gemini, local Ollama, or Anthropic — **off by default** (`--llm none`). |
| Can the AI declare a vulnerability real? | **No.** Only deterministic code marks `CONFIRMED`. |
| Can the AI send traffic to the target? | **No.** All traffic goes through the `Replayer`. |
| Does the tool work with no AI at all? | **Yes.** `--llm none` still finds and proves findings. |
