# Glossary of Terms

> AS-9 (GOREVLER.md — ops maturity). The **extended** version of the short glossary in DESIGN.md §2:
> it also defines terms that appear often in the codebase but are not defined in §2 (oracle/detector/
> marker/verdict/canary/holdout). The goal is terminological consistency — never using the same word
> in two different senses (e.g. "control" could mean both "positive/negative control" and "access
> control"; here they are disambiguated).

## Core concepts

| Term | Description |
|---|---|
| **Actor** | An identity/session used for testing (`user_A`, `user_B`, `admin`) — `models.Actor` |
| **Session** | The isolated `httpx.AsyncClient` bound to an `Actor` (`net/session_store.py`) — cookie/token are never shared |
| **Endpoint** | An HTTP path template to be tested (`method` + `path_template` + `id_param`) |
| **Hypothesis** | A candidate saying an endpoint should be tested for a given vulnerability type (deterministic or LLM-sourced) — not yet evidence |
| **Finding** | The result record an `Oracle`/`Detector` produces, carrying a `verdict` + `Evidence` |
| **Oracle** | The component that runs a differential test with two actors (victim/attacker) and makes a deterministic decision (`oracle/base.py`) — "an experiment, not a judgment" |
| **AgentOracle** | The agent-target counterpart of `Oracle` — works on an `AgentTrace` (tool-call trace) instead of an HTTP victim/attacker (AS-1) |
| **Detector** | A single-request/signature-based check component (`detector/base.py`) — not differential, a separate family from `Oracle` |
| **Replayer** | The single choke point through which all outbound traffic passes — auth injection + policy enforcement happen here (`net/replay.py`) |
| **PolicyEngine** | The pure, LLM-free scope/security gate (`policy/authorize.py`) — `authorize()` is enforced on every request |

## The verdict ladder

| Term | Description |
|---|---|
| **CONFIRMED** | Indisputable evidence (a leaked-marker or canary was seen) — produced **only by code**, never the LLM |
| **LIKELY** | A strong but not indisputable signal (e.g. a structural difference exists but no marker) |
| **REJECTED** | The controls passed but no vulnerability was observed — "tried, not found" |
| **INCONCLUSIVE** | The controls could not be completed (e.g. an unstable baseline) — no decision possible |

## Evidence / control terms

| Term | Description |
|---|---|
| **Leaked-marker** | Actor A's unique data appearing in actor B's response — conclusive proof of a leak |
| **Canary** | A random marker written into the victim's object before the scan starts, which the attacker could not know in advance (`oracle/canary.py`, R-A1) — by definition can never be public/shared |
| **Positive control** | The "does the vulnerability actually trigger under the right conditions?" check — proof that the oracle's own test works |
| **Negative control** | The "am I producing a false positive?" check — legitimate/authorized access must not yield CONFIRMED |
| **Baseline stability** | The response staying structurally stable across a repeated identical request — an unstable baseline invalidates the verdict |
| **Structural diff** | Comparing two responses by their TYPE/key skeleton (`oracle/base.py::_shape`), not their VALUES |
| **Confirmation margin** | How "comfortably" a CONFIRMED/LIKELY decision was made — how many independent markers leaked + divergence from the baseline (AS-6, `margin.py`). Does not change the verdict, only flags the ones that pass by a hair |
| **Low margin ("by a hair")** | A CONFIRMED/LIKELY whose `confirmation_margin` has not cleared the minimum threshold — can be fragile under environment drift (version/config change) |

## Calibration / benchmark terms

| Term | Description |
|---|---|
| **Precision / Recall / FP-rate** | Standard metrics measured against the labelled case set (`benchmarks/*.expected.yaml`) (`bench/`) |
| **Holdout target** | A target left completely "untouched" during calibration, used only for evaluation — measures generalization (out-of-overfit) (AS-5) |
| **Negative-twin** | The "hardened" (fixed) twin of the same application — the test data for the 0-FP regression gate (RK-10, `bench/twins.py`) |
| **Dedup / agreement** | The same root cause (CWE+endpoint+param) being confirmed from more than one source (different actor/oracle) (R-D2, `report/dedup.py`) |

## Agent-security terms (AS-1..AS-4)

| Term | Description |
|---|---|
| **AgentTrace** | The normalized tool-call trace of a task sent to an agent/MCP target (`models.AgentTrace`) |
| **ToolCall** | A single agent action — name, arguments, output, `source` (who triggered it), and `target_url` if any |
| **Untrusted content** | Attacker-controlled external content (web.search/email.read output) — NOT the user |
| **UNTRUSTED_TO_ACTION** | An instruction embedded in untrusted content triggering a privileged tool-call (AS-3) |
| **Taint (source-tracking)** | Recording, as evidence, which untrusted output fed which action |

---

For the short core glossary: [DESIGN.md §2](../DESIGN.md#2-glossary). For the agent-security context:
[DESIGN.md §10 (module contracts)](../DESIGN.md#10-module-contracts).
