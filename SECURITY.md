# Security Policy

Sentinel-Agent is a pentest tool that finds authorization (IDOR/BOLA + BFLA) vulnerabilities
**with proof**. If you find a security vulnerability **in the tool itself**, please follow the
process below.

## Scope

**In scope** — vulnerabilities in Sentinel-Agent ITSELF:

- Bypassing the scope gate (`PolicyEngine`) — e.g. getting a request out beyond `allowed_hosts`/
  `allowed_ports`, or defeating the DNS-pin/rebinding protection.
- Session/cookie leakage between two actors (cross-contamination).
- Redaction (`evidence/store.redact`) writing a token/JWT/PII raw into a log, evidence or report.
- CSRF/host-rebinding/path-traversal in the Web UI (`RequestGuard`, run-id/secrets-path checks).
- An LLM suggestion being able to make a request to the network directly, or produce `CONFIRMED`,
  without a code decision (without deterministic leaked-marker evidence).
- Dependency/local-execution vulnerabilities (e.g. command injection in `repro_curl` generation).

**Out of scope** — these are the *intended function* of Sentinel-Agent, not vulnerabilities:

- Sentinel-Agent finding a real IDOR/BFLA/etc. on a target the user is **authorized for and has
  configured for scanning** (this is the tool's purpose).
- Use of this tool against third-party targets you do not own or lack explicit written
  authorization for — this is entirely the user's responsibility (see [README §Ethics](README.md)
  and [CLAUDE.md §10](CLAUDE.md)).

## How to report

**Do NOT open a public issue** — a disclosed vulnerability can become exploitable before a fix
ships.

Instead, use GitHub's private reporting flow:
**Repo → Security tab → "Report a vulnerability"**
(https://github.com/TeamMagi/Sentinel-Agent/security/advisories/new)

Include in your report:

- The affected file/function (ideally `path:line`) and the commit/version.
- Steps to reproduce, or a minimal PoC (against a controlled environment such as
  `httpx.MockTransport`, not a real target — see [CLAUDE.md §6](CLAUDE.md)).
- The impact: which security invariant is violated (see [CLAUDE.md §5](CLAUDE.md)).

## Process

Because this is a volunteer-run project we cannot give a firm SLA; however:

- When we receive a report, we try to give a first response within a reasonable time (target:
  within a few business days).
- We ask that you do not disclose the finding until a fix is released (responsible disclosure).
- After the fix, if you wish, we will add a thank-you/credit to you as the reporter (unless you
  state otherwise).

## Supported versions

The project is not yet at a versioned (tagged-release) stage; security fixes are applied only to the
CURRENT state of the `main` branch.
