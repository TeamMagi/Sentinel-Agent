# Development environment

> Moved out of the README on purpose. This is **not** required to try the tool — `make demo` works
> without reading any of it. This page is for contributors who want the same environment the team
> uses, and for anyone debugging a platform-specific problem.

## Quick start (no Docker)

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

That is enough to run the test suite and scan a target you control. Tests never touch the network.

## The team environment: WSL2 + Docker

On Windows the team standardises on **WSL2 + Docker Desktop (WSL2 backend)**. Four reasons:

1. **Reproducibility.** `docker compose` gives everyone — Windows, macOS, Linux — the same Python,
   Playwright and dependency versions. "It worked on my machine" stops being a category of bug.
2. **WSL2 is already underneath Docker.** So the *code* should live in the WSL2 Linux filesystem
   (`~/projects/...`) too. A bind-mount through `/mnt/c` is **very slow** and breaks file watching
   (`inotify`).
3. **Production-like behaviour.** Playwright/Chromium and async networking behave on Linux the way
   they behave in production.
4. **Team consistency.** Line-ending (CRLF/LF), path and file-permission differences disappear.

```bash
docker compose up -d juice-shop                    # calibration target → http://localhost:3000
docker compose run --rm sentinel bash              # dev shell with dependencies + Playwright
#   inside:  pytest -q   |   python -m scripts.run_scan --help
```

## Traps

- **OneDrive.** A repository inside a OneDrive-synced folder will corrupt `.git`, `.venv` and
  `node_modules`. Keep the repo **outside** OneDrive.
- **`python` vs `python3`.** Some systems have no `python` on `PATH`. The `Makefile` resolves an
  interpreter itself (`.venv/bin/python`, else `python3`); override it with
  `make test PYTHON=/usr/bin/python3.11`.
- **Juice Shop resets on restart.** Bringing the compose target up again wipes the accounts a
  previous run created. Re-run `python -m scripts.bootstrap_demo` afterwards.

## Configuration files

Real config is git-ignored; only `*.example.yaml` is tracked (see [CLAUDE.md](../CLAUDE.md) §8).

```bash
cp config/scope.example.yaml     config/scope.yaml
cp config/actors.example.yaml    config/actors.yaml
cp config/endpoints.example.yaml config/endpoints.yaml
```

Real credentials, tokens and `storageState` exports belong in `.secrets/` — never in a commit.

## Local LLM (optional)

The tool runs fully without an LLM (`--llm none` is the default). To use a local model so target
data never leaves the machine:

```bash
ollama pull qwen3.8:27b                      # or qwen2.5:14b-instruct (faster)
cp config/llm.example.yaml config/llm.yaml   # provider / model / host / think
```

`think: false` is recommended — reasoning mode is slower and the JSON schema constraint already
guarantees well-formed output. If you run Ollama inside Docker, point `host` at
`http://host.docker.internal:11434`.
