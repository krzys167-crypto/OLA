# OLA DI-OS

OLA is a decision-intelligence runtime that executes agent tasks and records every step in a **tamper-evident, append-only evidence chain**. A task only reaches `VERIFIED` when its evidence re-computes cleanly; anything unknown or unverifiable fails closed.

> **Status: pre-production.** Stripe is wired in **sandbox/test mode only**. Revenue in production is **not proven** (`PRODUCTION_REVENUE=NOT_PROVEN` is printed by CI on purpose). A development branch is never production evidence — see [SECURITY.md](SECURITY.md).

## What it does

| Component | Role |
|---|---|
| Six-agent runtime (`/agent-run`) | `codeact → react → agentic_rag → mcp_tool_use → self_reflection → multi_agent`, each step written to the evidence chain |
| NINA (`/nina-run`) | Plans and executes a task; requested tools are checked before use |
| IGOR | Independent verifier of NINA's evidence, provenance and result |
| Human Gate (`/nina-run/{run_id}/approve`) | Execution needs a human approval that the caller cannot self-assert; the default is `BLOCK` |
| Evidence chain (`/evidence`, `app/hashchain.py`) | Per-tenant hash chain with DB-level append-only triggers; supports v1/v2 hashes |
| Provenance | Every run is bound to the exact source commit (`OLA_RUNTIME_COMMIT`) |
| Replay (`app/replay.py`) | Re-verifies a captured chain independently of the run that produced it |

## Four guarantees, re-checked by script

`scripts/verify_readme_claims.py` re-runs these against a fresh temporary database. It exits non-zero if any of them breaks, and `e2e.yml` runs it in CI.

1. **Append-only** — an `UPDATE` on an evidence record is rejected by the database itself.
2. **Tamper detection** — changing a payload in the hash chain is detected on recompute.
3. **Tenant isolation** — reading another tenant's record returns **404**, not 403 (existence is not disclosed).
4. **`UNKNOWN` is never coerced to `PASS`** — missing records and malformed input stay `UNKNOWN`.

```bash
export OLA_API_KEY_PEPPER="$(openssl rand -hex 32)"   # must be >= 32 UTF-8 bytes
python scripts/verify_readme_claims.py
```

## Run it

```bash
docker build -t ola .
docker run --rm -p 8000:8000 \
  -e OLA_API_KEY_PEPPER="$(openssl rand -hex 32)" \
  -e OLA_LLM_MODE=deterministic \
  ola
curl http://127.0.0.1:8000/health      # {"status":"ok"}
```

Tenants and API keys are currently provisioned by inserting rows into the SQLite database (see the `docker exec` steps in `.github/workflows/provenance-gate-final.yml`); there is no self-service endpoint yet. Authenticated routes expect an `X-API-Key` header.

### Configuration

| Variable | Meaning |
|---|---|
| `OLA_API_KEY_PEPPER` | Required secret for API-key hashing, at least 32 bytes. The value in CI workflows is a CI-only placeholder; never reuse it. |
| `OLA_LLM_MODE` | `deterministic` (default; local model, no network) or `required` (real LLM; fails instead of silently falling back) |
| `OLA_LLM_PROVIDER`, `OLA_LLM_MODEL` | Provider and model for real-LLM runs |
| `OLA_RUNTIME_COMMIT` | Source commit recorded in provenance |
| `OLA_EG_DB_PATH` | SQLite path (`/data/ola.db` in the image) |
| `OLA_STRIPE_MODE` | Stripe mode; sandbox only until production is proven |

## Test

```bash
python -m pip install -r requirements.txt
OLA_LLM_MODE=deterministic python -m pytest -q
```

Browser tests need Playwright and are not part of the default run. They start a real server and drive the console (`aurora-e2e.yml` runs them in CI):

```bash
python -m pip install playwright==1.57.0 && python -m playwright install chromium
python -m pytest tests/browser_command_center_real_server.py -q
```

## What a green CI check does and does not prove

Several gates need `OPENAI_API_KEY` (the `ci-openai` environment). Without it — for example on fork PRs — the real-LLM steps are **skipped**, and the run proves only the deterministic and Ollama paths. Since this change the workflows say so explicitly with a `NOT EXECUTED` warning annotation and job summary. To make a missing credential a hard failure, set the repository variable:

```
OLA_REQUIRE_REAL_OPENAI=true
```

Runner images are pinned to `ubuntu-24.04`; the `ubuntu-26.04` job in `evidence-graph.yml` is an intentional compatibility check.

## Repository map

- `app/` — runtime, agents, evidence chain, Human Gate, Stripe webhook
- `scripts/` — independent verifiers (`verify_*.py`), stress and continuity runners
- `tests/` — contract and regression suite
- `web/` — product console served at `/`
- `revenue/` — sandbox revenue surface
- `workstation/` — Windows loopback command executor kit
- `docs/` — architecture, security, runbooks ([signing](docs/runbooks/SIGNING.md)), [PR triage](docs/PR_TRIAGE.md)
- `.github/rulesets/` — proposed branch ruleset for `main`

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately; do not post credentials, customer data or exploit details in public issues.

## License

Public domain ([Unlicense](LICENSE)).
