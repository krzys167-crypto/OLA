# OLA

A fail-closed, evidence-based pipeline: **NINA → OLLAMA → EVIDENCE → IGOR → GATE → REPLAY**.

The rule of the repository: nothing is called `VERIFIED` without evidence, anything not measured is `UNKNOWN`, and a missing proof never counts as a pass.

## What is in here

| Path | What it is |
|---|---|
| `app/` | FastAPI service: append-only evidence store with a hash chain, NINA/IGOR runs, human gate, agent firewall, Ed25519 identities, CFR (Code Forensics Range) scenarios and witness, revenue proof (Stripe) |
| `ola_pipeline/` | Stand-alone pipeline with its own stdlib Ed25519 attestation and an independent session verifier |
| `cfr_scenarios/` | CFR scenarios; `certificate-apocalypse` is the first one |
| `scripts/` | Verifiers, evaluation harnesses and CI helpers |
| `tests/` | Test suite (CI also runs the gates listed in `.github/workflows/`) |
| `docs/` | Design notes, the pipeline bridge, the control/evidence matrix, sales and payment notes (`docs/sales/`) |
| `workstation/`, `web/` | Workstation kit and the static web UI |

## Guarantees that are re-checked on their own

`python scripts/verify_readme_claims.py` re-runs four guarantees on a fresh temporary database, independent of the test suite:

1. Append-only: an `UPDATE` on an evidence record is blocked at the database level.
2. Hash chain: a tampered payload is detected by recomputing the chain.
3. Tenant isolation: access to another tenant's record is `404`, not `403`.
4. `UNKNOWN` is never silently coerced to `PASS`.

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health          # {"status":"ok"}
```

Tests: `pytest` (Python 3.11 or newer). The `Dockerfile` builds the same service on `debian:13-slim`, exposes port 8000 and checks `/health`.

A session produced by `ola_pipeline` can be checked without the service: `python -m ola_pipeline verify <session_dir>`. Exit codes: 0 `VERIFIED`, 1 `FAILED`, 2 `CONSISTENT`, 3 `PARTIAL`, 4 bad `--trusted-key` (see `ola_pipeline/verify.py`); `docs/sales/sample/` walks through a synthetic session.

## Status vocabulary

`VERIFIED` (proved by evidence that was actually checked), `ATTESTED` (signed by a party, not independently checked), `PARTIAL`, `UNVERIFIED`, `BLOCKED`, `UNKNOWN`. Payments follow the same rule: a claimed payment is not money, and a payment is `PROVEN` only through Stripe evidence (see `docs/sales/`).

## Security and license

Report vulnerabilities as described in [SECURITY.md](SECURITY.md). Released into the public domain under the [Unlicense](LICENSE).
