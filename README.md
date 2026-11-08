# OLA — Evidence-Driven Execution Runtime

OLA is a Python/FastAPI application for controlled agent execution, tenant-scoped evidence capture, hash-chain integrity checks, replay-oriented verification, and a payment-triggered execution path.

This repository is the canonical OLA runtime source. A successful test or CI workflow proves only the checks that actually ran; it does not, by itself, establish production readiness or a live customer transaction.

## Repository scope

The current source tree contains:

- `app/` — FastAPI application, tenant/API-key handling, agent runtime, NINA orchestration, IGOR verification, execution safety gate, Human Gate decision model, evidence persistence, replay, and Stripe checkout/webhook integration.
- `evidence_graph.py` — a separate SQLite-backed Evidence Graph projection module. The package metadata currently describes this module; it is not a complete description of the whole FastAPI application.
- `tests/` — unit and integration tests for runtime, evidence, agent controls, replay, payment handling, and related contracts.
- `scripts/` — runtime, provenance, stress, continuity, and evidence verification helpers.
- `docs/` — implementation notes, design records, and operational documentation.
- `web/` — static application entry page.
- `workstation/` — workstation-related assets.
- `.github/workflows/` — CI, security, runtime, provenance, and production-evidence workflows.
- `revenue/` — revenue-related assets and supporting material.

## Runtime and persistence facts

- Python requirement in `pyproject.toml`: Python 3.11 or newer.
- The Docker image installs Python 3.13 and starts `uvicorn app.main:app` on port 8000.
- The current application database implementation uses SQLite. Its default file is `ola.db`; the path can be overridden with `OLA_EG_DB_PATH`.
- Evidence writes use SQLite `BEGIN IMMEDIATE`, per-tenant sequence numbers, previous-record hashes, and append-only database triggers.
- The database implementation explicitly rejects non-SQLite append operations until a separately audited policy exists. Do not describe the current application persistence as PostgreSQL.
- `pyproject.toml` metadata names the distribution `ola-evidence-graph` and declares FastAPI; `requirements.txt` supplies the pinned runtime/test dependencies used by the Docker build.

## Main application surfaces

The inspected application source defines these HTTP routes:

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Serves the static web entry page. |
| GET | `/health` | Basic process health response. |
| POST | `/chat` | Tenant-authenticated chat surface. |
| POST | `/checkout` | Creates a Stripe Checkout Session when configured. |
| GET | `/payment-success` | Retrieves and checks a Checkout Session and its matching webhook execution. |
| POST | `/evidence` | Appends tenant-submitted evidence, while rejecting reserved internal evidence types. |
| POST | `/audit` | Runs the currently supported controlled fault-and-recovery audit scenario. |
| POST | `/agent-run` | Requests an agent execution through the execution safety controls. |

Check `app/main.py` for the complete route contract and current request/response details.

## Trust and control boundaries

- Unknown, malformed, or unverifiable states must not be promoted to `VERIFIED` or `ALLOW`.
- NINA is a bounded orchestration layer over registered capabilities; it does not create verification evidence.
- IGOR is an independent verification component in the application flow; its presence in code is not proof that every execution is independently verified in production.
- The current `ExecutionSafetyGate` denies unknown actions and returns `REVIEW` for HIGH-risk actions. Its source explicitly says a caller-controlled boolean is not trusted Human Gate approval and that a trusted approval verifier is not yet integrated at that execution boundary.
- The current `HumanGate` model checks the review actor, approval decision, and candidate status. Do not treat this small decision model alone as proof of a complete authenticated production approval workflow.
- A local hash chain supports integrity checking; it does not independently prove the truth of submitted observations or the identity of an external source.
- Stripe integration code is present. A configured checkout path or passing mocked test is not proof of a live paid order, successful fulfillment, or production revenue. Those require exact live Stripe event/session evidence and a verified execution result.

## Local setup

Requirements: Python 3.11+ and a working shell.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the application:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Check basic health:

```bash
curl --fail http://127.0.0.1:8000/health
```

Run the test suite:

```bash
pytest
```

Build and run the container:

```bash
docker build -t ola:local .
docker run --rm -p 8000:8000 -v ola-data:/data ola:local
```

The Dockerfile sets `OLA_EG_DB_PATH=/data/ola.db` and runs as an unprivileged `ola` user. Configure Stripe environment variables only in a local secret store or deployment secret manager; never commit credentials.

## Stripe configuration

The inspected source uses these environment variables:

- `STRIPE_SECRET_KEY` — Stripe API secret.
- `STRIPE_WEBHOOK_SECRET` — webhook signature verification secret.
- `OLA_STRIPE_PRICE_ID` — configured Stripe Price ID.
- `OLA_STRIPE_TENANT_ID` — fallback tenant identifier for webhook processing when session metadata does not provide one.

The webhook handler validates Stripe signatures and checks the configured offer, product, paid status, EUR currency, and expected amount. The currently inspected source enforces an amount of 9900 minor units (EUR 99.00) for the supported offer. Confirm the live Stripe Price configuration and commercial approval before advertising or changing a price.

## Verification and release status

Use the GitHub Actions workflows and the scripts in `scripts/` as evidence sources, but inspect each run against the exact commit SHA being evaluated. A workflow file existing in the repository is not evidence that it passed.

Before any production claim, independently verify at minimum:

1. the exact source commit and its required check runs;
2. test and security results for that exact SHA;
3. container build and runtime health;
4. evidence-chain integrity and replay/tamper checks;
5. provenance and release artifact attestations;
6. real Stripe checkout, signed webhook, confirmed payment, execution, and customer deliverable evidence;
7. the required human approval and production authorization.

Until all required evidence is present, describe production readiness as `UNKNOWN`, `PARTIAL`, or `BLOCKED` as appropriate — never infer `VERIFIED` from documentation or workflow definitions.

## Security

Read [SECURITY.md](SECURITY.md) before reporting vulnerabilities or preparing a release. Never commit API keys, Stripe secrets, signing keys, customer data, or production evidence containing sensitive information.


## Portfolio repository map

The current repository ownership and provenance snapshot is maintained in [REPOSITORY_CATALOG.md](docs/REPOSITORY_CATALOG.md), with a machine-readable companion at [REPOSITORY_CATALOG.json](docs/REPOSITORY_CATALOG.json). These files distinguish canonical source repositories, forks, specifications, and experiments; they do not assert production readiness.
