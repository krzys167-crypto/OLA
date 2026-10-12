# Events & Webhooks integration candidate

Status: BLOCKED for production. This branch stages an integration decision, not executable deployment.

Source: user-supplied `ola-events.tgz` (2026-10-12). Candidate modules: `backend/events/{outbox,worker}.py`, `backend/webhooks/{inbound,outbound,security}.py`, tests `test_webhooks.py`.

## Existing OLA compatibility
- Preserve `app/stripe_webhook.py` and its tests; Paddle must remain an optional adapter.
- Confirm actual FastAPI application entrypoint, auth/RBAC, tenant model, database strategy and evidence graph before importing routers.
- Do not deploy the candidate SQLite outbox as a substitute for OLA's existing durable audit store.

## Mandatory remediation before adding runtime code
1. Atomic delivery claims / lease expiration and idempotent receiver semantics for concurrent workers.
2. Handler failures must not mark events processed; persistent retry/dead-letter per handler.
3. SSRF: prevent DNS rebinding through connection-level address pinning or controlled outbound egress proxy; disallow redirects and unsafe ports.
4. Secret encryption at rest and rotation; no plaintext credentials in evidence/logs.
5. Tenant isolation and authentication aligned with existing OLA auth, no parallel API-key system without explicit design.
6. Independent signed checkpoints for hash chain, tamper and truncation detection, replay tests.
7. Negative tests, multiworker concurrency, tenant isolation, integration CI, migration and rollback plan.

## Gates
SOURCE=PARTIAL (user archive available); LOCAL_TESTS=5 PASS (candidate only); INTEGRATION=BLOCKED; CI=UNKNOWN; PRODUCTION=NO-GO.

Next: port and harden candidate into an isolated package, add CI tests, then submit draft PR; do not merge until gates pass.
