# Evidence Cryptography V4 — implementation contract

## State

V4 storage, cryptographic verification, and all five writer families are
implemented on the active PR branch. This is **branch implementation**, not a
production release: no production secret is provisioned, no production
historical ledger has been migrated, and deployment remains blocked pending
independent review and Human Gate.

Writer integration map (all append through the caller-owned transaction):

1. `database.append_evidence_atomic` — central application writer; retains
   SQLite `BEGIN IMMEDIATE`, PostgreSQL tenant advisory locking, sequence
   allocation, deduplication, and the unique `(tenant_id, seq)` guard.
2. `nina_workflow_gate` — both workflow and NINA approval records; retains
   read/verify preflight, tenant lock reacquisition, and approved-tip recheck.
3. `paid_order_execution` — execution lifecycle evidence; retains outbox
   claim, row locks, and transaction coupling with execution state.
4. `order_approval` — revenue execution approval; retains payment proof,
   current-tip validation, and atomic approval/control/job updates.
5. `report_review` — report approval and delivery evidence; retains report
   digest recomputation, tip binding, and atomic review/delivery state.

The independent verifier in `app/igor_evidence_verifier.py` handles V1/V2/V3/V4
without importing the writer's cryptographic implementation. Runtime
verification is key-dependent: V3 requires the historical
`OLA_API_KEY_PEPPER`; V4 requires the injected V4 keyring. Production key
custody and authentic historical records remain unproven release blockers.

## Storage contract — no schema migration

The current `EvidenceRecord` schema is retained:

- `tenant_id`
- `seq`
- `record_type`
- `payload_json`
- `prev_hash`
- `record_hash`

V4 metadata is stored inside `payload_json` under the reserved top-level key
`__ola_evidence_v4__`. Its exact schema is:

```json
{
  "__ola_evidence_v4__": {
    "version": 4,
    "key_id": "key-2026-01",
    "record_type": "provenance.runtime",
    "producer": "ola_runtime"
  }
}
```

Application payload fields remain at the top level. V4 writers must reject both
reserved keys `__ola_evidence_v2__` and `__ola_evidence_v4__` in caller payloads.
The V2 metadata key and its historical contents are never rewritten.

The V4 authenticated material includes the domain, version, key_id, tenant_id,
sequence, predecessor hash, record type, producer, and the exact canonical
`payload_json`. The record hash is lowercase HMAC-SHA256 hex. No database
columns or existing V1/V2/V3 bytes need to be rewritten.

## Key custody

Inject `OLA_EVIDENCE_V4_KEYRING_JSON` as a JSON object mapping key IDs to
base64-encoded random key material, and `OLA_EVIDENCE_V4_ACTIVE_KEY_ID`.
Each key must contain at least 32 random bytes. The keyring belongs in an
external secret manager; it must never be persisted in the evidence database,
logs, repository, or evidence backups. Evidence backups and secret backups are
separate recovery artifacts.

Verification selects exactly the `key_id` embedded in the V4 metadata. Missing
or unknown keys fail closed. Rotation changes the active key for new writes but
retains old keys for historical reads. The in-memory keyring is defensively
copied and immutable.

## Legacy compatibility

- V1: no `__ola_evidence_v2__` metadata; historical unkeyed V1 digest.
- V2: `__ola_evidence_v2__.version = 2`; historical domain-separated SHA-256.
- V3: `__ola_evidence_v2__.version = 3`; historical HMAC derivation from
  `OLA_API_KEY_PEPPER` using `OLA-EVIDENCE-CHAIN-KEY-V3`.
- V4: `__ola_evidence_v4__.version = 4`; independent keyring and HMAC domain.

The V3 algorithm is recoverable from immutable source commit
`c46b469836fc841638654850158c82d728164f3c`, file
`app/hashchain.py` (blob
`60f12f96bcb0291201b432747cfd16b12921d2c3`). A V3 compatibility test and
historical-format fixture must retain that source provenance. V3 key custody
must remain distinct from V4 custody; do not substitute or rotate the old
pepper as part of V4.

The mixed-chain adapter checks global sequence/predecessor continuity and
verifies V4 itself. Legacy V1/V2/V3 segments are passed intact to an explicit
legacy verifier. It must never silently treat a legacy record as V4 or fall
back to a V4 key for legacy verification.

## Required release gates

- All five evidence writers produce V4 using the storage contract above.
- All read paths verify mixed V1/V2/V3/V4 chains.
- Immutable, provenance-labelled V1/V2/V3 fixtures pass exact historical
  verification; fixture provenance is not inferred from a synthetic example.
- Rotation, key loss, unknown key_id, key substitution, restart,
  backup/restore, and mixed-chain scenarios pass.
- IGOR uses an independently implemented verifier and does not import the
  writer's hash implementation.
- CI separates functional cryptographic tests from secret-management tests.
- Independent security review has no open critical findings.

Until every gate is evidenced at the exact release SHA: `PRODUCTION_BLOCKED`.

## Writer migration invariants

The V4 append primitive must accept the caller's already-open SQLAlchemy
transaction/session. It must not open or commit a nested session. Existing
tenant serialization remains owned by each call site:

- `database.append_evidence_atomic`: retain SQLite `BEGIN IMMEDIATE`,
  PostgreSQL tenant advisory lock, idempotent deduplication, sequence allocation,
  and the unique `(tenant_id, seq)` guard.
- `nina_workflow_gate`: retain read/verify outside the lock, then reacquire the
  tenant lock and recheck the approved tip before append.
- `paid_order_execution`: retain the existing outbox claim, row locks, and
  transaction boundary; append V4 in the same transaction as execution state.
- `order_approval`: retain payment proof checks, current-tip binding, and the
  same transaction as approval/control/job updates.
- `report_review`: retain independent report digest recomputation, tip binding,
  and the same transaction as review/delivery state.

A central append helper alone is not a migration: all four direct-writer
families above must call the V4 append primitive explicitly. The migration must
not move business checks across transaction boundaries.

Read migration is separate from write migration. The V4 chain dispatcher must
first establish complete chain integrity for all versions, then callers may
apply trust policy. A V1/V2 record remains readable but never gains V4 trust.
V3 verification continues to require the historical V3 pepper. V4 key rotation
must not alter or replace that legacy pepper.

## Idempotency and deduplication

V4 `key_id` is cryptographic metadata, not business-event identity. A key
rotation must not cause a retried event to be appended a second time solely
because the active key changed. The V4 append primitive therefore compares
canonical application payload, tenant, record type, and producer while
excluding `key_id`.

Deduplication is deliberately V4-version-scoped. V1/V2/V3 rows do not satisfy
a V4 retry automatically. That avoids treating legacy history as trusted
idempotency evidence without a separate historical reconciliation policy.
The append primitive verifies the complete existing tenant chain before
deduplication or append, and refuses to extend a chain it cannot verify.

## Lifecycle evidence and CI separation

The functional suite uses a deterministic, public test-only key injected by
pytest. It exercises the V4 writer, independent IGOR verification, rotation,
tampering, and mixed legacy chains.

`tests/test_evidence_v4_process_lifecycle.py` starts separate Python
processes for write, restart/read, key rotation, SQLite backup, restore, and
key-loss verification. It writes the evidence database backup and keyring
backup as separate artifacts and asserts that neither raw nor base64 key
material appears in the database file.

`tests/test_evidence_secret_management.py` is marked
`secret_management`. A separate CI job runs it without a V4 test key and
proves missing/invalid injection fails closed, short keys are rejected,
duplicate key IDs are rejected, and key bytes are not exposed in repr output.
This is a secret-injection contract test, not proof of a production secret
manager integration. Production secret-manager provisioning and access-policy
verification remain release blockers.
