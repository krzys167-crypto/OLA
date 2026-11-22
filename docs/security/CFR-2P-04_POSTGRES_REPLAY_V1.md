# CFR-2P-04 — PostgreSQL durable capability replay v1

**Candidate status:** stacked on PR #273 exact head `6d8011717dd63c7df8442b5009f718ada6582aee`. Not integrated into the shared execution choke point.

## Replay-store contract

- PostgreSQL is the only accepted backend for this candidate; no memory or SQLite fallback.
- A tenant-scoped unique nonce and voucher-ID key make concurrent consumption atomic across verifier instances/workers.
- The runtime role must have SELECT/INSERT only for `capability_replay_ledger`; UPDATE, DELETE and TRUNCATE are denied.
- PostgreSQL triggers reject UPDATE/DELETE even for the migration/owner role.
- Schema verification requires the table, unique constraints, migration marker and trigger definitions.
- SQLite `MemoryReplayLedger` and `SQLiteReplayLedger` remain contract-test/local tools only.

## Tests

The PostgreSQL contract test uses the isolated CI service to race two verifiers against the same voucher, expects one accepted and one replay rejection, checks the persisted record, verifies append-only triggers, and confirms that an overprivileged runtime role is rejected.

## Not implemented

- No route/worker integration or shared execution choke point.
- No voucher issuance configuration or secret handling.
- No production migration, staging DB mutation, runtime grant, deployment, payment or external effect.
- No retention/cleanup policy; replay rows are append-only and retention must be approved before production scale.

**HUMAN_GATE:** an authorized DB owner must approve the runtime role's SELECT/INSERT grants, schema target and migration timing. Independent review and exact-SHA PostgreSQL CI are required.
