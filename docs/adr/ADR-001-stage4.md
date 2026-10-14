# Stage 4 — durable local execution permit pilot

Existing /auth/session authenticates a credential ID only. No human identity,
owner role, passkey or OIDC provider was found in this checkout. Production
PermitService therefore defaults to an identity resolver that always denies.
There is no public approval endpoint or automatic enrollment of existing API keys.
Tests use clearly labeled fixture actors, not Krzysztof's authenticated approval.

The pilot stores permits in an additive execution_permits table in the existing
SQLite database and appends transitions to the existing EvidenceRecord chain.
A trusted server adapter must resolve fresh issuer/subject/tenant/role identities.
Credential strings and different keys alone do not establish different people.
The owner and requesting service must have different stable identities.

A permit binds exact source SHA and source-file digest, policy-file digest, tenant,
requester, operation, immutable parameters, a specific result resource and 300s
expiry. Only bounded sha256-text is supported. Execution accepts an ID and expected
subject digest, never replacement parameters. Source/policy, current executor
identity, state, approval digest and expiry are rechecked inside the transaction.

BEGIN IMMEDIATE serializes approval/revocation/execution. SHA-256 calculation,
completion record, receipt and COMPLETED state commit in one transaction.
Repeated execution is denied after completion, including in a fresh process.
Failure before commit rolls back this local calculation and its state together.
This is exactly one committed local result, NOT exactly one physical CPU evaluation.
External effects cannot be added under this atomicity assumption. They need durable
idempotency, outcome reconciliation and an uncertain-outcome state.

scripts/prove_permit_restart.py uses a fresh OS process for every step and actual
Git source observation, but its identity provider is an explicit LOCAL-TEST-FIXTURE.
scripts/inspect_permit_receipt.py reads exported bytes in a separate process and
compares expected source/policy digests, immutable subject, timing and calculation.
It reports LOCAL/UNKNOWN only. It has no signature/trust-root authentication and
cannot detect a wholly rewritten, consistently rehashed artifact.

Not delivered: production identity provider/enrollment; role revocation integration;
public API/UI for owner approval; integration into live NINA tool dispatch;
external-effect permits; independently administered IGOR or signed external anchors.
Local server time and SQLite are trusted within this pilot. Privileged DB rollback
or code manipulation is outside the guarantee. Production remains NO-GO.
