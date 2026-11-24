# Vantage / CFR evidence integration — recovery record

Date: 2026-11-24
Status: DESIGN CONTRACT RECORDED / INTEGRATION NOT IMPLEMENTED / PRODUCTION NO-GO

## Verified inputs

- Active Vantage scenario platform: `krzys167-crypto/Vantage-v0.3`.
- Vantage `main` and its configured default branch are divergent; do not merge or change the default branch until both unique commit sets are reviewed.
- Historical Vantage CI run `42258004693` returned 30 failed jobs. Job-log retrieval returned a storage 404 during this recovery, so failure causes remain unknown.
- Vantage contains a grader, signed reports/debrief, scenario execution and hosted-range admission policy. The policy has fixture-based CEL tests; live k3s enforcement remains unverified.
- Recovered CFR-15 source: 33 non-E2E tests pass locally; E2E test collection requires `fakeredis`, declared in the archive requirements.
- Recovered CFR-14 source: local smoke could not be completed in this environment; Docker Compose and k6 were unavailable.
- The separate `ola-evidence-gateway` GitHub repository currently contains a README contract only. An implementation candidate exists in a recovered archive, but has not been ported or independently verified as repository source.

## Integration contract

Vantage is the execution and grading authority. OLA Evidence is the durable evidence and provenance authority. OLA Decision consumes verified evidence; it does not replace the grader.

Required evidence envelope:

- `schema_version`
- `run_id`, `scenario_id`, `scenario_version`
- `source_repository`, `commit_sha`, `workflow_run_id`
- `tenant_id`, `subject_id` (scoped identifiers; no secrets)
- `started_at`, `completed_at`
- `result`: PASS / FAIL / UNKNOWN
- `artifact_digests[]` (SHA-256 of raw retained artifacts)
- `signer_key_id`, signature and verification metadata

## Required end-to-end path

1. Vantage executes a scenario and produces raw artifacts.
2. The grader signs the evidence envelope using a controlled signing identity.
3. Gateway validates schema, authorization, signature, source provenance and content digests; it must recalculate hashes rather than trust supplied values.
4. Gateway stores append-only evidence and returns a stable evidence ID plus verification result.
5. OLA Decision references the evidence ID, verifier version and policy version.
6. Reports link back to raw evidence and retain PASS / FAIL / UNKNOWN distinctions.

## Security constraints

- Never treat participant self-report as the sole evidence source.
- Never accept a public key supplied only by the participant as a trust anchor.
- Do not store credentials, private keys or bearer tokens in evidence payloads.
- Enforce tenant isolation and idempotent replay handling.
- Hashing proves byte integrity, not source truth or signer identity.
- UNKNOWN must never be promoted to PASS by default.
- Preserve original evidence; corrections are new linked records, not updates/deletes.

## Release gates

- Reconcile Vantage branch divergence without rewriting either history.
- Restore green CI on an exact commit and retain raw job logs/artifacts.
- Run hosted admission policy on k3s >= 1.30 and demonstrate allowed restart / denied pod-spec mutation.
- Complete CFR-15 full test suite and live Docker/k6/OTel run.
- Complete CFR-14 Docker/k6 run and required stability window.
- Port Evidence Gateway only after per-file provenance and hash review.
- Add repository-native integration tests and a signed end-to-end run.

Until all applicable gates pass: `NO-GO` for hosted production, customer certification or compliance claims.
