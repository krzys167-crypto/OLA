# PR #307 P1 Hardening Reproduction Matrix

This matrix tracks adversarial tests for three risks. It is not a pass report; tests must be implemented and executed against the exact candidate SHA.

## Stripe webhook execution idempotency

| ID | Setup / fault | Expected invariant |
|---|---|---|
| STR-01 | Worker A executes task beyond lease; Worker B attempts reclaim | One durable execution per checkout session; second worker recovers result or is rejected |
| STR-02 | Crash after task side effect, before runtime persistence | Retry retrieves task result via idempotency key; no repeat side effect |
| STR-03 | Two event IDs refer to same checkout session concurrently | Same durable execution key and result |
| STR-04 | Lease reclaimed; stale worker attempts write | Stale worker cannot mutate record or trigger new side effects |
| STR-05 | Worker killed; lease expires | Recovery is bounded; no orphaned permanent PROCESSING state |

Required implementation contract: runner receives a stable idempotency key derived from checkout-session identity; task execution/result storage is durable and lookupable; lease heartbeat or fencing does not substitute for runner idempotency.

## Pipeline concurrency across processes

| ID | Setup / fault | Expected invariant |
|---|---|---|
| PIPE-01 | Launch N independent processes, each attempts a run | Global in-flight count never exceeds configured limit |
| PIPE-02 | Worker dies while holding slot | Slot expires/reclaims safely |
| PIPE-03 | Invalid limit configuration | Fail closed, no unlimited execution |
| PIPE-04 | Two replicas race to acquire last slot | Exactly one acquisition succeeds |

If deployment is single-process only, startup must reject multi-worker/replica topology or make the constraint explicit and observable.

## External timestamp checkpoint

| ID | Setup / fault | Expected invariant |
|---|---|---|
| ANC-01 | Rewrite host evidence then obtain new TSA timestamp | Verification fails against externally pinned checkpoint |
| ANC-02 | Delete anchor/checkpoint | Verification is BLOCK/unknown fail-closed; never VERIFIED |
| ANC-03 | Roll back tip or replace token | Pin mismatch detected |
| ANC-04 | Revoke TSA certificate | Verification applies configured revocation policy |
| ANC-05 | Valid token, pinned expected tip/genTime | Verification succeeds only for exact pinned values |

## Acceptance evidence

- Run tests on exact candidate commit SHA.
- Include CI run URL and runtime topology.
- Record reproducible test command, test counts, and outcome.
- Do not label the PR production verified until all required evidence is present.

Status: pending implementation and execution; this file itself does not close any finding.
