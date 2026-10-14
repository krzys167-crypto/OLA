# ADR-001 — Evidence trust boundary (proposed)

Status: PROPOSED / NO-GO
Source reviewed: OLA PR #103, c78135d49afe519bcda55dfcfc3187e1bbb51cc1, 2026-10-14.

## Finding
`app/igor.py` returns VERIFIED after local hash-chain and expected provenance/outcome checks. The reviewed code does not authenticate NINA with a trusted signing key or verify an external checkpoint. `app/decision_report.py` consumes caller-supplied status values. Therefore current VERIFIED must not be presented as independently attested execution.

## Decision
Preserve existing legacy APIs and evidence formats. Introduce a separate evidence assurance level: RECORDED (durable capture), LOCAL (local consistency), ATTESTED (authenticated origin and bound policy/source), VERIFIED (independent verifier, separately controlled trust root, required artifact checks and external checkpoint), BLOCKED (failed required check). UNKNOWN is a non-promotable result when evidence is absent or insufficient; levels are not a total order of truth.

## Minimum Evidence-Stream v0.1 contract
Signed payload includes: protocol/version; tenant_id, event_id, request_id, execution_id; agent_id, host_id, signing key ID; full source commit SHA and binding proof reference; operation and canonical parameter digest; policy ID/digest/decision; human approval digest when required; started/finished timestamps; result artifact digest; stream ID, sequence and previous event hash. Sign SHA-256 of RFC 8785 canonical payload with Ed25519 and domain separation. Keep verifier receipt outside producer payload.

## Required verifier checks
Schema and canonical encoding; signing key bound to tenant/host/agent; signature; replay protection and sequence; chain consistency; signed source and policy bindings; pre-execution authorization; approval scope, expiry and revocation; artifact bytes vs digest; external checkpoint; independent verifier signature. Deny unknown, missing, inconsistent, expired or unverifiable conditions. Distinguish fast local checks from asynchronous full verification.

## Non-goals and limits
Cannot infer complete machine state from logs. An attacker who controls an entire unanchored database can rewrite history undetected. A signed statement is not proof of real-world execution. Clock timestamps are not a trusted ordering source. Do not assume millisecond end-to-end verification without benchmarks.

## Implementation order
1. Add decision-report.v2 with exact source SHA, policy digest, evidence root, human approval digest and explicit assurance status.
2. Add canonical Evidence-Stream schema and compatibility adapter, keeping v1/v2 legacy records readable.
3. Run IGOR as an independently permissioned verifier with external trust anchors and signed receipts.
4. Add mutation tests: changed payload, wrong key, replay, reordered event, wrong host, wrong policy, expired approval, missing artifact, rewritten unanchored database (expected NOT DETECTED before anchoring), and rewritten anchored database (expected BLOCK).
5. Benchmark p50/p95/p99 separately for signature check, durable receipt and asynchronous full verification.

## Production gate
No merge, signing, deployment or GO until owner-approved branch protection, trusted signer/UID, immutable frozen tree, independent Human Gate, successful exact-SHA CI, evidence/replay and adversarial results are demonstrated. Never promote legacy local VERIFIED automatically.
