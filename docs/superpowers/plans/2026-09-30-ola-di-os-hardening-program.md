# OLA di-OS Hardening Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden OLA di-OS into a fail-closed, evidence-driven execution system where no component can silently promote unverified state to `VERIFIED`.

**Architecture:** Keep the existing OLA runtime and Evidence Graph bounded by explicit trust boundaries. Make terminal status derivation, cryptographic replay, state continuity, independent verification, provenance, and human approval separate gates; execution authority remains outside the graph projection and outside Nina.

**Tech Stack:** Python, FastAPI, pytest, SQLite/PostgreSQL as already used by the repository, Docker, GitHub Actions, CodeQL, SHA-256 hash chains, Ed25519 signatures, OpenTelemetry-compatible evidence, k6 for load testing.

**Spec:** Current OLA security-hardening decisions in repository PRs #49 and #50 plus the existing Evidence Graph v0.1 boundary.

## Global Constraints

- Fail closed: `UNKNOWN`, `BLOCKED`, failed assertions, verifier failures, and tamper failures never become `VERIFIED`.
- Retry only infrastructure failures (model pull, timeout, HTTP 5xx), maximum one retry, with reason recorded in evidence.
- Never retry assertion, verifier, or tamper failures.
- A regression fixture is named `verifier regression`, not runtime verification.
- Any fixture mutation must invalidate its expected integrity/provenance guard.
- Human approval must be independently authenticated and bound to the candidate evidence tip.
- Replay must verify the complete tenant chain from sequence zero and bind the expected tip hash.
- The Evidence Graph is a projection, not source of truth and has no execution authority.
- No claim of production verification without runtime evidence from the real execution boundary.
- Every security gate must have a negative test proving the forbidden promotion is impossible.

## Review Focus

- Self-declared approval or terminal status: must be ignored unless independently authenticated and structurally valid.
- Partial evidence chains: must never be accepted as full replay verification.
- Mutated evidence or checkpoint artifacts: must fail integrity verification.
- Infrastructure retry versus semantic failure: only the former is retryable, once.
- Health instability: `VERIFIED` must remain impossible until the required stability window passes.

---

### Task 1: Establish the P0 terminal-status contract

**Files:**
- Modify: existing status/gate modules identified from PR #49
- Test: existing status/gate test suite plus new regression tests

**Interfaces:**
- Consumes: `RUNTIME`, `EVIDENCE`, `REPLAY_INTEGRITY`, `POLICY`, `HUMAN_GATE`
- Produces: deterministic terminal status; `EXECUTION_ALLOWED` is derived, never supplied by callers

- [ ] Write failing tests for self-declared approval, `EXECUTION_ALLOWED` injection, BLOCK+approved, and missing gate input.
- [ ] Run focused tests and record RED output.
- [ ] Implement fail-closed derivation with exactly the five authoritative inputs.
- [ ] Run focused tests and full relevant suite.
- [ ] Add a verifier-regression mutation guard.
- [ ] Commit only after tests prove the forbidden promotions remain impossible.

### Task 2: Cryptographic replay and complete-chain verification

**Files:**
- Modify: existing replay/hashchain modules from PR #50
- Test: replay and hash-chain regression suite

**Interfaces:**
- Consumes: raw `EvidenceRecord` dictionaries, tenant identity, expected tip hash.
- Produces: replay result containing full-chain count, integrity result, and terminal decision.

- [ ] Add RED tests for expected tip binding, sequence starting at zero, record type/status regression, non-dict payload rejection, and reuse of canonical `verify_chain()`.
- [ ] Implement complete-chain replay.
- [ ] Verify mutation, truncation, cross-tenant, and wrong-tip cases are BLOCK/REJECT.
- [ ] Run focused and full relevant tests.
- [ ] Commit.

### Task 3: State continuity and stability gate

**Files:**
- Modify: checkpoint/state verification modules associated with PR #39
- Test: state continuity, recovery, stability, and tamper tests

**Interfaces:**
- Consumes: canonical checkpoint artifacts and runtime execution stages.
- Produces: `STABLE` only after the configured health/stability window.

- [ ] Add RED tests for stale checkpoint, modified checkpoint, missing checkpoint, recovery mismatch, and premature promotion.
- [ ] Implement atomic checkpoint + SHA-256 binding + chained state hash verification.
- [ ] Require stable health window before terminal `VERIFIED`.
- [ ] Verify recovery and tamper behavior.
- [ ] Commit.

### Task 4: Independent Nina/Igor execution boundary

**Files:**
- Modify: `app/agent_runtime.py`, `app/igor.py`, relevant gate modules and workflows
- Test: real-runtime and verifier regression tests

**Interfaces:**
- Nina produces candidate evidence; Igor consumes evidence independently.
- Igor may veto but cannot manufacture upstream runtime evidence.

- [ ] Add RED tests proving Nina cannot self-verify.
- [ ] Require real runtime identifiers/response evidence where the real-LLM gate is enabled.
- [ ] Keep Human Gate explicitly `PENDING` until independent approval is authenticated.
- [ ] Add regression fixture with mutation guard.
- [ ] Run the real-runtime workflow only under explicit real-LLM configuration.
- [ ] Commit.

### Task 5: Provenance and signed evidence bundle

**Files:**
- Create/modify: evidence bundle and provenance modules
- Test: provenance, hash, signature, and replay tests

**Interfaces:**
- Produces: `execution_id`, source/runtime/artifact references, SHA-256 manifest, Ed25519 signature, verifier result.

- [ ] Add RED tests for missing provenance link, altered manifest, wrong signature, and artifact mismatch.
- [ ] Implement canonical manifest generation and signature verification.
- [ ] Ensure secrets never enter evidence payloads or logs.
- [ ] Add replayable evidence bundle generation.
- [ ] Commit.

### Task 6: CI security perimeter

**Files:**
- Modify: `.github/workflows/*` security and verification workflows
- Test: workflow/static validation fixtures

- [ ] Verify CodeQL Actions/Python coverage.
- [ ] Add/verify dependency vulnerability and secret scanning gates where supported.
- [ ] Enforce least-privilege workflow permissions.
- [ ] Ensure exact PR-head checkout for security-sensitive checks.
- [ ] Ensure failed security gates cannot be bypassed by unrelated green jobs.
- [ ] Verify branch protection/check requirements independently before claiming merge blocking.
- [ ] Commit.

### Task 7: Runtime scenario and load proof

**Files:**
- Create: scenario fixtures, Docker assets, probe scripts, k6 load script, assertions, score and run scripts
- Test: runtime scenario suite

- [ ] Implement the Certificate Apocalypse scenario as a real Docker/k3d runtime fixture.
- [ ] Cover certificate expiration, trust-chain failure, time skew, and recovery.
- [ ] Collect availability, latency p95/p99, error rate, MTTR, and blast radius evidence.
- [ ] Require health stability after recovery.
- [ ] Run load tests and verify SLO assertions.
- [ ] Produce signed evidence bundle.
- [ ] Commit.

### Task 8: Production verification gate

**Files:**
- Modify: release/verification workflow
- Test: end-to-end production-gate regression suite

- [ ] Compose final gate from runtime, evidence, integrity, replay, policy, human gate, stability, and provenance.
- [ ] Add explicit negative tests for every omitted/failed gate.
- [ ] Verify end-to-end on the real workstation/runtime.
- [ ] Preserve all evidence artifacts with hashes and execution IDs.
- [ ] Only then classify the result as `VERIFIED` for the tested scope.
- [ ] Commit and request independent code review.

## Definition of Done

A tested OLA di-OS path is not considered verified until the same execution can be independently reconstructed from evidence, the evidence integrity can be checked, replay can reproduce the decision, tampering is rejected, the health state remains stable for the configured window, and all required human/policy gates are satisfied.
