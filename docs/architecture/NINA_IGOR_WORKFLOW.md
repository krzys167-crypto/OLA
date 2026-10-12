# OLA — NINA / IGOR evidence-bound workflow (PR #100)

## Operational pipeline

1. **SOURCE**: on a PR, select `github.event.pull_request.head.sha` rather than the ephemeral `github.sha` test-merge commit. Checkout that *exact SHA* and compare with `git rev-parse HEAD` before tests/build.
2. **NINA + REAL OLLAMA**: six real provider invocations on a disposable CI runner; record the exact SOURCE_SHA in runtime provenance.
3. **IGOR**: independent Python verification of tenant/run, six-agent execution, provider/model, exact source, result and append-only evidence chain. A separate proof-policy checker validates the exported JSON and rejects altered source/roles/status.
4. **EVIDENCE + REPLAY**: record a source-bound execution report, standalone verifier output, hashes and CI artifacts; do not report VERIFIED when an assertion fails.
5. **POLICY**: CI always expects `HUMAN_GATE=BLOCK`, `EXECUTION_ALLOWED=REVIEW`, and `status=REVIEW`; it never approves execution itself.
6. **RELEASE**: trusted owner produces a *separate* signed, single-parent commit from current main with identical reviewed tree; GitHub verifies the signature and allowlisted fingerprint. Rerun all CI for that new source SHA. Independent review, active main ruleset, credential migration, persistent deployment, authenticated stability check and human approval are additional gates before GO.

## Evidence truth boundaries

* `VERIFIED_CI_PROOF` is **not** signed production, live deployment, paid customer proof, or an authorized Human Gate action.
* `github.sha` is retained solely as `workflow_event_sha` for diagnostics; it may be the synthetic PR merge SHA, not source identity.
* GitHub Actions artifacts are per source SHA and run attempt; their integrity is checked inside the workflow, but the workflow's own code is not an external root of trust.
* Existing `Nina Igor Gate` already checks out exact PR HEAD independently; both jobs must be green on the *same SHA*.
* `main` is never updated by this workflow. No force pushes, credential rotations, payment actions or production deployment are permitted by it.

## Fail-closed cases

Reject: source mismatch; missing provider/model; fewer than six real LLM calls; failed IGOR or replay; forged Human Gate; missing run/tenant IDs; invalid evidence JSON; failed standalone verifier; unsigned release commit; missing separate approval or persistent production evidence.
