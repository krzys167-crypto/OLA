# ADR-001 stage 1: decision report v2

Base: c78135d49afe519bcda55dfcfc3187e1bbb51cc1 (PR #103).
Local implementation candidate. Production NO-GO. No signing, merge or deployment.

`/nina-run` adds `decision_report_v2`; `decision_report` and v1 semantics remain
unchanged. The legacy CLI still uses VERIFIED for a checksum match: consumers
must not interpret that as an independently attested execution. No automatic
promotion from legacy fields exists in v2.

V2 binds an immutable snapshot of the legacy report, exact source SHA (40 lowercase
hex characters or null), policy digest, evidence root and human approval digest
(64 lowercase hex characters or null). Invalid legacy runtime source labels map
to null; the original claim remains in existing provenance. The evidence root is
the input-chain tip BEFORE decision.candidate, not the response tip_hash after
that append. It may cover earlier runs in the same tenant chain.

Policy and approval digests remain null in the live adapter because this endpoint
has neither an immutable policy document nor a report-bound approval. Supplying a
well-formed digest proves neither its authenticity nor its connection to execution.
All stage-1 reports therefore have assurance UNKNOWN and production_eligible=false.
No receipt is manufactured. Future receipt validation must be a separate versioned
path; merely adding a caller-supplied status is forbidden.

The local inspector returns integrity LOCAL only for a matching report structure
and checksum; it leaves execution assurance UNKNOWN. BLOCKED indicates invalid
structure or local integrity. Exit 0 means local inspection passed, never GO.

Encoding: UTF-8 sorted compact Python JSON, ensure_ascii=false, allow_nan=false.
Domain-separated checksum: SHA256(b"OLA/decision-report/v2\\0" + encoded body),
where \\0 denotes one NUL byte and body excludes report_sha256. This is explicitly
not RFC 8785. RFC 8785 and Ed25519 belong to the subsequent Evidence-Stream contract.

Run:

    python -m pytest tests/test_decision_report_v2.py tests/test_decision_report.py tests/test_decision_report_verifier.py tests/test_nina_run_endpoint_contract.py tests/test_nina_igor_chain.py tests/test_human_approval_integrity.py tests/test_atomic_human_gate.py tests/test_replay.py tests/test_contradiction_replay.py
    python scripts/inspect_decision_report_v2.py report.json

Remaining ADR work: canonical signed Evidence-Stream; independently controlled
trust root and verifier receipts; policy/source/approval authorization checks;
replay protection and external checkpoint; full adversarial tests and benchmarks.
This local report format alone cannot detect an attacker rewriting and resealing
an entire report. This is an explicit trust boundary, not an attestation feature.
