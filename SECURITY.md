# OLA Security Policy

## Scope

This policy covers the OLA runtime, evidence chain, agent execution, provenance, replay verification, human gate, CI/CD release gates, and published release artifacts.

## Supported versions

Only the current protected release line on `main` is supported. Development branches are not production releases and must not be used as production evidence.

## Security invariants

- Fail closed: an unknown or unverifiable state cannot become `ALLOW` or `VERIFIED`.
- Human approval is independent of caller-provided approval fields.
- Evidence-chain tampering must be rejected.
- Provenance mismatch must block promotion.
- Replay must independently verify the captured chain.
- Production promotion requires the final production gate.
- Release source and release artifacts are attested and independently verifiable in CI.

## Release evidence

A production release must retain the final production evidence bundle, including:

1. exact source commit;
2. source snapshot SHA-256;
3. signed GitHub build provenance attestation for the source snapshot;
4. release image SHA-256;
5. signed build provenance attestation for the release image;
6. CI, state-continuity, stability, provenance, runtime, stress, tamper and replay results;
7. final production manifest.

## Vulnerability reporting

Report suspected vulnerabilities privately to the repository maintainers through the repository's configured private security reporting channel. Do not disclose credentials, API keys, customer data, or exploitable proof-of-concept details in public issues.

If a private reporting channel is not configured, repository maintainers must configure GitHub private vulnerability reporting before declaring the project production-ready.

## Incident response

Security incidents must be classified, contained, evidenced, remediated, and independently verified before the affected release is promoted again. Evidence must preserve the original failing state and the remediation proof.

## Secrets and keys

Production credentials must not be committed to the repository. Keys used for release signing or external services must be rotated after suspected exposure. CI must use short-lived identity where supported and must not treat a static secret as proof of source provenance.

## Security claims

CI success is evidence for the executed checks only. It is not a claim of absolute security or immunity from compromise. `UNKNOWN` remains `UNKNOWN` until independently verified.
