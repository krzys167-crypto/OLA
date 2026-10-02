# OLA di-OS Evidence Chain Policy

## Canonical source identity

`SOURCE_SHA` is the only canonical correlation key for runtime, provenance, replay and production evidence.

- Pull request: `SOURCE_SHA = github.event.pull_request.head.sha`.
- Production: `SOURCE_SHA = github.sha` on a workflow triggered by `main`.
- `GITHUB_SHA` as the pull-request merge ref is never accepted as the source identity.

## Signature policy

The exact `SOURCE_SHA` being evaluated must have GitHub commit verification status `verified=true`.

This means:

- pre-merge proof is bound to the signed PR head;
- post-merge production proof is bound to the signed commit currently at `main`;
- an unsigned exact source SHA remains BLOCKED.

## Runtime/provenance binding

Every six-agent evidence record carries `source_commit`.

The standalone verifier must compare every evidence record's `source_commit` to the expected `SOURCE_SHA`; a caller-provided expected SHA alone is not sufficient.

## Real LLM response identity

The runtime records:

- `response_id` only when the provider actually supplies an identifier;
- `response_digest` as a local cryptographic fingerprint of the provider response body.

A locally generated digest is never presented as a provider-issued response ID.

## LLM causality

For real LLM execution, the CodeAct result is taken from the model's structured proposal after independent safe-expression validation. A wrong or malformed model proposal blocks the run instead of silently falling back to a deterministic result.

## Human Gate

`Human Gate = VERIFIED` is reserved for a separate external approval record.

A contract or CI assertion cannot self-certify human approval. Automated production evidence therefore remains `REVIEW_REQUIRED` until an independent human approval is recorded.

## Freeze anchoring

The final gate creates `freeze-anchor.json` from the canonical `SOURCE_SHA` and the correlation-manifest digest, then records and independently verifies an artifact attestation. This is the immutable freeze checkpoint for the observed evidence set.

## External evidence still required

The following are runtime evidence obligations, not code claims:

- one registered run executed on the physical ZBook;
- real usage/request export containing model/request/token/cost identifiers;
- an independently retained copy of that usage/cost export.

Until those are captured, they remain UNKNOWN / NOT VERIFIED.