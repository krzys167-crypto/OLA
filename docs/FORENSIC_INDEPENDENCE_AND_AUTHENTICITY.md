# OLA di-OS Forensic Independence and Authenticity Gate

## Purpose

The forensic proposal is treated as a hypothesis and collection protocol, not as proof. OLA must not promote a self-reported runtime result to `VERIFIED` merely because the runtime, manifest, or CI job says so.

The forensic closure follows:

`SOURCE -> RUNTIME -> ARTIFACT -> HASH -> INDEPENDENT VERIFY`

with explicit intermediate states for evidence that is captured but not independently authenticated.

## Required gate states

| Gate | VERIFIED means | Intermediate / failure states |
|---|---|---|
| Archive integrity | supplied ZIP and external SHA-256 file match | REVIEW_REQUIRED / BLOCKED |
| Artifact hashes | every exported file matches SHA256SUMS.txt | UNKNOWN / BLOCKED |
| Source binding | actual checkout SHA equals the expected canonical SHA in every relevant artifact | UNKNOWN / BLOCKED |
| Run correlation | runtime, provider trace, verifier and manifest share the same run_id | UNKNOWN / BLOCKED |
| Image/model digests | Docker image ID and Ollama model digest are captured as content digests | UNKNOWN / BLOCKED |
| Runtime execution | exactly six ordered real-LLM agent records exist | BLOCKED |
| Provider trace integrity | provider-boundary records match runtime response digests, model and run identity | UNKNOWN / BLOCKED |
| Timing | six agent windows are monotonic and inside the overall execution window | UNKNOWN / BLOCKED |
| Execution integrity | no skipped required gates; expected exit codes only | UNKNOWN / BLOCKED |
| Independence boundary | runtime verifier and forensic verifier are separate components | UNKNOWN / BLOCKED |
| Provider authenticity | the provider/server has an independent trust anchor | REVIEW_REQUIRED until externally authenticated |

## Important independence distinction

A verifier implemented in the same source tree can be operationally separate while still sharing the same trust root. OLA therefore records two different properties:

1. **Independence boundary** — the verifier does not import or reuse the runtime verification implementation and is a distinct component.
2. **External authenticity** — the evidence has a trust root outside the runtime path.

The first can be VERIFIED from the bundle. The second cannot be promoted to VERIFIED from a local Ollama trace and a local SHA-256 alone.

## Provider response identity

Ollama may not provide a provider-issued response identifier. OLA therefore records:

- `response_id` only when the provider actually returns one;
- `response_digest` as a local fingerprint of the complete provider response.

A response digest proves consistency of captured content. It does not, by itself, prove that the response came from an authentic provider/server.

## Physical ZBook evidence

The workstation collector now captures:

- exact source SHA;
- physical workstation metadata;
- Docker image content ID;
- Ollama model digest;
- six-agent runtime evidence;
- per-agent start/end timestamps;
- independent verifier result;
- real append-only mutation attempt;
- stability window;
- gate-by-gate exit-code/state records;
- relative-path SHA256SUMS.txt.

The collector deliberately leaves physical execution as captured evidence. The uploaded ZIP is independently reviewed before the physical run can be marked VERIFIED.

## Current canonical source

For this closure branch the forensic snapshot is:

`df9f8783248812c2c887cc9805524602f4dc3ef2`

The source-signature requirement remains separate: an exact SHA must have GitHub commit verification `verified=true` before it can satisfy the production signature gate.

## Response to the forensic proposal

The correct response is not to accept the proposal's conclusions as established facts. The response is to extract its falsifiable claims and require a corresponding independent artifact for each claim.

Any missing trust root remains `UNKNOWN` or `REVIEW_REQUIRED`; it is never silently promoted to `VERIFIED`.
