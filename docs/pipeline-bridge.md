# Pipeline bridge: NINA → OLLAMA → EVIDENCE → IGOR → GATE → REPLAY

`ola_pipeline/` is a generate → evaluate → improve pipeline (max 3 iterations) that talks to a real
model runtime and writes a hash-chained evidence vault. `app/pipeline_bridge.py` joins it to what OLA
already has. **No existing component was modified** (`hashchain`, `EvidenceRecord`, `NinaOrchestrator`,
`NinaIgorChain`, `HumanGate`, `replay`, `decision_report` are used as they are); `main.py` only gained
two routes.

```
POST /pipeline-run
  NinaOrchestrator.plan  (deny-by-default tools; empty task / bad tenant → nothing runs)
  → ola_pipeline.Pipeline.run     real Ollama / OpenAI call, envelopes, Igor judge, canary, Gate
  → anchor_session                ONE `pipeline.anchor` record in the tenant's hash chain
  → verify_anchor                 standalone verifier on disk + tenant chain + anchor comparison
  → NinaIgorChain.finalize        existing terminal rule + HumanGate (human cannot promote UNKNOWN)
  → replay_from_anchor            existing build_replay / verify_replay over the sealed anchor
  → build_decision_report         existing policy report (OLA-POLICY-v1)
GET  /pipeline-session/{id}       the same independent re-verification later; foreign tenant → 404
```

## State mapping (single place: `pipeline_bridge.map_states`)

| pipeline Gate | standalone verifier | OLA IGOR status | terminal |
|---|---|---|---|
| PASS | VERIFIED | VERIFIED | VERIFIED only with explicit human approval |
| PASS | PARTIAL / CONSISTENT / other | UNKNOWN | BLOCK |
| REVIEW_REQUIRED | any but FAILED | UNKNOWN | BLOCK |
| BLOCKED | any | BLOCK | BLOCK |
| any | FAILED | BLOCK | BLOCK |
| unrecognised value | – | BLOCK | BLOCK |

## What the anchor adds

The session vault is a file-system hash chain. It detects edits, but a *consistent* regeneration of a
whole session under the same `session_id` is internally valid. The anchor (`chain_head`, SHA-256 of
`final.json`, summary of every envelope) lives in the tenant's append-only chain, so such a rewrite no
longer matches (`test_consistent_rewrite_of_a_session_is_caught_by_the_anchor`: the standalone verifier
says VERIFIED for the forgery, the anchor says BLOCK).

Optional Ed25519 signing (`OLA_SIGNING_KEY_FILE`) and pinning (`OLA_PIPELINE_TRUSTED_KEY`) are
described in the `ola_pipeline` verifier; a configured pin makes a missing/foreign signature a BLOCK.
A malformed pin is a 503, never silently ignored. `requirements.txt` now includes `cryptography`, so signing
uses its constant-time Ed25519; the pure-Python fallback (not constant-time, unaudited) exists only for
environments without it, and each attestation records which one signed (`signer_impl`).

## Configuration

| variable | meaning |
|---|---|
| `OLA_NINA_PROVIDER` / `_MODEL` / `_BASE_URL` | `ollama-local` (default), `ollama-cloud`, `openai`; **model is never defaulted** |
| `OLA_IGOR_PROVIDER` / `_MODEL` | judge; same model as Nina is refused unless `OLA_ALLOW_SAME_MODEL_IGOR=1` |
| `OLA_NINA_THINK`, `OLA_IGOR_THINK` | `0`/`1` for reasoning models (see "Observed" below) |
| `OLA_PIPELINE_VAULT_DIR` | per-tenant vault root (default `./ola_pipeline_evidence`, `/data/pipeline-evidence` in the image) |
| `OLA_SIGNING_KEY_FILE`, `OLA_PIPELINE_TRUSTED_KEY` | sign sessions / pin the accepted public key |
| `OLA_PIPELINE_MAX_CONCURRENCY` | runs in flight per process (default 4). Over the limit → HTTP 429 + `Retry-After`; an invalid value → 503, never "unlimited" |
| `OLA_PIPELINE_MAX_TASK_CHARS` | longest accepted task (default 8000) → HTTP 400 before any model call |

## Verification status

| claim | status | how |
|---|---|---|
| Existing OLA suite unchanged | VERIFIED (sandbox) | 71 tests, same before and after; `scripts/verify_readme_claims.py` passes |
| Vendored pipeline suite inside the repo | VERIFIED (sandbox) | 69 pass + 3 live skipped |
| Whole repo in a clean venv built from `requirements.txt` only | VERIFIED (sandbox) | 195 passed, 4 skipped (all four are live-Ollama tests) |
| Bridge logic, fail-closed paths, tenant isolation, anchor tamper detection | VERIFIED (sandbox, Ollama test double) | 55 tests; mutation check: 20 mutants of the bridge/endpoints, all detected |
| Real runtime through `/pipeline-run` (in-process `TestClient`) | OBSERVED locally, not in CI | Ollama 0.35.1, Qwen3-0.6B (digest `0f23c3d6f2e5…`), same model as judge by explicit opt-in. `THINK=1`: 3/3 runs VERIFIED. `THINK=0`: 4/4 REVIEW_REQUIRED → BLOCK (the judge accepted the canary "2 + 2 = 5") |
| Real HTTP server (uvicorn) from a clean venv holding only `requirements.txt` + `app/` + `ola_pipeline/` | OBSERVED locally, not in CI | 4 requests (3 in flight for one tenant, 1 for another), `THINK=1`: 4× HTTP 200, 3 VERIFIED + 1 REVIEW_REQUIRED → BLOCK. Tenant chains valid and contiguous, 3+1 anchors, `GET /pipeline-session` re-verification matches, foreign tenant → 404. Anchors landed at different times, so this did **not** stress the append-retry path (the thread test does) |
| `.github/workflows/pipeline-bridge.yml` | **UNKNOWN** (statically clean) | `actionlint` 1.7.7 with `shellcheck` 0.11.0 report nothing; never executed on GitHub |
| Docker image build | **UNKNOWN** | a daemon could be started, but the base image could not be pulled (`registry-1.docker.io` is blocked here). Substitute: the clean-venv server run above |
| `ollama-cloud` / `openai` providers | **UNKNOWN** | code written from documentation, never run |
| Independent, stronger judge | **UNKNOWN** | only one small model was available |

## Limits that remain

* The anchor is in the same database as the other OLA records. Someone who can rewrite both the vault
  directory and the SQLite file (and recompute the chain) is not detected. An external anchor or
  timestamp authority is not implemented.
* A PASS means "process evidence intact and the judge rejected a known-wrong canary". It is not proof
  the answer is correct. With the judge equal to the generator it is weaker still.
* `signed_at` is the signer's own clock; there is no key revocation list; rolling a vault back to an
  older (validly signed, still anchored) state is only visible through the anchor, not the signature.

## Observed in the baseline (not changed here)

* `agent_runtime._invoke_llm` defaults to `openai` and, without a key and outside
  `OLA_LLM_MODE=required`, silently falls back to `deterministic-runtime-v1` even if a local Ollama is
  running. `/nina-run` therefore reports `invocation_type: local_deterministic_model` by default.
* `IgorVerifier` checks provenance fields (`provider`, `model`, `commit`) that the same process wrote;
  it verifies consistency, not independent observation of the runtime. `/pipeline-run` records the
  model digest and runtime proof taken from the Ollama API by the pipeline itself.
* The GitHub repository `ola-evidence-gateway` contains only a README and a devcontainer. The
  evidence store used here is the one inside this repository (`EvidenceRecord`).
