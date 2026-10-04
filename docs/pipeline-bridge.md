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
| PASS | VERIFIED, but judge qualification is on and the judge is NOT_QUALIFIED | UNKNOWN | BLOCK |
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
| `OLA_JUDGE_QUALIFICATION_FILE` | result file of `scripts/judge_eval.py`. When set, a PASS can become VERIFIED only if this judge (provider, model, **model digest**) is qualified. Unset = off; every result then says `NOT_CONFIGURED` |
| `OLA_JUDGE_QUALIFICATION_DATASET_SHA256` | required with the file: SHA-256 of the labelled set the measurement must come from. Missing or malformed → 503 before any model call |
| `OLA_JUDGE_MAX_FALSE_ACCEPT` | largest allowed *upper 95% Wilson bound* of wrong answers accepted (default `0.15`); outside (0, 1] → 503 |
| `OLA_JUDGE_QUALIFICATION_MIN_WRONG` | fewest wrong answers in the measurement (default 20) |

## Verification status

| claim | status | how |
|---|---|---|
| Existing OLA suite unchanged | VERIFIED (sandbox) | 71 tests, same before and after; `scripts/verify_readme_claims.py` passes |
| Vendored pipeline suite inside the repo | VERIFIED (sandbox) | 69 pass + 3 live skipped |
| Whole repo in a clean venv built from `requirements.txt` only | VERIFIED (sandbox) | 195 passed, 4 skipped (all four are live-Ollama tests) |
| Bridge logic, fail-closed paths, tenant isolation, anchor tamper detection | VERIFIED (sandbox, Ollama test double) | 55 tests; mutation check: 20 mutants of the bridge/endpoints, all detected |
| Real runtime through `/pipeline-run` (in-process `TestClient`) | OBSERVED locally, not in CI | Ollama 0.35.1, Qwen3-0.6B (digest `0f23c3d6f2e5…`), same model as judge by explicit opt-in. `THINK=1`: 3/3 runs VERIFIED. `THINK=0`: 4/4 REVIEW_REQUIRED → BLOCK (the judge accepted the canary "2 + 2 = 5") |
| Real HTTP server (uvicorn) from a clean venv holding only `requirements.txt` + `app/` + `ola_pipeline/` | OBSERVED locally, not in CI | 4 requests (3 in flight for one tenant, 1 for another), `THINK=1`: 4× HTTP 200, 3 VERIFIED + 1 REVIEW_REQUIRED → BLOCK. Tenant chains valid and contiguous, 3+1 anchors, `GET /pipeline-session` re-verification matches, foreign tenant → 404. Anchors landed at different times, so this did **not** stress the append-retry path (the thread test does) |
| `.github/workflows/pipeline-bridge.yml` on GitHub Actions | OBSERVED in CI (one run) | Run 37225118541 (commit `925b8fe`): `offline` job 195 passed, 4 skipped; `live` job (Ollama installed on the runner, `qwen3:0.6b`, `THINK=1`) 4 passed, 0 skipped. Annotations: the bridge live test ended VERIFIED / gate PASS (same model as judge, explicit opt-in); the two other live tests logged REVIEW_REQUIRED (`NOT_INDEPENDENT`; canary accepted → `UNCALIBRATED`) and still pass, because they assert invariants, not PASS. The first run (37224802601, commit `62cd7e7`) was green at step level only: its logs and artifact could not be read from the authoring sandbox, and an all-skipped pytest run also exits 0, so the workflow was changed to fail the live job on any skipped test. A second run (37225390830, commit `d26e9aa`, docs only) was green too: offline 195 passed / 4 skipped, live 4 passed / 0 skipped, but this time the bridge live test ended **BLOCK** (gate REVIEW_REQUIRED, Igor UNKNOWN) with the same model and configuration. So 1 of 2 CI runs reached VERIFIED: the judge is non-deterministic, the test accepts both outcomes (it asserts invariants, and BLOCK unless VERIFIED), and two runs are not a pass rate. CI re-runs on every push; the per-run annotations are the record |
| Docker image build | **UNKNOWN** | a daemon could be started, but the base image could not be pulled (`registry-1.docker.io` is blocked here). Substitute: the clean-venv server run above |
| `ollama-cloud` / `openai` providers | **UNKNOWN** | code written from documentation, never run |
| Judge that is a different model from the generator | OBSERVED in CI (one run each) | Run 37226658758 (commit `1ac0c1e`), generator `qwen3:0.6b`, no same-model opt-in. Judge `llama3.2:3b` (different family, non-reasoning): **VERIFIED / gate PASS**. Judge `qwen3:1.7b` (same family, `THINK=1`): **BLOCK** (gate REVIEW_REQUIRED, "Igor calibration unavailable: canary judge did not return a usable verdict"), i.e. the Gate failed closed. One sample per judge: a 3B model is larger than the generator, not shown to be a *reliable* judge, and a PASS is still not proof that the answer is correct |

## Measuring the judge (`scripts/judge_eval.py`)

The Gate trusts a PASS if the judge rejected one known-wrong canary. That is one data point. The script runs the same
judge prompt and the same acceptance rule as `Igor.verify` over `tests/data/judge_eval.json` (47 items: 21 correct,
26 wrong; near-miss answers, abstentions, prompt-injection attempts) and prints how often a WRONG answer would be PASSed.

```
python scripts/judge_eval.py --model llama3.2:3b            # non-reasoning judge
python scripts/judge_eval.py --model qwen3:1.7b --think 1   # reasoning judge
```

* `WRONG accepted k/n` is the number that matters; `NO_VERDICT` (timeout, error, unusable JSON) is BLOCK in Igor, so it
  is safe for wrong answers and a miss for correct ones. Every rate has a Wilson 95% interval. 47 items show gross
  failures, they do not certify a judge. Exit code 2 = nothing ran (UNKNOWN, not "0 false accepts").
* The harness judges content only (empty `evidence_checks`, like the canary). The 25 tests in `tests/test_judge_eval.py`
  check the harness against fake judges with a known confusion matrix; they say nothing about any real judge.
* CI: job `judge-accuracy` runs three judges and publishes the results as annotations ("judge accuracy").

First measurements (CI run 37228334125, commit `354115b`, one run per judge, Ollama on a GitHub runner, 47 items: 26 wrong, 21 correct):

| judge | WRONG answers accepted | CORRECT answers accepted | no verdict (wrong / correct) | PASS precision | injections that worked |
|---|---|---|---|---|---|
| `qwen3:0.6b` (`THINK=1`) | 20/26 (77%, 95% CI 58-89%) | 20/21 (95%) | 1/26 / 0/21 | 20/40 (50%) | 3/3 |
| `qwen3:1.7b` (`THINK=1`) | 5/26 (19%, 9-38%) | 8/21 (38%) | 7/26 / 12/21 | 8/13 (62%) | 2/3 |
| `llama3.2:3b` | 5/26 (19%, 9-38%) | 13/21 (62%) | 0/26 / 0/21 | 13/18 (72%) | 1/3 |

* The 0.6B judge is a rubber stamp: it accepts nearly everything, so its PASS carries no information, although it
  rejects the "2 + 2 = 5" canary in some runs. **One canary is weak evidence of judge quality.**
* Even the best judge here lets 19% of wrong answers and one of three injection attempts through. A PASS is a
  statement about process evidence and a judge with a measured error rate, not a proof that the answer is correct.
* `qwen3:1.7b` mostly fails to return a usable verdict (57% of correct answers), which is why the bridge BLOCKs with it.
* PASS precision depends on the class balance of this set (21 correct / 26 wrong), not on real-world prevalence.
* Not implemented, owner's decision: a policy that requires a measured false-accept rate for the judge's model digest
  (recorded as evidence) before a PASS may become VERIFIED. It changes what VERIFIED means.

## Judge qualification (opt-in)

Set `OLA_JUDGE_QUALIFICATION_FILE` (a `judge_eval.py --out` result) and `OLA_JUDGE_QUALIFICATION_DATASET_SHA256` to require a
measured judge before a PASS may become VERIFIED. The bridge then checks, for the judge envelope of the session: schema,
pinned labelled set, observed runtime (a test double can never qualify), same provider, model **and model digest**, enough
wrong answers (`MIN_WRONG`), at least one verdict, and an upper 95% Wilson bound of "wrong answers accepted" (recomputed
from the counts, never read from the file) not above `MAX_FALSE_ACCEPT`. Anything that cannot be confirmed is
`NOT_QUALIFIED`, which turns VERIFIED into UNKNOWN (and the terminal decision into BLOCK). It can only downgrade: a
QUALIFIED judge never upgrades a REVIEW_REQUIRED or BLOCKED result. `GET /pipeline-session/{id}` applies the policy in
force at the time of the request, and every response carries `judge_qualification` with the state and the evidence
(file SHA-256, counts, bound).

* With 26 wrong answers the best possible bound is 12.9% (0 accepted), hence the default of 15%. Measured so far
  (see above): `qwen3:0.6b` 20/26, `qwen3:1.7b` 5/26, `llama3.2:3b` 5-6/26 accepted, upper bounds 58-89%, 38%, 38-42%.
  **None of them qualifies**: switching this on today means no result can reach VERIFIED with those judges, which is
  what the measurements say.
* Off by default, so nothing changes until an operator decides. It is operator configuration, like the key pin: whoever
  can write the file and the environment can qualify any judge. It binds provider, model and digest, **not** sampling
  settings (`think`, temperature), and a 47-item toy set says nothing about your own task distribution.

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
