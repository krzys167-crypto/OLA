# CFR scenario DSL v0

A scenario is one YAML file. `cfr_scenarios/certificate-apocalypse/scenario.yaml` is the first and the reference. Everything
here is measured by `tests/test_cfr_dsl.py` or labelled otherwise; anything not measured is UNKNOWN.

## What it is, and what it is not

* It **describes** a scenario in one place and is **checked against** the code that runs it (`cfr_range.py`,
  `docker/compose.yaml`, `k6_load.js`, `scripts/gen_bad_cert.sh`, `assertions.sh`, `score.py`). It does **not** generate or
  drive the range: the range still has its own constants, and a test fails when the two disagree.
* It **generates** `manifest.json`. The manifest is what the server registers and pins by digest, so a scenario cannot
  change what runs are scored against without a visible diff there. `variants` keep the order of `faults` because the server
  picks the variant by index: reordering faults is a new scenario version.
* v0 declares only what a runner can honour. A fault kind, traffic tool or evidence collector no runner implements is not in
  the schema, so it cannot be declared (a mode that is not provided lists no files; k3d is declared `not_provided`).

```
python3 cfr_scenarios/dsl/cfr_dsl.py validate cfr_scenarios/certificate-apocalypse/scenario.yaml
python3 cfr_scenarios/dsl/cfr_dsl.py manifest cfr_scenarios/certificate-apocalypse/scenario.yaml --check cfr_scenarios/certificate-apocalypse/manifest.json
make -C cfr_scenarios/certificate-apocalypse dsl-check
```
Exit 0 valid, 1 invalid or drifted, 2 UNKNOWN (PyYAML or jsonschema missing: nothing was checked, never a pass).

## Keys

| key | declares | enforced / consumed by | checked by |
|---|---|---|---|
| `dsl_version` | `"0"` | schema `const` | schema |
| `meta` | id, version, title, difficulty, brief | manifest `scenario_id`, `version` | manifest equality |
| `env` | `modes` (process, docker, k3d: `provided` + files, or `not_provided`), `seed`, `user_mutation`, container `limits` | `cfr_range.py`, `compose.yaml`, `POST /cfr/runs` | host template vs `host_for()`, limits vs compose, files exist |
| `services` | name, TLS certificate file, container and host ports | `cfr_range.py` (`PEM`), compose | vs `SERVICES`, `PEM`, compose `ports` |
| `faults` | id, kind, target services, per-kind `params`, injector script | `gen_bad_cert.sh`; manifest `variants` | ids and order vs `VARIANTS`; dates and SAN prefix vs the script |
| `traffic` | the monitor's `probe` (scored) and the k6 `load` (second source, `scored: false`) | monitor, `k6_load.js` | vs `INTERVAL_S`, k6 options and thresholds |
| `tasks` | brief and constraints, each with its owner (`assertion:<id>` or `scoring:<key>`) | the participant sees `visible: true` ones | owner resolves |
| `scoring` | weights, limits, penalties, tiers | `app/cfr.py` recomputes score and tier from the manifest | sum = 1, monotone limits, tiers ascending, server `validate_manifest` |
| `assertions` | `required` or `hidden`, observed services, `window_s` | `assertions.sh`; manifest lists | ids = what the script emits; `health_stable_Ns` waits N s |
| `evidence` | collected files, ed25519 signing, optional witness and tolerance | `score.py`, `witness.py`, server reconcile | collectors = `artifact_digests()` |
| `hints` | `after_s` + text | **not served by the v0 runner** (declared) | strictly increasing; names no hidden assertion |

Extension keys start with `x-` and are ignored. Unknown keys are errors.

## Anti-LLM mechanisms (what is real)

The aim is to measure the operator-plus-AI, not to keep AI out: a participant who drives an agent through `make assert` and
`openssl` is a legitimate participant, and **this scenario can be solved that way**. What the mechanisms prevent is a fix
copied from somewhere else.

| mechanism | status | what it stops | limit |
|---|---|---|---|
| host name derived from the per-run seed (`svc-<6 hex>.range.test`) | implemented | a certificate or command copied from another run or answer | the participant sees this run's host (`make` prints it), so an agent working in the run has it; 6 hex = 2^24 names |
| fault variant chosen by the server | implemented | one memorised fix | 3 variants only |
| hidden assertions (`san_matches_host`, `ca_untouched`, `san_exact`) | implemented | the "make the visible checks pass" fix, e.g. a wildcard SAN (`GOOD_WILDCARD=1` models it) | **hidden in the run output, not in the repository**: the ids and the check are public here. A private scenario repository or server-side scenario is needed for this to hold against someone who reads the source |
| stability window (`health_stable_10s`) | implemented | a fix that holds for one probe | 10 s |
| restarts observed from the `boot=` token | implemented | a restart that is not announced | costs 0.05 per restart, it does not forbid it |
| signed result, server-side scoring, manifest pinned by digest | implemented | an edited score or scoring rules | the runner attests the metrics (see below) |
| multi-step tasks, per-user log noise, different evidence per user | **not built** | – | Certificate Apocalypse is one task |

## Measurement

| metric | source | definition (`cfr_range.compute_metrics`) |
|---|---|---|
| availability | monitor probes, every 0.2 s, all four services, chain and host name verified | successful probes / all probes of the whole run (the pre-fault baseline is in the denominator) |
| latency p95 | the same probes | 95th percentile of successful ones |
| MTTR | `fault_injected` event to the start of the first window of `stable_s` in which every service is healthy in every round | `null` = never recovered |
| blast radius | probes of the services no fault targets | number of them that failed at least once after the injection |
| restarts | `boot=` token in `/health` plus announced `restart` events | the most often any ONE service restarted |
| downtime | probe rounds | time with at least one service failing |
| load numbers | k6 (`k6_load.js`, CI job `cfr-docker`) | second, independent source; **not scored** |

Independence: the container-mode monitor is a separate container; the witness (`witness.py`, own key) probes from the host
and the server marks the run `DISPUTED` when it disagrees beyond `tolerance`. The `fault_injected` timestamp is written by the
participant-side `make break`, and in process mode the monitor shares the participant's machine. Whether the weights and tiers
rank people sensibly is **UNKNOWN**: they are a transparent heuristic, not calibrated against human runs.

## Migration to v1 (plan, nothing below is built)

1. **Keep the contract.** `dsl_version` is an exact major. A v1 runner reads v0 through `upgrade_0_to_1(doc)`; the manifest
   generated from the upgraded document must equal the v0 one, or it is a new scenario version (the digest is pinned).
2. **Kinds as plugins.** The `allOf`/`if` chain per fault kind moves to a registry: each fault, assertion and collector
   ships its own params schema and an implementation entry point, and `scenario.schema.json` is assembled from the registry.
   Kinds in the original wish list that exist nowhere today: `invalid_truststore`, `time_skew`, `dns_poison`, `kafka_lag`,
   `cpu_throttle`; collectors `bash_history`, `kubectl_trace`, `otel_spans`. Each becomes declarable only together with its code.
3. **Generate, don't mirror.** The artifact generator that now produces `manifest.json` also produces `compose.yaml` and, once a
   k3d mode exists, its manifests from `services`/`env.limits`, replacing the drift tests with generation.
4. **Serve hints** and put their cost into `scoring`.
5. **Conformance suite.** Golden `(scenario.yaml, manifest.json)` pairs per DSL version, run by every runner.

## Not done / UNKNOWN

* k3d / Kubernetes: not provided, not run. `env.modes.k3d` says so, and a test fails if k3d/Kubernetes files appear in the scenario directory, so adding the mode means changing the DSL and that test together.
* CI: `tests/test_cfr_dsl.py` needs PyYAML and jsonschema (neither is in `requirements.txt`) and skips test by test without
  them. `cfr-docker.yml` (own step, a skip fails it) and `controls.yml` (control EC-17: a skipped test makes the control
  FAILING) install both with pinned versions. Checked locally, including that without jsonschema only EC-17 turns FAILING.
  Whether it is green **on a runner** is UNKNOWN: at the time of writing GitHub Actions assigned no runner to any job of
  this repository, `main` included. Elsewhere (plain `pytest -q`) the tests still skip silently.
* Hints are declared, not served. The estimate `estimated_minutes: 20` is the author's, not measured.
