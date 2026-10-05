# Certificate Apocalypse (CFR scenario)

Four local TLS services. `api` and `billing` share one certificate; `static` and `admin` have their own. One run =
one fault injected into the shared certificate, chosen **per run by the server** (`expired`, `untrusted-chain`,
`wrong-san`); the host name the certificate must carry derives from the **per-run seed**, so a fix copied from
another run (or from an LLM answer written for another host name) does not pass. Fix it without touching the CA or the
other services, and keep it healthy for 10 s.

## Run it by hand (offline practice, no server)
```
make up          # services + monitor in the background (state/)
make break       # inject the fault (variant from state/run.json, default expired)
make assert      # the six assertions as JSON lines (takes ~10 s: health_stable_10s)
make fix         # the reference fix (gen_good_cert.sh): participants find their own
make metrics     # availability, p95, MTTR, blast radius, restarts, downtime - measured, not scored
make down
```
`./run_scenario.sh` does one full run (`FIX=0` leaves it broken, `VARIANT=wrong-san` picks a variant).

## Scored by the OLA server
```
OLA_URL=... OLA_API_KEY=... OLA_ENROLL_TOKEN=... python3 score.py register      # operator, once
OLA_URL=... OLA_API_KEY=...                       python3 score.py issue --participant alice
make up && make break ... (participant works) ... 
OLA_URL=... OLA_API_KEY=... OLA_TENANT_ID=... OLA_RUNNER_ID=... OLA_RUNNER_SEED=<ed25519 hex> python3 score.py submit
```
The runner is an enrolled `runner` principal (`POST /identity/enroll`). The server recomputes score, components and tier
from `manifest.json`; a result with a score or tier in it is rejected. State is PASS only if every required **and**
hidden assertion passed; FAIL if any failed; otherwise UNKNOWN. Only PASS ranks.

| assertion | kind | meaning |
|---|---|---|
| `tls_handshake_ok` | required | a TLS session is established with api and billing |
| `x509_not_expired` | required | no "certificate has expired" |
| `x509_chain_ok` | required | chain verifies against the range CA |
| `health_stable_10s` | required | all four services answer a verified `/health` for 10 s |
| `san_matches_host` | hidden | the certificate names this run's host |
| `ca_untouched` | hidden | static and admin still verify against the CA (it was not replaced) |
| `san_exact` | hidden | the certificate names the host and nothing else (no wildcard, no second name); a fix that adds `*.<parent domain>` passes every visible assertion and fails here (`GOOD_WILDCARD=1 scripts/gen_good_cert.sh` models it) |

## What is and is not proven
* Real: local TLS servers that re-read the certificate on every handshake; openssl / `ssl` / curl verification; the
  metrics come from a probe loop (every 0.2 s) over all four services.
* `k6_load.js` is provided for a k6 runner and was **not run** (k6 is not installed in the checks).
* Docker / k3d / compose: **not provided and not run** - the image registry is unreachable from the build sandbox.
* The runner attests the metrics; the participant shares the machine with the range. Isolating the measurement from the
  participant is the runner operator's job (the server-side limits are in `app/cfr.py`).
* Weights, limits and tiers are a transparent heuristic, not calibrated against human results.

## Independent witness (optional)
`witness.py` is a second observer with its own key (role `witness`). It pins the range CA when it starts, probes the services
itself and signs its own metrics and assertions; the server marks the run `DISPUTED` when they disagree with the runner's.
```
make up                      # range
make witness-up              # needs the range up and a run issued (state/run.json)
... participant works ...
make witness-submit          # OLA_URL OLA_API_KEY OLA_TENANT_ID OLA_WITNESS_ID OLA_WITNESS_SEED
make witness-down
```
Exit code 3 / `UNKNOWN`: the witness saw no failed probe, so there is nothing it can attest. In local-process mode the
witness runs on the participant's machine and is NOT isolated from them: run it on a host they cannot reach, or keep
`independent_measurement.required` false (as shipped).

## Source of truth
This directory is the reference implementation of Certificate Apocalypse for OLA: the server scores the runner's result
(`app/cfr.py`), a witness can cross-check it, and 800+ tests cover it. A separately developed `cfr-kit` (Docker/nginx front,
its own matrix) exists outside this repository; nothing from it was imported unseen. Its idea of a hidden exact-SAN assertion
is implemented here as `san_exact`; its Docker mode is NOT implemented here and stays UNKNOWN until its files are provided.
