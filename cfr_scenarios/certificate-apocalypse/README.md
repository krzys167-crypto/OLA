# Certificate Apocalypse (CFR scenario)

Four TLS services (local processes, or one container each). `api` and `billing` share one certificate; `static` and `admin` have their own. One run =
one fault injected into the shared certificate, chosen **per run by the server** (`expired`, `untrusted-chain`,
`wrong-san`); the host name the certificate must carry derives from the **per-run seed**, so a fix copied from
another run (or from an LLM answer written for another host name) does not pass. Fix it without touching the CA or the
other services, and keep it healthy for 10 s.

## Run it by hand (offline practice, no server)
```
make up          # services + monitor in the background (state/)
make break       # inject the fault (variant from state/run.json, default expired)
make assert      # the seven assertions as JSON lines (takes ~10 s: health_stable_10s)
make fix         # the reference fix (gen_good_cert.sh): participants find their own
make metrics     # availability, p95, MTTR, blast radius, restarts, downtime - measured, not scored
make down
```
`./run_scenario.sh` does one full run (`FIX=0` leaves it broken, `VARIANT=wrong-san` picks a variant).

## Run it in containers (docker compose)
```
make docker-up       # builds the image, starts init, api, billing, static, admin, monitor; returns when all four answer
make break           # the SAME targets as above, on the host, against ./state:
make assert          #   break / assert / fix / metrics / score / witness-*
make fix
make metrics
make docker-restart  # restarts api and billing; a restart costs a penalty and is OBSERVED (see below)
make docker-logs
make docker-down
```
One image, six roles (`docker/compose.yaml`): `init` (leaf certificates, `ports.json`, the `up` event), one TLS server per
service, and a `monitor` that probes all four over the compose network with the same verified probe as process mode. What
the container mode changes: every service has its own network namespace and its own process; the monitor is not the
participant's shell; services run as the host user's uid:gid, read-only, with no capabilities, and see only the
certificate **directory**, read-only (a directory, so that `make fix` replacing `server.pem` by rename is seen without a
restart). Ports are published on `127.0.0.1` only: 18441 api, 18442 billing, 18443 static, 18444 admin (`CFR_PORT_API` ...
override). Use one mode at a time: both write `./state`.

**Restarts are observed, not announced.** Every server instance answers `/health` with a fresh `boot=` token; the monitor
records it in `timeline.jsonl`. `restarts` is the larger of the announced `restart` events and the most often any ONE service
changed its token, so `docker restart api` by hand costs the same penalty as `make docker-restart`. Restarting api and billing
once each is one restart (the most-restarted service was restarted once), as the process-mode restart of all four is one.

## Scored by the OLA server
```
OLA_URL=... OLA_API_KEY=... OLA_ENROLL_TOKEN=... python3 score.py register      # operator, once
OLA_URL=... OLA_API_KEY=... OLA_RUNNER_ID=...   python3 score.py issue --participant alice   # binds the run to that runner
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
* Container mode (docker compose) is built and measured by the CI job `cfr-docker` (`.github/workflows/cfr-docker.yml`):
  baseline passes, the fault is visible, the fix passes all seven assertions, metrics from the monitor container, an
  independent witness on the host agrees within the manifest tolerance, a hand restart is observed, `k6_load.js` runs through
  the `grafana/k6` image with the chain and the host name verified. The result of that job is the check status of the pull
  request, not a claim in this file. The offline tests (`tests/test_cfr_containers.py`) run the container ROLES as processes;
  they cannot show that Docker accepts `compose.yaml` or that the image builds.
* k6 image: pinned by tag, not by digest (the digest the runner pulled is published as a notice by the job).
* k3d / Kubernetes: **not provided and not run.**
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
`independent_measurement.required` false (as shipped). In container mode the witness still runs on the host (it probes the
published ports): independent of the monitor container, not of the participant.

## Source of truth
This directory is the reference implementation of Certificate Apocalypse for OLA: the server scores the runner's result
(`app/cfr.py`), a witness can cross-check it, and 800+ tests cover it. A separately developed `cfr-kit` (Docker/nginx front,
its own matrix) exists outside this repository; nothing from it was imported unseen. Its idea of a hidden exact-SAN assertion
is implemented here as `san_exact`; its Docker/nginx front is NOT imported (the compose mode here is this repository's own,
stdlib TLS servers) and stays UNKNOWN until its files are provided.
