# Certificate Apocalypse (CFR scenario).
# Two modes over the SAME state directory (use one at a time): local processes (up/down) or containers (docker-up/docker-down).
# break, fix, assert, metrics, score and witness-* are the same in both. k3d / Kubernetes: not provided.
STATE ?= state
PY    ?= python3
CD    := cfr_range.py --state $(STATE)

.PHONY: up break fix assert score metrics restart down brief witness-up witness-observe witness-submit witness-down
.PHONY: docker-up docker-restart docker-down docker-logs
up:        ; $(PY) $(CD) up
break:     ; $(PY) $(CD) break
fix:       ; CERT_DIR=$(STATE)/certs HOST=$$($(PY) $(CD) host) ./scripts/gen_good_cert.sh
assert:    ; STATE=$(STATE) HOST=$$($(PY) $(CD) host) ./assertions.sh
metrics:   ; $(PY) $(CD) metrics
score:     ; $(PY) score.py --state $(STATE) preview
restart:   ; $(PY) $(CD) restart
down:      ; $(PY) $(CD) down
witness-up:      ; $(PY) witness.py --state $(STATE)-witness --range-state $(STATE) up
witness-observe: ; $(PY) witness.py --state $(STATE)-witness --range-state $(STATE) observe
witness-submit:  ; $(PY) witness.py --state $(STATE)-witness --range-state $(STATE) submit
witness-down:    ; $(PY) witness.py --state $(STATE)-witness --range-state $(STATE) down
brief:
	@echo "Two of four services (api, billing) fail TLS verification. Find out why and fix it WITHOUT touching the CA"
	@echo "or the other services. Verify with: make assert. A restart works but costs a penalty."

# ---- container mode (docker compose, docker/compose.yaml). Needs docker with the compose plugin.
COMPOSE ?= docker compose -f docker/compose.yaml
CFR_ENV  = CFR_STATE=$(abspath $(STATE)) CFR_UID=$$(id -u) CFR_GID=$$(id -g) CFR_HOST=$$($(PY) $(CD) host)
docker-up:
	$(CFR_ENV) $(COMPOSE) down --remove-orphans --timeout 5
	mkdir -p $(STATE)/certs
	$(CFR_ENV) $(COMPOSE) up -d --build --force-recreate
	$(PY) $(CD) wait --timeout 120
docker-restart: ; $(CFR_ENV) $(COMPOSE) restart --timeout 5 api billing
docker-down:    ; $(CFR_ENV) $(COMPOSE) down --remove-orphans --timeout 5
docker-logs:    ; $(CFR_ENV) $(COMPOSE) logs --no-color --tail 40
