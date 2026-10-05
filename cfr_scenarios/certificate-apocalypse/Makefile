# Certificate Apocalypse (CFR scenario). Local-process mode. Docker/k3d: not provided here (UNKNOWN).
STATE ?= state
PY    ?= python3
CD    := cfr_range.py --state $(STATE)

.PHONY: up break fix assert score metrics restart down brief
up:        ; $(PY) $(CD) up
break:     ; $(PY) $(CD) break
fix:       ; CERT_DIR=$(STATE)/certs HOST=$$($(PY) $(CD) host) ./scripts/gen_good_cert.sh
assert:    ; STATE=$(STATE) HOST=$$($(PY) $(CD) host) ./assertions.sh
metrics:   ; $(PY) $(CD) metrics
score:     ; $(PY) score.py --state $(STATE) preview
restart:   ; $(PY) $(CD) restart
down:      ; $(PY) $(CD) down
brief:
	@echo "Two of four services (api, billing) fail TLS verification. Find out why and fix it WITHOUT touching the CA"
	@echo "or the other services. Verify with: make assert. A restart works but costs a penalty."
