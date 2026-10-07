#!/usr/bin/env bash
# Non-interactive demo of one run: up -> break -> fix -> assert -> metrics. FIX=0 leaves it broken (a failing run).
# The score is computed by the OLA server (score.py submit), not here. `make score` prints a labelled preview.
set -euo pipefail
cd "$(dirname "$0")"
export STATE="${STATE:-state}"; FIX="${FIX:-1}"; STABLE_S="${STABLE_S:-10}"
rm -rf "$STATE"; python3 cfr_range.py --state "$STATE" up
sleep 2
python3 cfr_range.py --state "$STATE" break --variant "${VARIANT:-expired}"
sleep 3
[ "$FIX" = 1 ] && CERT_DIR="$STATE/certs" HOST="$(python3 cfr_range.py --state "$STATE" host)" ./scripts/gen_good_cert.sh
sleep 1
HOST="$(python3 cfr_range.py --state "$STATE" host)" STABLE_S="$STABLE_S" ./assertions.sh
python3 cfr_range.py --state "$STATE" metrics --stable-s "$STABLE_S" || true
python3 cfr_range.py --state "$STATE" down
