#!/usr/bin/env bash
# Print one JSON object per assertion: {"id": ..., "result": "pass|fail|unknown"}.
# Usage: STATE=state HOST=svc-xxxx.range.test STABLE_S=10 ./assertions.sh
# Reads state/ports.json: {"api": 1234, "billing": 1235, "static": 1236, "admin": 1237}
# Affected services (share the broken certificate): api, billing. Unaffected: static, admin (own certificates).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${STATE:-state}"; HOST="${HOST:-svc-local.range.test}"; STABLE_S="${STABLE_S:-10}"
CA="$STATE/certs/ca.crt"; PORTS="$STATE/ports.json"
emit() { printf '{"id":"%s","result":"%s"}\n' "$1" "$2"; }
if ! command -v openssl >/dev/null || ! command -v curl >/dev/null || [ ! -f "$PORTS" ] || [ ! -f "$CA" ]; then
  for a in tls_handshake_ok x509_not_expired x509_chain_ok health_stable_10s san_matches_host ca_untouched san_exact; do emit "$a" unknown; done
  exit 0
fi
port() { python3 -c "import json,sys;print(json.load(open('$PORTS'))['$1'])"; }
hs=pass; exp=pass; chain=pass; san=pass; sx=pass
for svc in api billing; do
  p="$(port $svc)"
  mapfile -t kv < <("$HERE/scripts/probe_tls.sh" 127.0.0.1 "$p" "$HOST" "$CA")
  declare -A r=(); for l in "${kv[@]}"; do r["${l%%=*}"]="${l#*=}"; done
  [ "${r[handshake]:-fail}" = ok ] || { hs=fail; exp=fail; chain=fail; san=fail; sx=fail; continue; }
  # san_exact (hidden): the certificate names the host and NOTHING else: no wildcard, no second name. A "fix" that adds
  # *.<parent domain> to get the handshake through passes the visible assertions and is caught here.
  names="$(echo | timeout 8 openssl s_client -connect "127.0.0.1:$p" -servername "$HOST" 2>/dev/null \
            | openssl x509 -noout -text 2>/dev/null | sed -n '/Subject Alternative Name/{n;p;}' | grep -o 'DNS:[^, ]*' || true)"
  if [ -z "$names" ]; then [ "$sx" = fail ] || sx=unknown
  elif [ "$(wc -l <<<"$names")" -gt 1 ] || grep -q '\*' <<<"$names"; then sx=fail; fi
  code="${r[verify_code]:--1}"
  case "$code" in
    0) ;;
    10|11) exp=fail ;;                       # certificate has expired / not yet valid
    62) san=fail ;;                          # hostname mismatch
    2|18|19|20|21|27) chain=fail ;;          # unable to get issuer / self-signed / untrusted
    *) chain=fail ;;                         # anything else is not a pass
  esac
  unset r
done
emit tls_handshake_ok "$hs"; emit x509_not_expired "$exp"; emit x509_chain_ok "$chain"; emit san_matches_host "$san"
emit san_exact "$sx"
# The CA must be the one the range created: the unaffected services still verify against it.
ca_ok=pass
for svc in static admin; do
  p="$(port $svc)"
  c="$("$HERE/scripts/probe_tls.sh" 127.0.0.1 "$p" "$HOST" "$CA" | sed -n 's/^verify_code=//p')"
  [ "$c" = 0 ] || ca_ok=fail
done
emit ca_untouched "$ca_ok"
# health_stable_Ns: every service answers /health with a verified connection, once a second, for STABLE_S seconds.
stable=pass
end=$(( $(date +%s) + STABLE_S ))
while [ "$(date +%s)" -lt "$end" ]; do
  for svc in api billing static admin; do
    curl -fsS --noproxy "*" --max-time 3 --cacert "$CA" --resolve "$HOST:$(port $svc):127.0.0.1" "https://$HOST:$(port $svc)/health" >/dev/null 2>&1 || stable=fail
  done
  [ "$stable" = fail ] && break
  sleep 1
done
emit health_stable_10s "$stable"
