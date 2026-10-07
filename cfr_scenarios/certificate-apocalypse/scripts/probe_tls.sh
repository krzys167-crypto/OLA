#!/usr/bin/env bash
# Probe one TLS endpoint with openssl and print key=value lines.
# Usage: scripts/probe_tls.sh <connect-host> <port> <verify-host> <ca.crt>
#   handshake=ok|fail   verify_code=<openssl code>   verify_msg=...   not_after=...
set -uo pipefail
CONNECT="${1:?connect host}"; PORT="${2:?port}"; VHOST="${3:?verify host}"; CA="${4:?ca file}"
out="$(echo | timeout 8 openssl s_client -connect "$CONNECT:$PORT" -servername "$VHOST" -CAfile "$CA" \
        -verify_hostname "$VHOST" 2>&1)"
code="$(sed -n 's/^ *Verify return code: \([0-9]*\) (\(.*\))$/\1|\2/p' <<<"$out" | tail -1)"
if [ -z "$code" ]; then
  echo "handshake=fail"; echo "verify_code=-1"; echo "verify_msg=no TLS session established"; exit 0
fi
echo "handshake=ok"
echo "verify_code=${code%%|*}"
echo "verify_msg=${code#*|}"
na="$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' <<<"$out" | openssl x509 -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
echo "not_after=${na:-unknown}"
