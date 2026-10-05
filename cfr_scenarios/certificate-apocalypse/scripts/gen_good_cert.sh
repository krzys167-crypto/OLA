#!/usr/bin/env bash
# Issue a valid server certificate for $HOST from the range CA (creating the CA on first use).
# The shared certificate (api + billing) is written to $CERT_DIR/server.pem (key + chain, one atomic rename).
# The CA is NEVER regenerated here: replacing it would break every service that still trusts the old one.
# Usage: CERT_DIR=state/certs HOST=svc-xxxx.range.test DAYS=30 scripts/gen_good_cert.sh [name]
set -euo pipefail
CERT_DIR="${CERT_DIR:-state/certs}"; HOST="${HOST:-svc-local.range.test}"; DAYS="${DAYS:-30}"; NAME="${1:-server}"
mkdir -p "$CERT_DIR"; cd "$CERT_DIR"
if [ ! -f ca.key ] || [ ! -f ca.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj "/CN=CFR Range CA" -days 3650 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
openssl req -newkey rsa:2048 -nodes -keyout "$tmp/key.pem" -out "$tmp/req.csr" -subj "/CN=$HOST" >/dev/null 2>&1
SAN="DNS:$HOST"
# GOOD_WILDCARD=1 models a participant who "fixes" the outage by adding *.<parent domain> as well: it verifies, but it is
# not what was asked (hidden assertion san_exact).
[ "${GOOD_WILDCARD:-0}" = 1 ] && SAN="$SAN,DNS:*.${HOST#*.}"
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
  "$SAN" > "$tmp/ext.cnf"
openssl x509 -req -in "$tmp/req.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$tmp/crt.pem" -days "$DAYS" \
  -extfile "$tmp/ext.cnf" >/dev/null 2>&1
cat "$tmp/key.pem" "$tmp/crt.pem" > "$NAME.pem.new"
mv "$NAME.pem.new" "$NAME.pem"
echo "issued $CERT_DIR/$NAME.pem for $HOST (valid ${DAYS}d, signed by the range CA)"
