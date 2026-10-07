#!/usr/bin/env bash
# Break the shared certificate. Variants (one per run, chosen by the server):
#   expired          signed by the range CA, validity ended in 2020
#   untrusted-chain  self-signed, not issued by the range CA
#   wrong-san        signed by the range CA, valid, but for another host name
# Usage: CERT_DIR=state/certs HOST=svc-xxxx.range.test scripts/gen_bad_cert.sh <variant>
set -euo pipefail
VARIANT="${1:?variant}"; CERT_DIR="${CERT_DIR:-state/certs}"; HOST="${HOST:-svc-local.range.test}"
cd "$CERT_DIR"
[ -f ca.key ] && [ -f ca.crt ] || { echo "no CA in $CERT_DIR: run gen_good_cert.sh first" >&2; exit 2; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
openssl req -newkey rsa:2048 -nodes -keyout "$tmp/key.pem" -out "$tmp/req.csr" -subj "/CN=$HOST" >/dev/null 2>&1
san() { printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$1" > "$tmp/ext.cnf"; }
case "$VARIANT" in
  expired)
    san "$HOST"
    : > "$tmp/index.txt"; echo 01 > "$tmp/serial.txt"
    cat > "$tmp/ca.cnf" <<CNF
[ca]
default_ca = CA_default
[CA_default]
database = $tmp/index.txt
new_certs_dir = $tmp
serial = $tmp/serial.txt
default_md = sha256
policy = pol
unique_subject = no
[pol]
commonName = supplied
CNF
    openssl ca -batch -config "$tmp/ca.cnf" -cert ca.crt -keyfile ca.key -in "$tmp/req.csr" -out "$tmp/crt.pem" \
      -startdate 20200101000000Z -enddate 20200102000000Z -extfile "$tmp/ext.cnf" -notext >/dev/null 2>&1 ;;
  untrusted-chain)
    san "$HOST"
    openssl req -x509 -key "$tmp/key.pem" -out "$tmp/crt.pem" -subj "/CN=$HOST" -days 30 \
      -addext "subjectAltName=DNS:$HOST" >/dev/null 2>&1 ;;
  wrong-san)
    san "other-$HOST"
    openssl x509 -req -in "$tmp/req.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$tmp/crt.pem" -days 30 \
      -extfile "$tmp/ext.cnf" >/dev/null 2>&1 ;;
  *) echo "unknown variant: $VARIANT" >&2; exit 2 ;;
esac
cat "$tmp/key.pem" "$tmp/crt.pem" > server.pem.new
mv server.pem.new server.pem
echo "installed broken certificate ($VARIANT) as $CERT_DIR/server.pem"
