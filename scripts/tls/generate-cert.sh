#!/usr/bin/env bash
set -euo pipefail
umask 077
output="${1:-certs/local}"
if (( $# > 0 )); then shift; fi
if (( $# == 0 )); then set -- localhost 127.0.0.1 ::1; fi
for file in ca.key ca.crt server.key server.crt; do
  if [[ -e "$output/$file" ]]; then
    printf 'Certificate file already exists: %s/%s; use a new output directory.\n' "$output" "$file" >&2
    exit 1
  fi
done
mkdir -p "$output"
san=$(python3 - "$@" <<'PY'
import ipaddress, re, sys
entries = []
for value in sys.argv[1:]:
    try:
        entries.append('IP:' + str(ipaddress.ip_address(value)))
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', value):
            raise SystemExit('Invalid certificate hostname: ' + value)
        entries.append('DNS:' + value)
print(','.join(entries))
PY
)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$output/ca.key" -out "$output/ca.crt" -days 3650 -sha256 \
  -subj '/CN=FastP2P Private Gateway CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$output/server.key" -out "$output/server.csr" -subj '/CN=FastP2P Private Gateway'
printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$san" > "$output/server.ext"
openssl x509 -req -in "$output/server.csr" -CA "$output/ca.crt" -CAkey "$output/ca.key" \
  -CAcreateserial -out "$output/server.crt" -days 365 -sha256 -extfile "$output/server.ext"
openssl verify -CAfile "$output/ca.crt" "$output/server.crt"
printf 'Gateway TLS certificate created in %s\nSAN: %s\n' "$output" "$san"
