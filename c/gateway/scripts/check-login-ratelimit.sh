#!/usr/bin/env bash
# Login rate limiting: the expensive password hash must be capped per source.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
gateway="${FASTP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/fastp2p-gateway"
runtime=$(mktemp -d /tmp/fastp2p-login-ratelimit.XXXXXXXX)
chmod 700 "$runtime"
trap 'rm -rf "$runtime"' EXIT
bash "$repository/scripts/tls/generate-cert.sh" "$runtime/certs" localhost 127.0.0.1 \
  > "$runtime/certificate-generation.log" 2>&1
python3 "$repository/c/gateway/tests/login_ratelimit.py" \
  --gateway "$gateway" --cert-dir "$runtime/certs" --logs "$runtime/logs"
