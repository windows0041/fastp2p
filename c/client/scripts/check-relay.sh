#!/usr/bin/env bash
# Relay fallback check: three real C clients against a real C gateway, with the
# source forced through a relay so no direct path can be used.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
client="${FASTP2P_C_BUILD_DIR:-$repository/build/c}/fastp2p"
gateway="${FASTP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/fastp2p-gateway"
for binary in "$client" "$gateway"; do
  [[ -x "$binary" ]] || { echo "Build $binary first." >&2; exit 1; }
done
runtime=$(mktemp -d /tmp/fastp2p-relay-tests.XXXXXXXX)
chmod 700 "$runtime"
bash "$repository/scripts/tls/generate-cert.sh" "$runtime/certs" localhost 127.0.0.1 \
  > "$runtime/certificate-generation.log" 2>&1
echo "Private relay logs: $runtime"
exec python3 "$repository/c/client/tests/relay_integration.py" \
  --client "$client" --gateway "$gateway" \
  --cert-dir "$runtime/certs" --logs "$runtime/logs"
