#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run the isolated network test as root.' >&2; exit 1; }
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
gateway="${FASTP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/fastp2p-gateway"
client="${FASTP2P_C_BUILD_DIR:-$repository/build/c}/fastp2p"
for binary in "$gateway" "$client"; do
  [[ -x "$binary" ]] || { echo "Build $binary first." >&2; exit 1; }
done
runtime=$(mktemp -d /tmp/fastp2p-gateway-tests.XXXXXXXX)
chmod 700 "$runtime"
echo "Private test certificates and logs: $runtime"
bash "$repository/scripts/tls/generate-cert.sh" "$runtime/certs" localhost 127.0.0.1 10.203.0.1 > "$runtime/certificate-generation.log" 2>&1
exec unshare --net bash -c '
  set -euo pipefail
  ip link set lo up
  exec python3 "$@"
' _ "$repository/c/client/tests/integration.py" --gateway "$gateway" \
  --c-client "$client" --cert-dir "$runtime/certs" --logs "$runtime/logs" "$@"
