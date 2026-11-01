#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run the isolated network test as root.' >&2; exit 1; }
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
gateway="${OPENP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/openp2p-gateway-c"
client="${OPENP2P_C_BUILD_DIR:-$repository/build/c}/openp2p-c"
go_client="${OPENP2P_GO_BUILD_DIR:-$repository/build/go}/openp2p"
for binary in "$gateway" "$client" "$go_client"; do
  [[ -x "$binary" ]] || { echo "Build $binary first." >&2; exit 1; }
done
runtime=$(mktemp -d /tmp/openp2p-c-gateway-tests.XXXXXXXX)
chmod 700 "$runtime"
echo "Private test certificates and logs: $runtime"
bash "$repository/go/gateway/scripts/generate-cert.sh" "$runtime/certs" localhost 127.0.0.1 10.203.0.1 > "$runtime/certificate-generation.log" 2>&1
exec unshare --net bash -c '
  set -euo pipefail
  ip link set lo up
  exec python3 "$@"
' _ "$repository/c/client/tests/integration.py" --gateway "$gateway" --go-client "$go_client" \
  --c-client "$client" --cert-dir "$runtime/certs" --logs "$runtime/logs" "$@"
