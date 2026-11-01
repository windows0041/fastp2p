#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run with root for an isolated network namespace.' >&2; exit 1; }
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
client="${OPENP2P_C_BUILD_DIR:-$repository/build/c}/openp2p-c"
gateway="${OPENP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/openp2p-gateway-c"
go_client="${OPENP2P_GO_BUILD_DIR:-$repository/build/go}/openp2p"
for binary in "$client" "$gateway" "$go_client"; do
  [[ -x "$binary" ]] || { echo "Build $binary first." >&2; exit 1; }
done
logs=$(mktemp -d /tmp/openp2p-socks-tests.XXXXXXXX)
chmod 700 "$logs"
echo "Private SOCKS5 integration logs: $logs"
exec unshare --net bash -c '
  set -euo pipefail
  ip link set lo up
  exec python3 "$@"
' _ "$repository/c/client/tests/socks_integration.py" --client "$client" --gateway "$gateway" \
  --legacy-client "$go_client" --logs "$logs" "$@"
