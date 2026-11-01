#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Use root for isolated net/UTS namespaces.' >&2; exit 1; }
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
gateway="${OPENP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/openp2p-gateway-c"
client="${OPENP2P_C_BUILD_DIR:-$repository/build/c}/openp2p-c"
exec unshare --net --uts bash -c '
  set -euo pipefail
  ip link set lo up
  exec python3 "$@"
' _ "$repository/c/gateway/tests/registry_integration.py" --gateway "$gateway" --client "$client" "$@"
