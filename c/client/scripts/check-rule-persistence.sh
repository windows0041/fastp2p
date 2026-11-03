#!/usr/bin/env bash
# Rules persist in the gateway and are restored to clients on reconnect.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run with root for an isolated network namespace.' >&2; exit 1; }
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
client="${FASTP2P_C_BUILD_DIR:-$repository/build/c}/fastp2p"
gateway="${FASTP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/fastp2p-gateway"
for binary in "$client" "$gateway"; do
  [[ -x "$binary" ]] || { echo "Build $binary first." >&2; exit 1; }
done
runtime=$(mktemp -d /tmp/fastp2p-rule-persist.XXXXXXXX)
chmod 700 "$runtime"
echo "Private rule persistence logs: $runtime"
exec unshare --net bash -c '
  set -euo pipefail
  ip link set lo up
  exec python3 "$@"
' _ "$repository/c/client/tests/rule_persistence.py" \
  --client "$client" --gateway "$gateway" --logs "$runtime/logs"
