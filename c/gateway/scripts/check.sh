#!/usr/bin/env bash
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
sanitize=OFF
case "${1:-}" in
  '') ;;
  --sanitize) sanitize=ON ;;
  *) echo 'Usage: bash c/gateway/scripts/check.sh [--sanitize]' >&2; exit 2 ;;
esac
build="${FASTP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}"
cmake -S "$repository/c/gateway" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DFASTP2P_SANITIZE="$sanitize"
cmake --build "$build" --parallel 4
ctest --test-dir "$build" --output-on-failure
[[ $(id -u) == 0 ]] || { echo 'Protocol network tests need root and an isolated network namespace.' >&2; exit 1; }
runtime=$(mktemp -d /tmp/fastp2p-gateway-protocol.XXXXXXXX)
chmod 700 "$runtime"
echo "Private protocol logs: $runtime"
bash "$repository/scripts/tls/generate-cert.sh" "$runtime/certs" localhost 127.0.0.1 > "$runtime/certificate-generation.log" 2>&1
exec unshare --net bash -c '
  set -euo pipefail
  ip link set lo up
  python3 "$1/c/gateway/tests/protocol_integration.py" --gateway "$2" --cert-dir "$3/certs" --logs "$3/logs"
  exec python3 "$1/c/gateway/tests/admin_integration.py" --gateway "$2" --cert-dir "$3/certs" --logs "$3/admin-logs"
' _ "$repository" "$build/fastp2p-gateway" "$runtime"
