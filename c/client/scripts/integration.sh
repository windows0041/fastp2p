#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 ]] || { printf 'Run this network namespace test as root.\n' >&2; exit 1; }
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
output="${OPENP2P_C_BUILD_DIR:-$repository/build/c}"
go_output="${OPENP2P_GO_BUILD_DIR:-$repository/build/go}"
output=$(cd -- "$output" && pwd)
go_output=$(cd -- "$go_output" && pwd)
for binary in "$output/openp2p-c" "$go_output/openp2p" "$go_output/openp2p-gateway"; do
  [[ -x "$binary" ]] || { printf 'Build %s first.\n' "$binary" >&2; exit 1; }
done
work=$(mktemp -d /tmp/openp2p-c-tests.XXXXXXXX)
chmod 700 "$work"
printf 'Private test certificates and logs: %s\n' "$work"
bash "$repository/go/gateway/scripts/generate-cert.sh" "$work/certs" localhost 127.0.0.1 10.203.0.1
exec unshare --net bash -c '
  set -euo pipefail
  ip link set lo up
  exec python3 "$@"
' _ "$repository/c/client/tests/integration.py" \
  --gateway "$go_output/openp2p-gateway" --go-client "$go_output/openp2p" \
  --c-client "$output/openp2p-c" --cert-dir "$work/certs" --logs "$work/logs" "$@"
