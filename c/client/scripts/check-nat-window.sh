#!/usr/bin/env bash
# NAT window check: a peer that advertises a predictable mapping window must
# still complete a session, and the cone control case must be unaffected.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
client="${FASTP2P_C_BUILD_DIR:-$repository/build/c}/fastp2p"
gateway="${FASTP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/fastp2p-gateway"
for binary in "$client" "$gateway"; do
  [[ -x "$binary" ]] || { echo "Build $binary first." >&2; exit 1; }
done
# Keep artifacts on a persistent filesystem so a failed run can be inspected.
base=${FASTP2P_TEST_ROOT:-/tmp}
status=0
for claimed in 3 1; do
  runtime=$(mktemp -d "$base/fastp2p-nat-window.XXXXXXXX")
  chmod 700 "$runtime"
  bash "$repository/scripts/tls/generate-cert.sh" "$runtime/certs" localhost 127.0.0.1 \
    > "$runtime/certificate-generation.log" 2>&1
  echo "NAT window check with the responder claiming type $claimed: $runtime"
  python3 "$repository/c/client/tests/nat_window_integration.py" \
    --client "$client" --gateway "$gateway" \
    --cert-dir "$runtime/certs" --logs "$runtime/logs" --nat-type "$claimed" || status=1
done
exit $status
