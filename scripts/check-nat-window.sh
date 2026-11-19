#!/usr/bin/env bash
# NAT window check: a peer that advertises a symmetric mapping window must still
# complete a session, over both underlays, and the cone control case must be
# unaffected. The QUIC runs are the ones that actually announce a window; the TCP
# runs guard that the additional fields do not disturb port prediction.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
client="${FASTP2P_C_BUILD_DIR:-$repository/build}/fastp2p"
gateway="${FASTP2P_C_GATEWAY_BUILD_DIR:-$repository/../fastp2p-gateway/build}/fastp2p-gateway"
for binary in "$client" "$gateway"; do
  [[ -x "$binary" ]] || { echo "Build $binary first." >&2; exit 1; }
done
# Keep artifacts on a persistent filesystem so a failed run can be inspected.
base=${FASTP2P_TEST_ROOT:-/tmp}
# transport:nat-type. 2 is hard symmetric (centred window), 3 is the predictable
# symmetric mapping, 1 is the cone control.
combinations=${FASTP2P_NAT_WINDOW_CASES:-"tcp:3 tcp:1 quic:3 quic:2 quic:1"}
status=0
for combination in $combinations; do
  transport=${combination%%:*}
  claimed=${combination##*:}
  runtime=$(mktemp -d "$base/fastp2p-nat-window.XXXXXXXX")
  chmod 700 "$runtime"
  bash "$repository/scripts/tls/generate-cert.sh" "$runtime/certs" localhost 127.0.0.1 \
    > "$runtime/certificate-generation.log" 2>&1
  echo "NAT window check over $transport with the responder claiming type $claimed: $runtime"
  python3 "$repository/tests/nat_window_integration.py" \
    --client "$client" --gateway "$gateway" \
    --cert-dir "$runtime/certs" --logs "$runtime/logs" \
    --nat-type "$claimed" --transport "$transport" || status=1
done
exit $status
