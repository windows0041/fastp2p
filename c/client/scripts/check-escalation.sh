#!/usr/bin/env bash
# Escalation check: two endpoints in separate namespaces that cannot reach each
# other must still end up talking through a relay, without being forced.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
client="${FASTP2P_C_BUILD_DIR:-$repository/build/c}/fastp2p"
gateway="${FASTP2P_C_GATEWAY_BUILD_DIR:-$repository/build/c-gateway}/fastp2p-gateway"
for binary in "$client" "$gateway"; do
  [[ -x "$binary" ]] || { echo "Build $binary first." >&2; exit 1; }
done
[[ $(id -u) == 0 ]] || { echo 'Run the escalation check as root (it creates namespaces).' >&2; exit 1; }
# Keep artifacts on a persistent filesystem so a failed run can be inspected.
base=${FASTP2P_TEST_ROOT:-/tmp}
runtime=$(mktemp -d "$base/fastp2p-escalation.XXXXXXXX")
chmod 700 "$runtime"
bash "$repository/scripts/tls/generate-cert.sh" "$runtime/certs" localhost 127.0.0.1 10.90.0.1 \
  > "$runtime/certificate-generation.log" 2>&1
echo "Private escalation logs: $runtime"
exec python3 "$repository/c/client/tests/escalation_integration.py" \
  --client "$client" --gateway "$gateway" \
  --cert-dir "$runtime/certs" --logs "$runtime/logs"
