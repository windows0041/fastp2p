#!/usr/bin/env bash
# Run the NAT window integration test: the peer advertises a predicted mapping
# window and the session must still complete and carry traffic.
set -u
SRC=${FP_SRC:-$HOME/work/fastp2p}
BUILD=${FP_BUILD:-$HOME/work/build}
PY=${PYTHON:-python3}
CLIENT=$BUILD/client/fastp2p
GATEWAY=$BUILD/gateway/fastp2p-gateway
CERTDIR=$(mktemp -d)
WORK=$(mktemp -d)
trap 'rm -rf "$CERTDIR" "$WORK"' EXIT

bash "$SRC/scripts/tls/generate-cert.sh" "$CERTDIR" localhost 127.0.0.1 >/dev/null 2>&1
"$PY" "$SRC/c/client/tests/nat_window_integration.py" \
  --client "$CLIENT" --gateway "$GATEWAY" --cert-dir "$CERTDIR" \
  --logs "$WORK/logs"
