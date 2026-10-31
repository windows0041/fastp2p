#!/usr/bin/env bash
set -euo pipefail
dev="${OPENP2P_DEV_DIR:-$HOME/openp2p-dev}"
node="${1:-wsl-local-node}"
if (( $# > 0 )); then shift; fi
[[ "$node" =~ ^[A-Za-z0-9_-]{8,31}$ ]] || { printf 'Use an 8-31 character node name.\n' >&2; exit 1; }
set -a
. "$HOME/.config/openp2p-gateway/local.env"
set +a
export OPENP2P_LOCAL_CA="$dev/certs/local/ca.crt"
OPENP2P_TOKEN=$(python3 - <<'PY'
import json, os, ssl, urllib.request
payload = json.dumps({'user': os.environ['OPENP2P_USER'], 'password': os.environ['OPENP2P_PASSWORD']}).encode()
request = urllib.request.Request('https://127.0.0.1:10008/api/v1/user/login', data=payload, headers={'Content-Type': 'application/json'})
with urllib.request.urlopen(request, context=ssl.create_default_context(cafile=os.environ['OPENP2P_LOCAL_CA']), timeout=5) as response:
    print(json.load(response)['nodeToken'])
PY
)
export OPENP2P_TOKEN
unset OPENP2P_USER OPENP2P_PASSWORD
directory="$dev/nodes/$node"
mkdir -p "$directory"
cp "$dev/bin/openp2p" "$directory/openp2p"
exec "$directory/openp2p" -node "$node" -serverhost 127.0.0.1 \
  -cacert "$OPENP2P_LOCAL_CA" -sharebandwidth 0 "$@"
