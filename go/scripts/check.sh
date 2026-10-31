#!/usr/bin/env bash
set -euo pipefail

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
output="${OPENP2P_BUILD_DIR:-$repository/build/go}"
mkdir -p "$output"
output=$(cd -- "$output" && pwd)

printf 'Checking with %s\n' "$(go version)"
(
  cd "$repository/go/client"
  go test -mod=readonly -race -count=1 -skip '^TestNetInfo$' ./core ./cmd ./pkg/upnp
  go build -mod=readonly -trimpath -o "$output/openp2p" ./cmd
)
(
  cd "$repository/go/gateway"
  go test -mod=readonly -race -count=1 -skip '^TestNetInfo$' .
  go build -mod=readonly -trimpath -o "$output/openp2p-gateway" .
)
printf 'Go client and gateway built in %s\n' "$output"
