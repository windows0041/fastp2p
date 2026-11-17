#!/usr/bin/env bash
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
sanitize=OFF
interop=0
for argument in "$@"; do
  case "$argument" in
    --sanitize) sanitize=ON ;;
    --interop) interop=1 ;;
    *) printf 'Usage: bash c/client/scripts/check.sh [--sanitize] [--interop]\n' >&2; exit 2 ;;
  esac
done
suffix=c
if [[ "$sanitize" == ON ]]; then suffix=c-asan; fi
output="${FASTP2P_C_BUILD_DIR:-$repository/build/$suffix}"
mkdir -p "$output"
output=$(cd -- "$output" && pwd)
cmake -S "$repository/c/client" -B "$output" -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DFASTP2P_SANITIZE="$sanitize"
cmake --build "$output"
cmake --build "$output" --target example-embed
ctest --test-dir "$output" --output-on-failure
if (( interop )); then
  python3 "$repository/c/client/tests/quic_native.py" --binary "$output/quic-interop"
fi
