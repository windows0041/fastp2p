#!/usr/bin/env bash
set -euo pipefail
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
ndk="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/30.0.16248370}"
work="${OPENP2P_CROSS_WORK:-$HOME/openp2p-dev/cross}"
for abi in arm64-v8a x86_64; do
  python3 "$project/scripts/build-deps.py" "android-$abi" --work "$work" --ndk "$ndk"
done
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$project/android/local.properties"
if [[ -n "${OP2P_CMAKE_DIR:-}" ]]; then
  printf 'cmake.dir=%s\n' "$OP2P_CMAKE_DIR" >> "$project/android/local.properties"
fi
cd "$project/android"
exec bash ./gradlew --no-daemon "-Pop2pDepsBase=$work/prefix" :app:assembleDebug :app:assembleDebugAndroidTest
