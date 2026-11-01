#!/usr/bin/env bash
set -euo pipefail
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
ndk="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/30.0.16248370}"
work="${FASTP2P_CROSS_WORK:-$HOME/fastp2p-dev/cross}"
for abi in arm64-v8a x86_64; do
  python3 "$project/scripts/build-deps.py" "android-$abi" --work "$work" --ndk "$ndk"
done
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$project/android/local.properties"
if [[ -n "${FASTP2P_CMAKE_DIR:-}" ]]; then
  printf 'cmake.dir=%s\n' "$FASTP2P_CMAKE_DIR" >> "$project/android/local.properties"
fi
cd "$project/android"
if [[ -n "${FASTP2P_ANDROID_KEYSTORE:-}" ]]; then
  exec bash ./gradlew --no-daemon "-Pfastp2pDepsBase=$work/prefix" :app:assembleRelease :app:assembleReleaseAndroidTest :app:lintRelease
fi
exec bash ./gradlew --no-daemon "-Pfastp2pDepsBase=$work/prefix" :app:assembleDebug :app:assembleDebugAndroidTest :app:lintDebug
