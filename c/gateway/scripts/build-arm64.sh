#!/usr/bin/env bash
# Cross-build the arm64 gateway on a Debian host of the same release.
#
# libwebsockets ships an architecture-specific lws_config.h, so the arm64
# development files cannot be co-installed with the host copy. They are unpacked
# into a private sysroot instead, which also keeps the build reproducible.
#
# Usage: build-arm64.sh [--sysroot DIR] [--out DIR] [--skip-install]
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
sysroot=${FASTP2P_ARM64_SYSROOT:-/opt/arm64-sysroot}
out=${FASTP2P_ARM64_OUT:-$repository/dist}
build=${FASTP2P_ARM64_BUILD:-$repository/build/c-gateway-arm64}
skip_install=0
while (($#)); do
  case "$1" in
    --sysroot) sysroot=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --skip-install) skip_install=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if ((!skip_install)); then
  # Both the bookworm and the trixie runtime package names are listed; the ones
  # that do not exist on this release are skipped with a notice.
  packages="libwebsockets-dev libwebsockets17 libwebsockets19t64 libjson-c-dev libjson-c5
            libsqlite3-dev libsqlite3-0 libssl-dev libssl3 libssl3t64 libcap-dev libcap2
            zlib1g-dev zlib1g libev-dev libev4 libc6 libc6-dev libgcc-s1 libstdc++6
            linux-libc-dev libzstd1 liblzma5 libbz2-1.0 libgssapi-krb5-2 libkrb5-3
            libk5crypto3 libkrb5support0 libkeyutils1 libcom-err2"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  cd "$work"
  for package in $packages; do
    apt-get download "$package:arm64" >/dev/null 2>&1 || echo "missing arm64 package: $package" >&2
  done
  rm -rf "$sysroot"
  mkdir -p "$sysroot"
  for deb in *.deb; do dpkg -x "$deb" "$sysroot"; done
  echo "sysroot assembled: $sysroot"
fi

export PKG_CONFIG_SYSROOT_DIR="$sysroot"
export PKG_CONFIG_LIBDIR="$sysroot/usr/lib/aarch64-linux-gnu/pkgconfig:$sysroot/usr/share/pkgconfig"
cmake -S "$repository/c/gateway" -B "$build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DCMAKE_TOOLCHAIN_FILE="$repository/c/gateway/cmake/arm64-linux.cmake" \
  -DFASTP2P_SYSROOT="$sysroot" \
  -DOPENSSL_ROOT_DIR="$sysroot/usr" \
  -DOPENSSL_INCLUDE_DIR="$sysroot/usr/include" \
  -DOPENSSL_SSL_LIBRARY="$sysroot/usr/lib/aarch64-linux-gnu/libssl.so" \
  -DOPENSSL_CRYPTO_LIBRARY="$sysroot/usr/lib/aarch64-linux-gnu/libcrypto.so" \
  -DSQLite3_LIBRARY="$sysroot/usr/lib/aarch64-linux-gnu/libsqlite3.so" \
  -DSQLite3_INCLUDE_DIR="$sysroot/usr/include" \
  -DCMAKE_INSTALL_PREFIX="$out/c-gateway-debian-arm64" >/dev/null
cmake --build "$build" --parallel "$(nproc)"
cmake --install "$build"

mkdir -p "$out"
cp "$repository/c/gateway/README.md" "$repository/c/gateway/VALIDATION-ZH.md" \
   "$repository/c/gateway/THIRD_PARTY.md" "$repository/c/gateway/LICENSE" \
   "$repository/c/gateway/.env.example" "$out/c-gateway-debian-arm64/"
cp "$repository/c/NODE-STORAGE-ZH.md" "$out/c-gateway-debian-arm64/"
cp -R "$repository/c/gateway/deploy" "$out/c-gateway-debian-arm64/"
mkdir -p "$out/c-gateway-debian-arm64/scripts"
cp "$repository/scripts/tls/generate-cert.sh" "$out/c-gateway-debian-arm64/scripts/"
tar -C "$out" -czf "$out/fastp2p-gateway-debian-arm64.tar.gz" c-gateway-debian-arm64
command -v file >/dev/null && file "$out/c-gateway-debian-arm64/bin/fastp2p-gateway" || true
echo "artifact: $out/fastp2p-gateway-debian-arm64.tar.gz"
