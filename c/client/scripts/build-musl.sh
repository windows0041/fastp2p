#!/usr/bin/env bash
# Build a fully static musl client for one Linux architecture.
#
# Usage: build-musl.sh <arch> [--out DIR]
#   arch: x86_64 aarch64 armv7 i686 riscv64 s390x ppc64le mips64el
#
# The client links OpenSSL, curl, ngtcp2 and json-c, so the dependencies are
# built for the target first; the result is a static-pie binary that runs on any
# Linux with the right CPU, including musl-based routers.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
arch=${1:?usage: build-musl.sh <arch> [--out DIR]}
shift || true
out=${FASTP2P_MUSL_OUT:-$repository/dist}
work=${FASTP2P_MUSL_WORK:-$HOME/fastp2p-dev/musl}
root=${MUSL_CROSS_ROOT:-$HOME/musl-cross}
jobs=${FASTP2P_MUSL_JOBS:-$(nproc)}

case "$arch" in
  x86_64)   triple=x86_64-linux-musl;    qemu=qemu-x86_64-static ;;
  aarch64)  triple=aarch64-linux-musl;   qemu=qemu-aarch64-static ;;
  armv7)    triple=arm-linux-musleabihf; qemu=qemu-arm-static ;;
  i686)     triple=i486-linux-musl;      qemu=qemu-i386-static ;;
  riscv64)  triple=riscv64-linux-musl;   qemu=qemu-riscv64-static ;;
  s390x)    triple=s390x-linux-musl;     qemu=qemu-s390x-static ;;
  ppc64le)  triple=powerpc64le-linux-musl; qemu=qemu-ppc64le-static ;;
  mips64el) triple=mips64el-linux-musl;  qemu=qemu-mips64el-static ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

toolchain=$root/$triple-cross
if [[ ! -x $toolchain/bin/$triple-gcc ]]; then
  echo "fetching musl toolchain $triple" >&2
  mkdir -p "$root"
  curl -sSL --retry 3 --max-time 900 -o "$toolchain.tgz" "https://musl.cc/$triple-cross.tgz"
  tar xzf "$toolchain.tgz" -C "$root"
  rm -f "$toolchain.tgz"
fi

python3 "$repository/c/client/scripts/build-deps.py" "linux-$arch-musl" \
  --work "$work" --musl-root "$root" --jobs "$jobs"

build=$work/build/$arch
prefix=$work/prefix/linux-$arch-musl
cmake -S "$repository/c/client" -B "$build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DCMAKE_TOOLCHAIN_FILE="$repository/c/client/cmake/linux-musl.cmake" \
  -DFASTP2P_TARGET_ARCH="$arch" \
  -DCMAKE_C_COMPILER="$toolchain/bin/$triple-gcc" \
  -DCMAKE_AR="$toolchain/bin/$triple-ar" \
  -DCMAKE_RANLIB="$toolchain/bin/$triple-ranlib" \
  -DCMAKE_EXE_LINKER_FLAGS=-static \
  -DFASTP2P_DEPS_ROOT="$prefix" >/dev/null
cmake --build "$build" --parallel "$jobs"

mkdir -p "$out"
binary=$out/fastp2p-linux-$arch
cp "$build/fastp2p" "$binary"
file "$binary"

if command -v "$qemu" >/dev/null 2>&1; then
  "$qemu" "$binary" --version
else
  echo "note: $qemu not installed, skipped the execution check" >&2
fi
echo "artifact: $binary"
