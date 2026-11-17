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
  x86_64)   qemu=qemu-x86_64-static ;;
  aarch64)  qemu=qemu-aarch64-static ;;
  armv7)    qemu=qemu-arm-static ;;
  i686)     qemu=qemu-i386-static ;;
  riscv64)  qemu=qemu-riscv64-static ;;
  s390x)    qemu=qemu-s390x-static ;;
  ppc64le)  qemu=qemu-ppc64le-static ;;
  mips64el) qemu=qemu-mips64el-static ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

# The pinned archive, musl.cc and Bootlin are tried in that order by the
# shared helper, so the gateway build uses exactly the same toolchain.
toolchain=$(bash "$repository/c/client/scripts/fetch-musl-toolchain.sh" "$arch")
# A glob that matches nothing makes `ls` fail, which aborts the script before the
# message on the next line under `set -e`; glob it directly instead.
compiler=""
for candidate in "$toolchain"/bin/*-gcc; do
  [ -x "$candidate" ] || continue
  compiler=$candidate
  break
done
[[ -x $compiler ]] || { echo "no compiler in $toolchain" >&2; exit 1; }
binutils=${compiler%-gcc}

python3 "$repository/c/client/scripts/build-deps.py" "linux-$arch-musl" \
  --work "$work" --musl-toolchain "$toolchain" --jobs "$jobs"

build=$work/build/$arch
prefix=$work/prefix/linux-$arch-musl
cmake -S "$repository/c/client" -B "$build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DCMAKE_TOOLCHAIN_FILE="$repository/c/client/cmake/linux-musl.cmake" \
  -DFASTP2P_TARGET_ARCH="$arch" \
  -DCMAKE_C_COMPILER="$compiler" \
  -DCMAKE_AR="${binutils}-ar" \
  -DCMAKE_RANLIB="${binutils}-ranlib" \
  -DCMAKE_EXE_LINKER_FLAGS=-static \
  -DFASTP2P_DEPS_ROOT="$prefix" >/dev/null
cmake --build "$build" --parallel "$jobs"

# Ship an archive like every other platform: one download, no loose binaries.
mkdir -p "$out"
stage=$work/pkg/fastp2p-linux-static-$arch
rm -rf "$stage"
mkdir -p "$stage/bin"
cp "$build/fastp2p" "$stage/bin/fastp2p"
for doc in README.md PLATFORMS-ZH.md LICENSE; do
  [[ -f $repository/c/client/$doc ]] && cp "$repository/c/client/$doc" "$stage/"
done
archive=$out/fastp2p-linux-static-$arch.tar.gz
tar -C "$work/pkg" -czf "$archive" "fastp2p-linux-static-$arch"
file "$stage/bin/fastp2p"

if command -v "$qemu" >/dev/null 2>&1; then
  "$qemu" "$stage/bin/fastp2p" --version
else
  echo "note: $qemu not installed, skipped the execution check" >&2
fi
echo "artifact: $archive"
