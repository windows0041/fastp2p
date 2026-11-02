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
  x86_64)   triple=x86_64-linux-musl;      bootlin_family=x86-64;             qemu=qemu-x86_64-static ;;
  aarch64)  triple=aarch64-linux-musl;     bootlin_family=aarch64;            qemu=qemu-aarch64-static ;;
  armv7)    triple=arm-linux-musleabihf;   bootlin_family=armv7-eabihf;       qemu=qemu-arm-static ;;
  i686)     triple=i486-linux-musl;        bootlin_family=x86-i686;           qemu=qemu-i386-static ;;
  riscv64)  triple=riscv64-linux-musl;     bootlin_family=riscv64;            qemu=qemu-riscv64-static ;;
  s390x)    triple=s390x-linux-musl;       bootlin_family=s390x-z13;          qemu=qemu-s390x-static ;;
  ppc64le)  triple=powerpc64le-linux-musl; bootlin_family=powerpc64le-power8; qemu=qemu-ppc64le-static ;;
  # Bootlin only ships the n32 ABI for mips64el; it still runs on mips64el CPUs.
  mips64el) triple=mips64el-linux-musl;    bootlin_family=mips64el-n32;       qemu=qemu-mips64el-static ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

toolchain=$root/$triple-cross
if [[ ! -x $toolchain/bin/$triple-gcc ]]; then
  mkdir -p "$root"
  # Preferred source: the pinned archives published with the project, verified
  # against the committed digest list. External mirrors are only a fallback.
  base=${FASTP2P_TOOLCHAIN_BASE:-https://github.com/windows0041/fastp2p/releases/download/musl-toolchains}
  name=$triple-cross.tar.gz
  expected=$(awk -v n="$name" '$2 == n { print $1 }' \
    "$repository/c/client/scripts/musl-toolchains.txt" 2>/dev/null || true)
  fetched=0
  if [[ -n $expected ]]; then
    echo "fetching pinned toolchain $name" >&2
    if curl -fsSL --retry 2 --connect-timeout 30 --max-time 1200 -o "$root/$name" "$base/$name"; then
      if echo "$expected  $root/$name" | sha256sum -c --status; then
        tar xzf "$root/$name" -C "$root" && fetched=1
      else
        echo "checksum mismatch for $name, ignoring the download" >&2
      fi
    fi
    rm -f "$root/$name"
  fi
  if ((fetched)); then
    :
  else
  echo "fetching musl toolchain $triple" >&2
  musl_cc_url=${MUSL_CC_URL:-https://musl.cc}
  if ! curl -fsSL --retry 2 --connect-timeout 30 --max-time 900 \
      -o "$toolchain.tgz" "$musl_cc_url/$triple-cross.tgz"; then
    # musl.cc is not reachable from every CI network; Bootlin publishes the same
    # kind of static toolchain under a predictable directory listing.
    family=$bootlin_family
    listing="https://toolchains.bootlin.com/downloads/releases/toolchains/$family/tarballs/"
    echo "musl.cc unavailable, falling back to Bootlin ($family)" >&2
    latest=$(curl -fsSL --max-time 120 "$listing" |
      grep -o "[a-z0-9._-]*--musl--stable-[0-9.]*-[0-9]*\.tar\.bz2" |
      sort -V | tail -1)
    [[ -n $latest ]] || { echo "cannot locate a Bootlin toolchain for $family" >&2; exit 1; }
    curl -fsSL --retry 3 --max-time 900 -o "$root/bootlin.tar.bz2" "$listing$latest"
    mkdir -p "$root/bootlin-$arch"
    tar xjf "$root/bootlin.tar.bz2" -C "$root/bootlin-$arch" --strip-components=1
    rm -f "$root/bootlin.tar.bz2"
    toolchain=$root/bootlin-$arch
  else
    tar xzf "$toolchain.tgz" -C "$root"
    rm -f "$toolchain.tgz"
  fi
  fi
fi

compiler=$(ls "$toolchain"/bin/*-gcc | head -1)
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
