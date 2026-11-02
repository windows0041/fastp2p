#!/usr/bin/env bash
# Fetch (or locate) the pinned musl cross toolchain for one architecture.
#
# Prints the toolchain directory on stdout. The archives published with the
# project are verified against the committed digest list; external mirrors are
# only a fallback for networks that cannot reach GitHub.
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
arch=${1:?usage: fetch-musl-toolchain.sh <arch>}
root=${MUSL_CROSS_ROOT:-$HOME/musl-cross}

case "$arch" in
  x86_64)   triple=x86_64-linux-musl;      bootlin_family=x86-64 ;;
  aarch64)  triple=aarch64-linux-musl;     bootlin_family=aarch64 ;;
  armv7)    triple=arm-linux-musleabihf;   bootlin_family=armv7-eabihf ;;
  i686)     triple=i486-linux-musl;        bootlin_family=x86-i686 ;;
  riscv64)  triple=riscv64-linux-musl;     bootlin_family=riscv64 ;;
  s390x)    triple=s390x-linux-musl;       bootlin_family=s390x-z13 ;;
  ppc64le)  triple=powerpc64le-linux-musl; bootlin_family=powerpc64le-power8 ;;
  mips64el) triple=mips64el-linux-musl;    bootlin_family=mips64el-n32 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

toolchain=$root/$triple-cross
if [[ -x $toolchain/bin/$triple-gcc ]]; then
  echo "$toolchain"
  exit 0
fi

mkdir -p "$root"
base=${FASTP2P_TOOLCHAIN_BASE:-https://github.com/windows0041/fastp2p/releases/download/musl-toolchains}
name=$triple-cross.tar.gz
expected=$(awk -v n="$name" '$2 == n { print $1 }' \
  "$repository/c/client/scripts/musl-toolchains.txt" 2>/dev/null || true)
if [[ -n $expected ]]; then
  echo "fetching pinned toolchain $name" >&2
  if curl -fsSL --retry 2 --connect-timeout 30 --max-time 1200 -o "$root/$name" "$base/$name"; then
    if echo "$expected  $root/$name" | sha256sum -c --status; then
      tar xzf "$root/$name" -C "$root"
      rm -f "$root/$name"
      echo "$toolchain"
      exit 0
    fi
    echo "checksum mismatch for $name, ignoring the download" >&2
  fi
  rm -f "$root/$name"
fi

# Fallback 1: musl.cc publishes the same layout.
musl_cc_url=${MUSL_CC_URL:-https://musl.cc}
echo "fetching musl toolchain $triple from musl.cc" >&2
if curl -fsSL --retry 2 --connect-timeout 30 --max-time 900 -o "$toolchain.tgz" \
    "$musl_cc_url/$triple-cross.tgz"; then
  tar xzf "$toolchain.tgz" -C "$root"
  rm -f "$toolchain.tgz"
  echo "$toolchain"
  exit 0
fi

# Fallback 2: Bootlin, which does not publish a stable musl build for every family.
listing="https://toolchains.bootlin.com/downloads/releases/toolchains/$bootlin_family/tarballs/"
echo "musl.cc unavailable, trying Bootlin ($bootlin_family)" >&2
latest=$(curl -fsSL --max-time 120 "$listing" |
  grep -o "[a-z0-9._-]*--musl--stable-[0-9.]*-[0-9]*\.tar\.bz2" | sort -V | tail -1 || true)
if [[ -z $latest ]]; then
  echo "no pinned, musl.cc or Bootlin toolchain available for $arch" >&2
  exit 1
fi
curl -fsSL --retry 3 --max-time 900 -o "$root/bootlin.tar.bz2" "$listing$latest"
mkdir -p "$root/bootlin-$arch"
tar xjf "$root/bootlin.tar.bz2" -C "$root/bootlin-$arch" --strip-components=1
rm -f "$root/bootlin.tar.bz2"
echo "$root/bootlin-$arch"
