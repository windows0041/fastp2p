#!/usr/bin/env bash
# Build a fully static musl gateway, so one binary runs on any Linux.
#
# The released gateway is normally linked against the distribution libraries,
# which is why Debian 12 and Debian 13 need separate builds. Static linking
# removes that: the resulting static-pie executable has no libc, OpenSSL,
# libwebsockets, sqlite or json-c dependency at all.
#
# Usage: build-static.sh [x86_64|aarch64] [--out DIR] [--work DIR]
set -euo pipefail
repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
arch=${1:-x86_64}
shift || true
out=${FASTP2P_STATIC_OUT:-$repository/dist}
work=${FASTP2P_STATIC_WORK:-$HOME/fastp2p-dev/gateway-static}
root=${MUSL_CROSS_ROOT:-$HOME/musl-cross}
jobs=${FASTP2P_STATIC_JOBS:-$(nproc)}
while (($#)); do
  case "$1" in
    --out) out=$2; shift 2 ;;
    --work) work=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$arch" in
  x86_64)  triple=x86_64-linux-musl ;;
  aarch64) triple=aarch64-linux-musl ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac
toolchain=$root/$triple-cross
[[ -x $toolchain/bin/$triple-gcc ]] || {
  echo "missing musl toolchain: $toolchain" >&2
  echo "run c/client/scripts/build-musl.sh $arch once, or fetch the pinned archive" >&2
  exit 1
}

# The client recipe already builds OpenSSL and json-c for this target.
prefix=$work/prefix/linux-$arch-musl
python3 "$repository/c/client/scripts/build-deps.py" "linux-$arch-musl" \
  --work "$work" --musl-toolchain "$toolchain" --jobs "$jobs" >/dev/null
mkdir -p "$prefix"

export CC="$toolchain/bin/$triple-gcc"
export AR="$toolchain/bin/$triple-ar"
export RANLIB="$toolchain/bin/$triple-ranlib"
export CFLAGS="-O2 -fPIC"
export LDFLAGS="-static"

# SQLite amalgamation: one file, no configure step.
sqlite_version=3470000
sqlite_dir=$work/src/sqlite-amalgamation-$sqlite_version
if [[ ! -f $sqlite_dir/sqlite3.c ]]; then
  mkdir -p "$work/src"
  curl -fsSL --retry 3 -o "$work/src/sqlite.zip" \
    "https://www.sqlite.org/2024/sqlite-amalgamation-$sqlite_version.zip"
  python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \
    "$work/src/sqlite.zip" "$work/src"
fi
if [[ ! -f $prefix/lib/libsqlite3.a ]]; then
  ( cd "$sqlite_dir"
    "$CC" $CFLAGS -c sqlite3.c -o sqlite3.o -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION
    "$AR" rcs "$prefix/lib/libsqlite3.a" sqlite3.o )
  mkdir -p "$prefix/include" "$prefix/lib/pkgconfig"
  cp "$sqlite_dir/sqlite3.h" "$prefix/include/"
  printf 'Name: SQLite\nDescription: SQL database engine\nVersion: 3.47.0\nLibs: -L${prefix}/lib -lsqlite3\nCflags: -I${prefix}/include\n' \
    >"$prefix/lib/pkgconfig/sqlite3.pc"
fi

# libwebsockets 4.3.x still uses the HMAC_CTX struct, which OpenSSL 3 only
# exposes while deprecated declarations stay enabled.
lws_version=4.3.5
lws_dir=$work/src/libwebsockets-$lws_version
if [[ ! -d $lws_dir ]]; then
  mkdir -p "$work/src"
  curl -fsSL --retry 3 -o "$work/src/lws.tar.gz" \
    "https://github.com/warmcat/libwebsockets/archive/refs/tags/v$lws_version.tar.gz"
  tar xzf "$work/src/lws.tar.gz" -C "$work/src"
fi
if [[ ! -f $prefix/lib/libwebsockets.a ]]; then
  cmake -S "$lws_dir" -B "$work/build-lws-$arch" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_AR="$AR" -DCMAKE_RANLIB="$RANLIB" \
    -DCMAKE_C_FLAGS="$CFLAGS -DOPENSSL_API_COMPAT=0x10100000L" \
    -DCMAKE_EXE_LINKER_FLAGS="-static" \
    -DCMAKE_FIND_ROOT_PATH="$prefix" -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
    -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
    -DOPENSSL_ROOT_DIR="$prefix" -DOPENSSL_INCLUDE_DIR="$prefix/include" \
    -DOPENSSL_SSL_LIBRARY="$prefix/lib/libssl.a" \
    -DOPENSSL_CRYPTO_LIBRARY="$prefix/lib/libcrypto.a" \
    -DLWS_WITH_SHARED=OFF -DLWS_WITH_STATIC=ON -DLWS_WITHOUT_TESTAPPS=ON \
    -DLWS_WITHOUT_TEST_SERVER=ON -DLWS_WITHOUT_TEST_CLIENT=ON -DLWS_WITH_SSL=ON \
    -DLWS_WITH_MINIMAL_EXAMPLES=OFF -DLWS_WITHOUT_DAEMONIZE=ON -DLWS_WITH_SQLITE3=OFF \
    -DLWS_WITH_PLUGINS=OFF -DLWS_WITHOUT_EXTENSIONS=ON -DLWS_WITH_HTTP2=OFF \
    -DLWS_WITH_ZLIB=OFF -DLWS_WITH_LIBUV=OFF -DLWS_WITH_LIBEV=OFF \
    -DLWS_WITH_EVLIB_PLUGINS=OFF -DLWS_IPV6=OFF >/dev/null
  cmake --build "$work/build-lws-$arch" --parallel "$jobs" >/dev/null
  cmake --install "$work/build-lws-$arch" >/dev/null
fi

group="-Wl,--start-group $prefix/lib/libwebsockets.a $prefix/lib/libssl.a"
group="$group $prefix/lib/libcrypto.a $prefix/lib/libsqlite3.a $prefix/lib/libjson-c.a -Wl,--end-group"
export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
cmake -S "$repository/c/gateway" -B "$work/build-gateway-$arch" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DCMAKE_TOOLCHAIN_FILE="$repository/c/client/cmake/linux-musl.cmake" \
  -DFASTP2P_TARGET_ARCH="$arch" \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_AR="$AR" -DCMAKE_RANLIB="$RANLIB" \
  -DCMAKE_EXE_LINKER_FLAGS=-static \
  -DOPENSSL_ROOT_DIR="$prefix" -DOPENSSL_INCLUDE_DIR="$prefix/include" \
  -DOPENSSL_SSL_LIBRARY="$prefix/lib/libssl.a" \
  -DOPENSSL_CRYPTO_LIBRARY="$prefix/lib/libcrypto.a" \
  -DSQLite3_LIBRARY="$prefix/lib/libsqlite3.a" \
  -DSQLite3_INCLUDE_DIR="$prefix/include" \
  -DCMAKE_C_STANDARD_LIBRARIES="$group" >/dev/null
cmake --build "$work/build-gateway-$arch" --parallel "$jobs"

# Package exactly what the service needs: the binary, the deployment assets and
# the documentation that ships with the other platforms.
stage=$out/c-gateway-linux-static-$arch
rm -rf "$stage"
mkdir -p "$out"
cmake --install "$work/build-gateway-$arch" --prefix "$stage" >/dev/null
cp "$repository/c/gateway/README.md" "$repository/c/gateway/VALIDATION-ZH.md" \
   "$repository/c/gateway/THIRD_PARTY.md" "$repository/c/gateway/LICENSE" \
   "$repository/c/gateway/.env.example" "$stage/"
cp "$repository/c/NODE-STORAGE-ZH.md" "$stage/"
cp -R "$repository/c/gateway/deploy" "$stage/"
mkdir -p "$stage/scripts"
cp "$repository/scripts/tls/generate-cert.sh" "$stage/scripts/"

archive=$out/fastp2p-gateway-linux-static-$arch.tar.gz
tar -C "$out" -czf "$archive" "c-gateway-linux-static-$arch"
command -v file >/dev/null && file "$stage/bin/fastp2p-gateway" || true
"$stage/bin/fastp2p-gateway" --version
echo "artifact: $archive"
