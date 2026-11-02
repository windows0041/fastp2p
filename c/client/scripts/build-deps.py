#!/usr/bin/env python3
"""Build pinned C dependencies out of tree for a native or cross target."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import time
import urllib.request

parser=argparse.ArgumentParser()
LINUX_MUSL = {
    # target suffix: (musl cross triple, OpenSSL Configure target, extra CFLAGS)
    'aarch64': ('aarch64-linux-musl', 'linux-aarch64', ''),
    'armv7': ('arm-linux-musleabihf', 'linux-armv4',
              '-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard'),
    'i686': ('i486-linux-musl', 'linux-x86', '-march=i686'),
    'x86_64': ('x86_64-linux-musl', 'linux-x86_64', ''),
    'riscv64': ('riscv64-linux-musl', 'linux64-riscv64', ''),
    's390x': ('s390x-linux-musl', 'linux64-s390x', ''),
    'ppc64le': ('powerpc64le-linux-musl', 'linux64-ppc64le', ''),
    'mips64el': ('mips64el-linux-musl', 'linux64-mips64', ''),
}
parser.add_argument('target',choices=['linux-x86_64','windows-x86_64','android-arm64-v8a','android-x86_64',
    'macos-arm64','macos-x86_64']+['linux-'+a+'-musl' for a in LINUX_MUSL])
parser.add_argument('--work',default=str(Path.home()/'fastp2p-dev/cross'))
parser.add_argument('--ndk',default=os.environ.get('ANDROID_NDK_HOME',''))
parser.add_argument('--jobs',type=int,default=min(4,os.cpu_count() or 2))
parser.add_argument('--musl-root',default=os.environ.get('MUSL_CROSS_ROOT',str(Path.home()/'musl-cross')),
    help='directory holding <triple>/bin/<triple>-gcc musl cross toolchains')
parser.add_argument('--musl-toolchain',default='',
    help='explicit musl toolchain directory (any layout with bin/*-gcc)')
args=parser.parse_args()
project=Path(__file__).resolve().parents[1]
manifest=json.loads((project/'deps.lock.json').read_text())
work=Path(args.work).resolve()
cache=work/'downloads'
sources=work/'sources'
build=work/'build'/args.target
prefix=work/'prefix'/args.target
for p in (cache,sources,build,prefix): p.mkdir(parents=True,exist_ok=True)
stamp=prefix/'fastp2p-dependencies.json'
fingerprint={'sources':manifest,'recipe_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
if stamp.exists() and json.loads(stamp.read_text())==fingerprint:
    print('Dependencies already built:',prefix)
    raise SystemExit(0)
paths={}
for name,item in manifest.items():
    archive=cache/item['file']
    if not archive.exists():
        print('Downloading',name,item['version'],flush=True)
        partial=cache/(item['file']+'.partial')
        for attempt in range(3):
            try:
                with urllib.request.urlopen(item['url'],timeout=60) as response, partial.open('wb') as output:
                    while chunk:=response.read(1024*1024):output.write(chunk)
                if hashlib.sha256(partial.read_bytes()).hexdigest()!=item['sha256']:
                    raise SystemExit('Dependency checksum mismatch: '+name)
                partial.replace(archive)
                break
            except OSError:
                if attempt==2:raise
                print('Retrying download:',name,flush=True)
                time.sleep(2)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=item['sha256']:
        raise SystemExit('Dependency checksum mismatch: '+name)
    destination=sources/(name+'-'+item['version'])
    if not destination.exists():
        with tarfile.open(archive) as tar:
            members=tar.getmembers()
            top=members[0].name.split('/')[0]
            tar.extractall(sources,filter='data')
        extracted=sources/top
        if extracted!=destination: extracted.rename(destination)
    paths[name]=destination

environment=os.environ.copy()
environment['PKG_CONFIG_LIBDIR']=str(prefix/'lib/pkgconfig')
environment['PKG_CONFIG_PATH']=str(prefix/'lib/pkgconfig')
cmake_common=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_INSTALL_PREFIX='+str(prefix),
    '-DCMAKE_INSTALL_LIBDIR=lib','-DCMAKE_POSITION_INDEPENDENT_CODE=ON','-DBUILD_SHARED_LIBS=OFF','-DBUILD_TESTING=OFF',
    '-DCMAKE_NO_SYSTEM_FROM_IMPORTED=ON']
environment['CFLAGS']='-O2 -fPIC'
openssl_target='linux-x86_64'
openssl_extra=[]
if args.target=='windows-x86_64':
    cmake_common+=['-DCMAKE_TOOLCHAIN_FILE='+str(project/'cmake/windows-x86_64.cmake')]
    openssl_target='mingw64'
    environment['CC']='x86_64-w64-mingw32-gcc'
    environment['AR']='x86_64-w64-mingw32-ar'
    environment['RANLIB']='x86_64-w64-mingw32-ranlib'
    environment['CFLAGS']='-O2 -D_WIN32_WINNT=0x0A00'
elif args.target.startswith('android-'):
    ndk=Path(args.ndk).resolve()
    if not (ndk/'build/cmake/android.toolchain.cmake').exists(): raise SystemExit('Provide --ndk or ANDROID_NDK_HOME')
    abi=args.target.removeprefix('android-')
    toolbin=ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin'
    environment['ANDROID_NDK_ROOT']=str(ndk)
    environment['PATH']=str(toolbin)+os.pathsep+environment['PATH']
    environment['AR']=str(toolbin/'llvm-ar')
    environment['RANLIB']=str(toolbin/'llvm-ranlib')
    environment['CC']=str(toolbin/('aarch64-linux-android26-clang' if abi=='arm64-v8a' else 'x86_64-linux-android26-clang'))
    openssl_target='android-arm64' if abi=='arm64-v8a' else 'android-x86_64'
    openssl_extra=['-D__ANDROID_API__=26']
    cmake_common+=['-DCMAKE_TOOLCHAIN_FILE='+str(ndk/'build/cmake/android.toolchain.cmake'),
                   '-DANDROID_ABI='+abi,'-DANDROID_PLATFORM=android-26','-DANDROID_STL=none']
elif args.target.endswith('-musl'):
    arch=args.target.removeprefix('linux-').removesuffix('-musl')
    triple,openssl_target,arch_flags=LINUX_MUSL[arch]
    if args.musl_toolchain:
        # Any toolchain layout works: the compiler and its binutils are found by
        # globbing, which keeps musl.cc, Bootlin and the pinned archives
        # interchangeable.
        toolchain=Path(args.musl_toolchain)
        gccs=sorted((toolchain/'bin').glob('*-gcc'))
        if not gccs:
            raise SystemExit('No *-gcc in musl toolchain: %s'%toolchain)
        compiler=gccs[0]
    else:
        # musl.cc archives extract to <triple>-cross while the binaries keep the
        # bare triple, so accept either layout.
        toolchain=Path(args.musl_root)/triple
        if not (toolchain/'bin').is_dir():
            toolchain=Path(args.musl_root)/(triple+'-cross')
        compiler=toolchain/'bin'/(triple+'-gcc')
        if not compiler.exists():
            raise SystemExit('Missing musl toolchain: %s (see --musl-root)'%compiler)
    tool_prefix=compiler.name[:-len('-gcc')]
    archiver=toolchain/'bin'/(tool_prefix+'-ar')
    ranlib=toolchain/'bin'/(tool_prefix+'-ranlib')
    environment['CC']=str(compiler)
    environment['AR']=str(archiver)
    environment['RANLIB']=str(ranlib)
    environment['CFLAGS']=('-O2 -fPIC '+arch_flags).strip()
    environment['LDFLAGS']='-static'
    cmake_common+=['-DCMAKE_TOOLCHAIN_FILE='+str(project/'cmake/linux-musl.cmake'),
                   '-DFASTP2P_TARGET_ARCH='+arch,
                   '-DCMAKE_C_COMPILER='+str(compiler),
                   '-DCMAKE_AR='+str(archiver),
                   '-DCMAKE_RANLIB='+str(ranlib),
                   '-DCMAKE_EXE_LINKER_FLAGS=-static']
elif args.target.startswith('macos-'):
    if sys.platform!='darwin': raise SystemExit('macOS dependencies require an Apple SDK on macOS')
    arch=args.target.removeprefix('macos-')
    environment['CC']='clang'
    environment['CFLAGS']='-O2 -fPIC -arch '+arch+' -mmacosx-version-min=13.0'
    openssl_target='darwin64-arm64-cc' if arch=='arm64' else 'darwin64-x86_64-cc'
    cmake_common+=['-DCMAKE_OSX_ARCHITECTURES='+arch,'-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0']

def run(command,directory,label):
    print(args.target+': '+label,flush=True)
    log=build/(label.replace(' ','-')+'.log')
    with log.open('w') as output:
        result=subprocess.run([str(x) for x in command],cwd=directory,env=environment,stdout=output,stderr=subprocess.STDOUT)
    if result.returncode:
        print('\n'.join(log.read_text(errors='replace').splitlines()[-45:]),flush=True)
        raise SystemExit('Build failed; log: '+str(log))

openssl_build=build/'openssl'
openssl_build.mkdir(exist_ok=True)
openssl_flags=['no-shared','no-tests','no-apps','no-module']
if args.target.endswith('-musl') and args.target.split('-')[1] not in ('x86_64','aarch64'):
    openssl_flags.append('no-asm')
run(['perl',paths['openssl']/'Configure',openssl_target,*openssl_flags,
     '--prefix='+str(prefix),'--libdir=lib',*openssl_extra],openssl_build,'openssl-configure')
run(['make','-j'+str(args.jobs)],openssl_build,'openssl-build')
run(['make','install_sw'],openssl_build,'openssl-install')
ssl=['-DOPENSSL_ROOT_DIR='+str(prefix),'-DOPENSSL_INCLUDE_DIR='+str(prefix/'include'),
     '-DOPENSSL_SSL_LIBRARY='+str(prefix/'lib/libssl.a'),'-DOPENSSL_CRYPTO_LIBRARY='+str(prefix/'lib/libcrypto.a'),
     '-DOPENSSL_USE_STATIC_LIBS=TRUE']

def cmake(name,options):
    directory=build/name
    run(['cmake','-S',paths[name],'-B',directory,'-U_OPENSSL_*','-UHAVE_SSL_*',*cmake_common,*options],build,name+'-configure')
    run(['cmake','--build',directory,'--parallel',str(args.jobs)],build,name+'-build')
    run(['cmake','--install',directory],build,name+'-install')

cmake('ngtcp2',ssl+['-DENABLE_LIB_ONLY=ON','-DENABLE_SHARED_LIB=OFF','-DENABLE_STATIC_LIB=ON',
                  '-DENABLE_GNUTLS=OFF','-DENABLE_OPENSSL=ON'])
cmake('json-c',['-DDISABLE_WERROR=ON','-DBUILD_APPS=OFF','-DENABLE_THREADING=OFF'])
curl=['-DBUILD_CURL_EXE=OFF','-DBUILD_EXAMPLES=OFF','-DBUILD_LIBCURL_DOCS=OFF','-DBUILD_MISC_DOCS=OFF',
      '-DCURL_DISABLE_LDAP=ON','-DCURL_DISABLE_LDAPS=ON',
      '-DUSE_LIBIDN2=OFF','-DCURL_USE_LIBPSL=OFF','-DCURL_BROTLI=OFF','-DCURL_ZSTD=OFF','-DCURL_ZLIB=OFF',
      '-DCURL_USE_LIBSSH2=OFF','-DCURL_USE_LIBSSH=OFF','-DUSE_NGHTTP2=OFF','-DUSE_NGTCP2=OFF',
      '-DENABLE_THREADED_RESOLVER=OFF','-DENABLE_ARES=OFF','-DENABLE_WEBSOCKETS=ON']
if args.target=='windows-x86_64':
    curl+=['-DCURL_USE_SCHANNEL=ON','-DCURL_USE_OPENSSL=OFF']
else:
    curl+=ssl+['-DCURL_USE_OPENSSL=ON']
    if args.target.startswith('macos-'): curl+=['-DCURL_USE_SECTRUST=ON']
    if args.target.startswith('android-'): curl+=['-DCURL_CA_PATH=/system/etc/security/cacerts']
cmake('curl',curl)
stamp.write_text(json.dumps(fingerprint,indent=2)+'\n')
print('Dependency prefix:',prefix,flush=True)
