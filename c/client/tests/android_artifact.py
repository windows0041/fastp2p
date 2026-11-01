#!/usr/bin/env python3
"""Validate ABI payloads, the public symbol boundary, notices and 16 KB compatibility."""
import argparse
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

p=argparse.ArgumentParser()
p.add_argument('--apk',required=True)
p.add_argument('--ndk',required=True)
args=p.parse_args()
tools=Path(args.ndk)/'toolchains/llvm/prebuilt/linux-x86_64/bin'
header=Path(__file__).resolve().parents[1]/'include/fastp2p.h'
required=set(re.findall(r'FASTP2P_API\s+[^;\n]+?\b(fastp2p_\w+)\s*\(',header.read_text()))
with zipfile.ZipFile(args.apk) as apk, tempfile.TemporaryDirectory(prefix='fastp2p-android-abi-') as temp:
    for name in ['fastp2p-LICENSE','openssl-LICENSE.txt','curl-COPYING','ngtcp2-COPYING','json-c-COPYING']:
        assert len(apk.read('assets/licenses/'+name))>100,name
    for abi,machine in [('arm64-v8a',183),('x86_64',62)]:
        for library in ['libfastp2p.so','libfastp2p_jni.so']:
            data=apk.read('lib/'+abi+'/'+library)
            assert data[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',data,18)[0]==machine,abi
            offset=struct.unpack_from('<Q',data,32)[0]
            size,count=struct.unpack_from('<HH',data,54)
            for i in range(count):
                record=offset+i*size
                if struct.unpack_from('<I',data,record)[0]==1:
                    assert struct.unpack_from('<Q',data,record+48)[0]>=16384,(abi,library)
            if library=='libfastp2p.so':
                file=Path(temp)/(abi+'.so');file.write_bytes(data)
                output=subprocess.check_output([str(tools/'llvm-nm'),'--dynamic','--defined-only',str(file)],text=True)
                exported={line.split()[-1].split('@')[0] for line in output.splitlines() if ' T ' in line}
                assert exported==required,{'abi':abi,'missing':list(required-exported),'extra':list(exported-required)}
    subprocess.run([str(Path(args.ndk).parents[1]/'build-tools/36.0.0/zipalign'),'-c','-P','16','4',args.apk],check=True)
print('Android arm64/x86_64 C ABI, JNI payloads, notices and 16 KB alignment passed')
