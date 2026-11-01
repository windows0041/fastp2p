#!/usr/bin/env python3
"""Include headers, examples, locked-source notices and runtime-free sample config."""
import argparse
import json
from pathlib import Path
import shutil

p=argparse.ArgumentParser()
p.add_argument('--sdk',required=True)
p.add_argument('--work',default=str(Path.home()/'fastp2p-dev/cross'))
args=p.parse_args()
project=Path(__file__).resolve().parents[1]
sdk=Path(args.sdk).resolve();sdk.mkdir(parents=True,exist_ok=True)
for file in ['LICENSE','README.md','PLATFORMS-ZH.md','SOCKS5-ZH.md','THIRD_PARTY.md','config.example.json','config.socks5.example.json','deps.lock.json']:
    shutil.copyfile(project/file,sdk/file)
(sdk/'examples').mkdir(exist_ok=True)
(sdk/'include').mkdir(exist_ok=True)
shutil.copyfile(project.parent/'NODE-STORAGE-ZH.md',sdk/'NODE-STORAGE-ZH.md')
shutil.copyfile(project/'include/fastp2p.h',sdk/'include/fastp2p.h')
shutil.copyfile(project/'examples/embed.c',sdk/'examples/embed.c')
notices=sdk/'licenses';notices.mkdir(exist_ok=True)
manifest=json.loads((project/'deps.lock.json').read_text())
for name,item in manifest.items():
    source=Path(args.work)/'sources'/(name+'-'+item['version'])
    filename='LICENSE.txt' if name=='openssl' else 'COPYING'
    shutil.copyfile(source/filename,notices/(name+'-'+filename))
print('SDK metadata and third-party licenses:',sdk)
