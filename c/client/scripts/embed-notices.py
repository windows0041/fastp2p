#!/usr/bin/env python3
"""Keep complete distribution notices inside the standalone CLI."""
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--prefix', default='')
p.add_argument('--output', required=True)
args = p.parse_args()
root = Path(__file__).resolve().parents[1]
files = [('fastp2p LICENSE', root/'LICENSE'), ('Third-party notices', root/'THIRD_PARTY.md')]
if args.prefix:
    sources = Path(args.prefix).parent.parent/'sources'
    for name, item in json.loads((root/'deps.lock.json').read_text()).items():
        file = 'LICENSE.txt' if name == 'openssl' else 'COPYING'
        files.append((name + ' ' + item['version'], sources/(name+'-'+item['version'])/file))
data = b''.join(('\n===== '+name+' =====\n').encode() + path.read_bytes() + b'\n' for name, path in files)
Path(args.output).write_text('static const unsigned char fastp2p_notices[] = {\n' +
    '\n'.join(','.join(str(b) for b in data[i:i+32])+',' for i in range(0,len(data),32)) + '\n};\n', encoding='utf-8')
