#!/usr/bin/env python3
"""Embed only public gateway identity, never credentials or private keys."""
import argparse
import json
from pathlib import Path
import re
import ssl

p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--output',required=True);args=p.parse_args()
profile=json.loads(Path(args.input).read_text(encoding='utf-8'))
assert set(profile)=={'host','port','ca'},'Preset must contain public identity only'
assert isinstance(profile['host'],str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}',profile['host'])
assert type(profile['port']) is int and 1<=profile['port']<=65535
assert isinstance(profile['ca'],str) and len(profile['ca'])<=16384 and 'PRIVATE KEY' not in profile['ca']
if profile['ca']:ssl.create_default_context(cadata=profile['ca'])
data=json.dumps(profile,separators=(',',':')).encode()+b'\0'
Path(args.output).write_text('static const unsigned char fastp2p_bootstrap_profile[] = {\n'+
    '\n'.join(','.join(map(str,data[i:i+32]))+',' for i in range(0,len(data),32))+'\n};\n',encoding='utf-8')
