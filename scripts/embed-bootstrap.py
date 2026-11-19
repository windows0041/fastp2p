#!/usr/bin/env python3
"""Embed only public gateway identity, never credentials or private keys."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import ssl

p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--output',required=True);args=p.parse_args()
profile=json.loads(Path(args.input).read_text(encoding='utf-8'))
assert set(profile) in ({'host','port','ca'}, {'host','port','ca','tls_alias'}),'Preset must contain public identity only'
assert isinstance(profile['host'],str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}',profile['host'])
assert type(profile['port']) is int and 1<=profile['port']<=65535
assert isinstance(profile['ca'],str) and len(profile['ca'])<=16384 and 'PRIVATE KEY' not in profile['ca']
if profile['ca']:ssl.create_default_context(cadata=profile['ca'])
alias = profile.pop('tls_alias', None)
if alias is not None:
    assert set(alias) == {'host', 'ca'}, 'TLS alias must contain a public hostname and CA'
    assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', alias['host'])
    assert alias['host'].lower() != profile['host'].lower()
    assert 0 < len(alias['ca']) <= 16384 and 'PRIVATE KEY' not in alias['ca']
    ssl.create_default_context(cadata=alias['ca'])
else:
    alias = {'host': '', 'ca': ''}
data=json.dumps(profile,separators=(',',':')).encode()+b'\0'
Path(args.output).write_text('static const unsigned char fastp2p_bootstrap_profile[] = {\n'+
    '\n'.join(','.join(map(str,data[i:i+32]))+',' for i in range(0,len(data),32))+'\n};\n'+
    f'static const char fastp2p_bootstrap_host[] = {json.dumps(profile["host"])};\n'+
    f'static const unsigned fastp2p_bootstrap_port = {profile["port"]};\n'+
    f'static const char fastp2p_bootstrap_ca[] = {json.dumps(profile["ca"])};\n'+
    f'static const char fastp2p_bootstrap_ca_hash[] = "{hashlib.sha256(profile["ca"].encode()).hexdigest()}";\n'+
    f'static const char fastp2p_bootstrap_tls_host[] = {json.dumps(alias["host"])};\n'+
    f'static const char fastp2p_bootstrap_tls_ca[] = {json.dumps(alias["ca"])};\n',
    encoding='utf-8')
