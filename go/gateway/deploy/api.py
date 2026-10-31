#!/usr/bin/env python3
"""Call the private gateway API without printing the login JWT or password."""
import argparse
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('path')
parser.add_argument('--method', default='GET')
parser.add_argument('--data-file')
parser.add_argument('--url', default='https://127.0.0.1:10008')
parser.add_argument('--credentials', default='/etc/openp2p-selfhost/credentials.json')
parser.add_argument('--ca', default='/etc/openp2p-selfhost/tls/ca.crt')
args = parser.parse_args()
credentials = json.loads(Path(args.credentials).read_text())
context = ssl.create_default_context(cafile=args.ca)
body = json.dumps({'user': credentials['user'], 'password': credentials['password']}).encode()
request = urllib.request.Request(args.url + '/api/v1/user/login', data=body, headers={'Content-Type': 'application/json'})
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    token = json.load(response)['token']
body = Path(args.data_file).read_bytes() if args.data_file else None
request = urllib.request.Request(args.url + args.path, data=body, method=args.method,
                                 headers={'Authorization': token, 'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(request, context=context, timeout=20) as response:
        body = response.read()
        print(json.dumps({'status': response.status, 'response': json.loads(body) if body else None}, ensure_ascii=False))
except urllib.error.HTTPError as error:
    print(json.dumps({'status': error.code, 'error': error.read().decode(errors='replace')}, ensure_ascii=False))
    raise SystemExit(1)
