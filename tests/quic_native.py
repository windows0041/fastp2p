#!/usr/bin/env python3
"""Exercise the real C QUIC client/server roles with fastp2pv2 ALPN."""
import argparse
from pathlib import Path
import socket
import subprocess

p=argparse.ArgumentParser();p.add_argument('--binary',required=True);args=p.parse_args()
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as temporary:
    temporary.bind(('127.0.0.1',0));client_port=temporary.getsockname()[1]
server=subprocess.Popen([str(Path(args.binary).resolve()),'server','127.0.0.1',str(client_port),'0'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    first=server.stdout.readline();assert first.startswith('UDP_PORT=')
    port=int(first.split('=',1)[1])
    client=subprocess.run([str(Path(args.binary).resolve()),'client','127.0.0.1',str(port),str(client_port)],capture_output=True,text=True,timeout=25)
    output,error=server.communicate(timeout=25)
    assert client.returncode==0 and server.returncode==0,(client.stderr,error)
    assert 'ALPN=fastp2pv2' in client.stdout and 'ALPN=fastp2pv2' in output
    assert 'Sanitizer' not in error+client.stderr and 'runtime error:' not in error+client.stderr
    print('C QUIC client/server, fastp2pv2 ALPN and exact stream frames passed')
finally:
    if server.poll() is None:server.terminate();server.wait(timeout=5)
