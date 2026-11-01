#!/usr/bin/env python3
"""Exercise both C/Go roles with the actual OpenP2P ALPN and stream frame."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--build', required=True)
args = parser.parse_args()
build = Path(args.build).resolve()
suffix = '.exe' if os.name == 'nt' else ''
subprocess.run([str(build/('quic-interop'+suffix)), '--dependencies'], check=True)

def port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

results = {}
for c_server in (False, True):
    cp, gp = port(), port()
    while gp == cp:
        gp = port()
    c = [str(build / ('quic-interop'+suffix)), 'server' if c_server else 'client',
         '127.0.0.1', str(gp), str(cp)]
    go = [str(build / ('quic-go'+suffix)), 'client' if c_server else 'server',
          f'127.0.0.1:{gp}', f'127.0.0.1:{cp}']
    first, second = (c, go) if c_server else (go, c)
    process = subprocess.Popen(first, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = process.stdout.readline()
        assert 'READY' in line or 'UDP_PORT=' in line, line
        other = subprocess.run(second, capture_output=True, text=True, timeout=20)
        stdout, stderr = process.communicate(timeout=20)
        assert other.returncode == 0, other.stdout + other.stderr + line + stdout + stderr
        assert process.returncode == 0, line + stdout + stderr
        results['c_server_go_client' if c_server else 'c_client_go_server'] = True
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
print(json.dumps(results, indent=2))
