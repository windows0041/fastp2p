#!/usr/bin/env python3
"""Prove CA and hostname rejection happens before the token-bearing HTTP GET."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
from certificates import create_certificates

parser = argparse.ArgumentParser()
parser.add_argument('--client', required=True)
parser.add_argument('--cert-script', help='Deprecated: certificates are generated portably with OpenSSL')
parser.add_argument('--bootstrap', type=Path, help='Public gateway preset compiled into the client')
args = parser.parse_args()
client = str(Path(args.client).resolve())
results = {}
with tempfile.TemporaryDirectory(prefix='fastp2p-tls-') as runtime:
    runtime = Path(runtime)
    for case, hostname, trust in [('trusted_valid_host', '127.0.0.1', True),
                                   ('untrusted_ca', '127.0.0.1', False),
                                   ('trusted_wrong_host', 'wrong.invalid', True)]:
        directory = runtime / case
        create_certificates(directory, hostname)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / 'server.crt', directory / 'server.key')
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(.2)
        port = listener.getsockname()[1]
        stop = threading.Event()
        counters = {'attempts': 0, 'http_requests': 0}
        def serve():
            while not stop.is_set():
                try:
                    sock, _ = listener.accept()
                except TimeoutError:
                    continue
                counters['attempts'] += 1
                sock.settimeout(1)
                try:
                    with context.wrap_socket(sock, server_side=True) as tls:
                        data = tls.recv(4096)
                        if data.startswith(b'GET '):
                            counters['http_requests'] += 1
                        tls.sendall(b'HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                except (OSError, ssl.SSLError):
                    sock.close()
        thread = threading.Thread(target=serve)
        thread.start()
        command = [client, '--node', 'c-tls-negative', '--serverhost', '127.0.0.1',
                   '--port', str(port), '--run-seconds', '5']
        if trust:
            command += ['--cacert', str(directory / 'ca.crt')]
        env = os.environ.copy()
        env['FASTP2P_TOKEN'] = '9007199254740993'
        try:
            result = subprocess.run(command, env=env, capture_output=True, timeout=12)
            assert result.returncode == 1, case
            diagnostic = result.stdout + result.stderr
            assert b'Sanitizer' not in diagnostic and b'runtime error:' not in diagnostic, case + ': sanitizer failure'
        finally:
            stop.set()
            thread.join(timeout=2)
            listener.close()
        assert counters['attempts'] > 0, case + ': no TLS attempt was made'
        if case == 'trusted_valid_host':
            assert counters['http_requests'] > 0, 'Trusted valid certificate was not accepted'
        else:
            assert counters['http_requests'] == 0, case + ': credential-bearing request escaped TLS validation'
        results[case] = True

    if args.bootstrap:
        preset = json.loads(args.bootstrap.read_text(encoding='utf-8'))
        fingerprint = hashlib.sha256(preset['ca'].encode()).hexdigest()
        port = 1 if preset['port'] != 1 else 2
        profile = runtime / 'invalid-builtin.json'
        for case, digest in [('wrong_builtin_ca_fingerprint', '0' * 64),
                             ('wrong_builtin_ca_endpoint', fingerprint)]:
            profile.write_text(json.dumps({'CACertBuiltin': digest, 'network': {
                'Node': 'c-tls-negative', 'ServerHost': '127.0.0.1', 'ServerPort': port,
                'Token': '9007199254740993'}}))
            profile.chmod(0o600)
            result = subprocess.run([client, '--config', str(profile), '--run-seconds', '1'],
                                    capture_output=True, timeout=12)
            assert result.returncode == 2 and b'Invalid client configuration' in result.stderr, case
            results[case] = True
print(json.dumps(results, indent=2))
