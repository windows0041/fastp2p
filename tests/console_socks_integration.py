#!/usr/bin/env python3
"""The web console can push a SOCKS5 exit rule with a chosen local port.

Unlike socks_integration.py (which configures the proxy in a config file), this
drives the real /api/v1/device/<node>/app path the browser uses: login, then a
PUSH_RULE carrying protocol=socks5, a custom srcPort and optional credentials.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from certificates import create_certificates

p = argparse.ArgumentParser()
p.add_argument('--client', required=True)
p.add_argument('--gateway', required=True)
p.add_argument('--logs', required=True)
args = p.parse_args()
logs = Path(args.logs).resolve()
logs.mkdir(parents=True, exist_ok=True)
results = {}
children = []
files = []
servers = []


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(12)
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except OSError:
            pass


def wait(action, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assert all(c.poll() is None for c in children), 'a child exited; inspect private logs'
        try:
            if action():
                return
        except (OSError, AssertionError):
            pass
        time.sleep(0.15)
    raise TimeoutError('console SOCKS5 condition timed out')


def exact(sock, n):
    result = bytearray()
    while len(result) < n:
        data = sock.recv(n - len(result))
        if not data:
            raise ConnectionError('SOCKS5 connection closed early')
        result.extend(data)
    return bytes(result)


def address(host, port):
    return b'\x01' + socket.inet_aton(host) + struct.pack('!H', port)


def socks_echo(port, target, auth=False):
    sock = socket.create_connection(('127.0.0.1', port), timeout=3)
    sock.settimeout(10)
    # Greeting: offer both none and username/password.
    sock.sendall(b'\x05\x02\x00\x02')
    expected = b'\x05\x02' if auth else b'\x05\x00'
    got = exact(sock, 2)
    assert got == expected, ('greeting', got, expected)
    if auth:
        sock.sendall(b'\x01\x05alice\x06secret')
        assert exact(sock, 2) == b'\x01\x00'
    sock.sendall(b'\x05\x01\x00' + address('127.0.0.1', target))
    reply = exact(sock, 10)
    assert reply[:4] == b'\x05\x00\x00\x01', ('connect', reply[:4])
    payload = secrets.token_bytes(4096)
    sock.sendall(payload)
    assert exact(sock, len(payload)) == payload
    sock.close()
    return True


with tempfile.TemporaryDirectory(prefix='fastp2p-console-socks-') as temporary:
    root = Path(temporary)
    try:
        create_certificates(root / 'certs', '127.0.0.1')
        env = os.environ.copy()
        env.update(FASTP2P_USER='console-admin',
                   FASTP2P_PASSWORD=secrets.token_urlsafe(24),
                   FASTP2P_TOKEN='9999999999999999')
        ctx = ssl.create_default_context(cafile=str(root / 'certs' / 'ca.crt'))

        def start(command, name):
            directory = root / name
            directory.mkdir(exist_ok=True)
            f = (logs / (name + '.log')).open('w')
            files.append(f)
            child = subprocess.Popen([str(x) for x in command], cwd=directory, env=env,
                                     stdout=f, stderr=subprocess.STDOUT)
            children.append(child)
            return child

        start([Path(args.gateway).resolve(), '--bind', '127.0.0.1', '--apibind', '127.0.0.1',
               '--cert', root / 'certs' / 'server.crt', '--key', root / 'certs' / 'server.key'],
              'gateway')
        wait(lambda: socket.create_connection(('127.0.0.1', 27183), timeout=1).close() is None)

        # A target service on the exit node for the SOCKS client to reach.
        echo = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
        echo.daemon_threads = True
        servers.append(echo)
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        target_port = echo.server_address[1]

        def client(name):
            directory = root / name
            directory.mkdir()
            config = {'network': {'Node': name, 'ServerHost': '127.0.0.1'},
                      'CACertFile': str(root / 'certs' / 'ca.crt'), 'apps': []}
            path = directory / 'config.json'
            path.write_text(json.dumps(config))
            return start([Path(args.client).resolve(), '--config', path], name)

        client('socks-exit-node')
        client('socks-entry-node')

        def api(path, body=None, token=None, method=None):
            conn = http.client.HTTPSConnection('127.0.0.1', 10008, context=ctx, timeout=8)
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['Authorization'] = 'Bearer ' + token
            conn.request(method or ('POST' if body is not None else 'GET'), path,
                         json.dumps(body).encode() if body is not None else None, headers)
            response = conn.getresponse()
            status = response.status
            data = response.read()
            conn.close()
            return status, json.loads(data) if data else None

        status, login = api('/api/v1/user/login',
                            {'user': env['FASTP2P_USER'], 'password': env['FASTP2P_PASSWORD']})
        assert status == 200, (status, login)
        token = login['token']

        # Both nodes must be registered before the console can push a rule.
        def online(name):
            status, body = api('/api/v1/nodes?query=&limit=50', token=token)
            return status == 200 and any(n.get('name') == name for n in body['nodes'])
        wait(lambda: online('socks-entry-node') and online('socks-exit-node'))

        def push(port, auth):
            rule = {'appName': 'console-socks-' + str(port), 'protocol': 'socks5',
                    'srcPort': port, 'peerNode': 'socks-exit-node',
                    'punchPriority': 0, 'Username': 'alice' if auth else '',
                    'Password': 'secret' if auth else ''}
            status, body = api('/api/v1/device/socks-entry-node/app', rule, token)
            assert status == 200, (status, body)
            wait(lambda: socks_echo(port, target_port, auth))
            return True

        # Custom ports, one with RFC1929 auth and one without.
        open_port_auth = 23371
        open_port_open = 23372
        results['console_pushed_socks5_with_auth_and_custom_port'] = push(open_port_auth, True)
        results['console_pushed_socks5_without_auth_and_custom_port'] = push(open_port_open, False)

        # The pushed rules must be reported back as SOCKS5 with those exact ports.
        status, body = api('/api/v1/device/socks-entry-node/apps', token=token)
        assert status == 200, (status, body)
        apps = body.get('Apps') or body.get('apps') or []
        socks = [a for a in apps if a.get('protocol') == 'socks5']
        assert {int(a['srcPort']) for a in socks} >= {open_port_auth, open_port_open}, apps
        results['pushed_rules_reported_as_socks5'] = True
        results['success'] = True
    finally:
        for child in children:
            child.terminate()
        for child in children:
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
        for server in servers:
            server.shutdown()
        for f in files:
            f.close()

print(json.dumps(results, indent=2))
