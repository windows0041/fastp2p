#!/usr/bin/env python3
"""Rules live in the gateway database and survive a client restart.

Covers the full lifecycle the console drives: create while the node is offline,
have the node apply them on its next connection, edit / disable / delete while it
is online (applied immediately), and confirm everything survives a gateway
restart as well.
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


def wait(action, timeout=60, what='condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if action():
                return
        except (OSError, AssertionError):
            pass
        time.sleep(0.15)
    raise TimeoutError('timed out waiting for ' + what)


def exact(sock, n):
    result = bytearray()
    while len(result) < n:
        data = sock.recv(n - len(result))
        if not data:
            raise ConnectionError('SOCKS5 closed early')
        result.extend(data)
    return bytes(result)


def address(host, port):
    return b'\x01' + socket.inet_aton(host) + struct.pack('!H', port)


def socks_echo(port, target):
    sock = socket.create_connection(('127.0.0.1', port), timeout=3)
    sock.settimeout(10)
    sock.sendall(b'\x05\x01\x00')
    assert exact(sock, 2) == b'\x05\x00'
    sock.sendall(b'\x05\x01\x00' + address('127.0.0.1', target))
    reply = exact(sock, 10)
    assert reply[:4] == b'\x05\x00\x00\x01', reply[:4]
    payload = secrets.token_bytes(2048)
    sock.sendall(payload)
    assert exact(sock, len(payload)) == payload
    sock.close()
    return True


def listening(port, timeout=1.5):
    try:
        socket.create_connection(('127.0.0.1', port), timeout=timeout).close()
        return True
    except OSError:
        return False


with tempfile.TemporaryDirectory(prefix='fastp2p-persist-') as temporary:
    root = Path(temporary)
    try:
        create_certificates(root / 'certs', '127.0.0.1')
        env = os.environ.copy()
        env.update(FASTP2P_USER='persist-admin',
                   FASTP2P_PASSWORD=secrets.token_urlsafe(24),
                   FASTP2P_TOKEN='9999999999999999')
        ctx = ssl.create_default_context(cafile=str(root / 'certs' / 'ca.crt'))

        def start(command, name):
            directory = root / name
            directory.mkdir(exist_ok=True)
            f = (logs / (name + '.log')).open('a')
            files.append(f)
            child = subprocess.Popen([str(x) for x in command], cwd=directory, env=env,
                                     stdout=f, stderr=subprocess.STDOUT)
            children.append(child)
            return child

        gateway_cmd = [Path(args.gateway).resolve(), '--bind', '127.0.0.1',
                       '--apibind', '127.0.0.1', '--cert', root / 'certs' / 'server.crt',
                       '--key', root / 'certs' / 'server.key']
        gateway = start(gateway_cmd, 'gateway')
        wait(lambda: listening(27183, 1), what='gateway wss')

        echo = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
        echo.daemon_threads = True
        servers.append(echo)
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        target_port = echo.server_address[1]

        def client(name):
            directory = root / name
            directory.mkdir(exist_ok=True)
            config = {'network': {'Node': name, 'ServerHost': '127.0.0.1'},
                      'CACertFile': str(root / 'certs' / 'ca.crt'), 'apps': []}
            path = directory / 'config.json'
            path.write_text(json.dumps(config))
            return start([Path(args.client).resolve(), '--config', path], name)

        def api(path, body=None, token=None, method=None):
            conn = http.client.HTTPSConnection('127.0.0.1', 10008, context=ctx, timeout=10)
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

        def login():
            status, body = api('/api/v1/user/login',
                               {'user': env['FASTP2P_USER'], 'password': env['FASTP2P_PASSWORD']})
            assert status == 200, (status, body)
            return body['token']

        token = login()

        def rules_of(name):
            status, body = api('/api/v1/device/%s/apps' % name, token=token)
            assert status == 200, (status, body)
            return body.get('Apps') or []

        def online(name):
            status, body = api('/api/v1/nodes?query=&limit=50', token=token)
            return status == 200 and any(n.get('name') == name and n.get('isActive')
                                         for n in body['nodes'])

        # --- 1. Rules can be created while the node has never connected.
        # The name must match what the client will register as.
        entry_name = 'persist-entry-node'
        exit_name = 'persist-exit-node'
        rule_port = 23380
        rule = {'appName': 'persist-socks', 'protocol': 'socks5', 'srcPort': rule_port,
                'peerNode': exit_name, 'punchPriority': 0, 'Username': '', 'Password': ''}
        status, _ = api('/api/v1/device/%s/app' % entry_name, rule, token)
        assert status == 200, status
        stored = rules_of(entry_name)
        assert len(stored) == 1 and stored[0]['srcPort'] == rule_port, stored
        results['rule_persisted_before_node_ever_connected'] = True

        # --- 2. The node applies them automatically on first connection.
        client(exit_name)
        wait(lambda: online(exit_name), what='exit node online')
        client(entry_name)
        wait(lambda: online(entry_name), what='entry node online')
        wait(lambda: listening(rule_port), what='pushed rule listening')
        wait(lambda: socks_echo(rule_port, target_port), what='socks through persisted rule')
        results['node_applied_stored_rule_on_connect'] = True

        # --- 3. Editing while online takes effect immediately (new port).
        new_port = 23381
        edit = {'appName': 'persist-socks', 'protocol': 'socks5', 'srcPort': new_port,
                'peerNode': exit_name, 'punchPriority': 0, 'Username': '', 'Password': '',
                'protocol0': 'socks5', 'srcPort0': rule_port}
        status, _ = api('/api/v1/device/%s/app' % entry_name, edit, token)
        assert status == 200, status
        wait(lambda: listening(new_port), what='edited rule listening')
        wait(lambda: socks_echo(new_port, target_port), what='socks after edit')
        assert not listening(rule_port), 'old port must be released after the edit'
        results['edit_applied_immediately_and_old_port_released'] = True

        # --- 4. Disable stops it; enable brings it back.
        status, _ = api('/api/v1/device/%s/switchapp' % entry_name,
                        {'protocol': 'socks5', 'srcPort': new_port, 'enabled': 0}, token)
        assert status == 200, status
        wait(lambda: not listening(new_port), what='disabled rule released its port')
        stored = rules_of(entry_name)
        assert stored and int(stored[0]['enabled']) == 0, stored
        results['disable_stops_the_rule'] = True

        status, _ = api('/api/v1/device/%s/switchapp' % entry_name,
                        {'protocol': 'socks5', 'srcPort': new_port, 'enabled': 1}, token)
        assert status == 200, status
        wait(lambda: socks_echo(new_port, target_port), what='re-enabled rule serves traffic')
        results['enable_restores_the_rule'] = True

        # --- 5. A client restart re-applies from the gateway, not from the file.
        entry = children[-1]
        entry.terminate()
        entry.wait(timeout=10)
        wait(lambda: not listening(new_port), timeout=20, what='port closed after client stop')
        start([Path(args.client).resolve(), '--config', root / entry_name / 'config.json'],
              entry_name)
        wait(lambda: online(entry_name), what='entry node back online')
        wait(lambda: socks_echo(new_port, target_port), what='rule restored after restart')
        results['client_restart_restores_rules_from_gateway'] = True

        # --- 6. Rules survive a gateway restart too (SQLite persistence).
        gateway.terminate()
        gateway.wait(timeout=10)
        gateway = start(gateway_cmd, 'gateway')
        wait(lambda: listening(27183, 1), what='gateway back up')
        token = login()
        stored = rules_of(entry_name)
        assert stored and int(stored[0]['srcPort']) == new_port, stored
        results['rules_survive_gateway_restart'] = True

        # --- 7. Delete removes it from the database and from the running node.
        status, _ = api('/api/v1/device/%s/app' % entry_name,
                        {'protocol': 'socks5', 'srcPort': 0, 'srcPort0': new_port,
                         'protocol0': 'socks5'}, token)
        assert status == 200, status
        assert rules_of(entry_name) == []
        wait(lambda: not listening(new_port), what='deleted rule released its port')
        results['delete_removes_rule_and_stops_it'] = True

        # --- 8. A never-managed node keeps its local config (compatibility).
        status, body = api('/api/v1/device/%s/apps' % exit_name, token=token)
        assert status == 200 and body.get('Apps') == [], body
        results['unmanaged_node_has_no_stored_rules'] = True
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
