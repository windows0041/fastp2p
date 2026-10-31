#!/usr/bin/env python3
"""Local-only gateway/client integration test; run in an isolated network namespace."""
import argparse
import json
from pathlib import Path
import secrets
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--gateway', required=True)
parser.add_argument('--client', required=True)
parser.add_argument('--cert-dir', required=True)
parser.add_argument('--logs', required=True)
args = parser.parse_args()
logs = Path(args.logs).resolve()
logs.mkdir(parents=True, exist_ok=True)
certs = Path(args.cert_dir).resolve()
trusted = ssl.create_default_context(cafile=str(certs / 'ca.crt'))
result = {}
processes, files, echo_servers = [], [], []
user, password = 'local-gateway-test', secrets.token_urlsafe(24)

def request(path, data=None, token=None, context=trusted):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request('https://127.0.0.1:10008' + path, data=body)
    req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header('Authorization', token)
    try:
        with urllib.request.urlopen(req, context=context, timeout=3) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()

def wait_until(action, timeout=45):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError('A test process exited; inspect the log files')
        try:
            value = action()
            if value:
                return value
        except (OSError, urllib.error.URLError) as error:
            last = error
        time.sleep(0.2)
    raise TimeoutError(f'Timed out waiting for local integration step: {last}')

def launch(command, log_name, cwd, env=None):
    log = (logs / log_name).open('w')
    files.append(log)
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    processes.append(process)
    return process

class TCPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                break
            self.request.sendall(data)

class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        connection.sendto(data, self.client_address)

try:
    with tempfile.TemporaryDirectory(prefix='openp2p-e2e-') as runtime:
        launch([str(Path(args.gateway).resolve()), '-bind', '127.0.0.1',
                '-cert', str(certs / 'server.crt'), '-key', str(certs / 'server.key')],
               'e2e-gateway.log', runtime,
               env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'OPENP2P_USER': user, 'OPENP2P_PASSWORD': password})
        wait_until(lambda: request('/healthz')[0] == 200)
        result['trusted_tls'] = True
        try:
            request('/healthz', context=ssl.create_default_context())
            raise AssertionError('Untrusted gateway certificate was accepted')
        except urllib.error.URLError as error:
            assert isinstance(error.reason, ssl.SSLCertVerificationError), error
        result['untrusted_tls_rejected'] = True
        result['unauthenticated_status'] = request('/api/v1/devices')[0]
        assert result['unauthenticated_status'] == 401
        status, credentials = request('/api/v1/user/login', {'user': user, 'password': password})
        assert status == 200
        jwt, install_token = credentials['token'], credentials['nodeToken']

        result['udp_nat_ports'] = {}
        import struct
        for port in (27180, 27181, 27182, 27183):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(struct.pack('<IHH', 4, 2, 0) + b'null', ('127.0.0.1', port))
                packet, _ = sock.recvfrom(2048)
                assert json.loads(packet[8:])['IP'] == '127.0.0.1'
                result['udp_nat_ports'][str(port)] = True

        for protocol, server_type, handler in [('tcp', socketserver.ThreadingTCPServer, TCPEcho),
                                                ('udp', socketserver.ThreadingUDPServer, UDPEcho)]:
            server = server_type(('127.0.0.1', 0), handler)
            server.daemon_threads = True
            echo_servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            result[protocol + '_echo_port'] = server.server_address[1]

        for index, node in enumerate(('wsl-gateway-a', 'wsl-gateway-b')):
            directory = Path(runtime) / node
            directory.mkdir()
            binary = directory / 'openp2p'
            shutil.copy2(args.client, binary)
            launch([str(binary), '-newconfig', '-node', node, '-serverhost', '127.0.0.1',
                    '-token', install_token, '-sharebandwidth', '0', '-cacert', str(certs / 'ca.crt'),
                    '-publicipport', str(23001 + index), '-loglevel', '0'],
                   'e2e-' + node + '.log', directory)

        def ready_nodes():
            status, data = request('/api/v1/devices', token=jwt)
            nodes = data.get('nodes') or []
            return status == 200 and len(nodes) == 2 and all(node.get('lanip') for node in nodes)
        wait_until(ready_nodes)
        result['two_clients_authenticated'] = True

        for protocol, source in (('tcp', 24001), ('udp', 24002)):
            status, _ = request('/api/v1/device/wsl-gateway-a/app', {
                'appName': 'local-' + protocol, 'protocol': protocol, 'srcPort': source,
                'peerNode': 'wsl-gateway-b', 'dstHost': '127.0.0.1',
                'dstPort': result[protocol + '_echo_port'],
            }, token=jwt)
            assert status == 200

        payload = bytes(range(256)) * 256
        def tcp_roundtrip():
            with socket.create_connection(('127.0.0.1', 24001), timeout=2) as sock:
                sock.settimeout(5)
                sock.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    packet = sock.recv(65536)
                    if not packet:
                        return False
                    received.extend(packet)
                return received == payload
        wait_until(tcp_roundtrip)
        result['tcp_roundtrip_bytes'] = len(payload)

        datagram = b'OpenP2P self-hosted gateway UDP test' * 20
        def udp_roundtrip():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.sendto(datagram, ('127.0.0.1', 24002))
                return sock.recvfrom(2048)[0] == datagram
        wait_until(udp_roundtrip)
        result['udp_roundtrip_bytes'] = len(datagram)

        # The old server caused the client to exit after 20 seconds. Check beyond
        # both that timeout and the first periodic heartbeat at 30 seconds.
        stability_deadline = time.monotonic() + 35
        while time.monotonic() < stability_deadline:
            assert all(process.poll() is None for process in processes), 'A process exited during heartbeat verification'
            time.sleep(0.5)
        result['heartbeat_stable_35s'] = True
        assert tcp_roundtrip() and udp_roundtrip()
        result['forwarding_after_heartbeat'] = True
        result['success'] = True
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    for server in echo_servers:
        server.shutdown()
        server.server_close()
    for log in files:
        log.close()
    (logs / 'e2e-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
