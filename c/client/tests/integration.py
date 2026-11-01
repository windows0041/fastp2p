#!/usr/bin/env python3
"""Six C clients against the C gateway, in an isolated netns.

Requires root + `unshare --net` and a loopback interface brought up by the caller.
Runtime credentials and logs stay outside the checkout.
"""
import argparse
import json
import os
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
parser.add_argument('--c-client', required=True)
parser.add_argument('--cert-dir', required=True)
parser.add_argument('--logs', required=True)
parser.add_argument('--quick', action='store_true', help='Skip the 35s stability and reconnect checks')
args = parser.parse_args()
if Path('/proc/self/ns/net').readlink() == Path('/proc/1/ns/net').readlink():
    raise SystemExit('Run in a separate network namespace to avoid deployed services')
logs = Path(args.logs).resolve()
logs.mkdir(parents=True, exist_ok=True)
certs = Path(args.cert_dir).resolve()
context = ssl.create_default_context(cafile=str(certs / 'ca.crt'))
processes, handles, echo_servers = [], [], []
c_processes = []
results = {}
gateway_host = '10.203.0.1'
password = secrets.token_urlsafe(24)
install_token = secrets.randbelow(9*10**15) + 10**15
credentials = {'FASTP2P_USER': 'c-integration-user', 'FASTP2P_PASSWORD': password,
               'FASTP2P_TOKEN': str(install_token)}
jwt = None

def api(path, data=None, auth=True):
    req = urllib.request.Request('https://127.0.0.1:10008' + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Content-Type': 'application/json'})
    if auth and jwt:
        req.add_header('Authorization', jwt)
    with urllib.request.urlopen(req, context=context, timeout=3) as response:
        payload = response.read()
        return json.loads(payload) if payload else None

def start(command, name, directory, env=None):
    output = (logs / (name + '.log')).open('w')
    handles.append(output)
    child_env = os.environ.copy()
    child_env.update(env or {})
    child = subprocess.Popen([str(x) for x in command], cwd=directory, env=child_env,
                             stdout=output, stderr=subprocess.STDOUT)
    processes.append(child)
    return child

def wait(check, timeout=50):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('A process exited; inspect private integration logs')
        try:
            value = check()
            if value:
                return value
        except (OSError, urllib.error.URLError, ValueError) as exc:
            error = type(exc).__name__
        time.sleep(.15)
    raise TimeoutError('Integration condition timed out: ' + str(error))

class TCPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            first = bytearray()
            while len(first) < len(b'FASTP2P-FIN\n'):
                data = self.request.recv(len(b'FASTP2P-FIN\n') - len(first))
                if not data:
                    return
                first.extend(data)
            if first == b'FASTP2P-FIN\n':
                self.request.sendall(bytes(range(256)) * 128)
                return
            self.request.sendall(first)
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except OSError:
            pass

class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)

def tcp_roundtrip(port, host='127.0.0.1'):
    payload = secrets.token_bytes(262144)
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.settimeout(5)
        sock.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            data = sock.recv(65536)
            if not data:
                return False
            received.extend(data)
    return received == payload

def udp_roundtrip(port, host='127.0.0.1'):
    payload = secrets.token_bytes(1000)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(payload, (host, port))
        return sock.recvfrom(4096)[0] == payload

def tcp_final_response(port, host='127.0.0.1'):
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.settimeout(5)
        sock.sendall(b'FASTP2P-FIN\n')
        response = bytearray()
        while True:
            data = sock.recv(65536)
            if not data:
                break
            response.extend(data)
    return response == bytes(range(256)) * 128

try:
    with tempfile.TemporaryDirectory(prefix='fastp2p-integration-') as runtime:
        runtime = Path(runtime)
        runtime.chmod(0o700)
        subprocess.run(['ip', 'link', 'add', 'c-gateway', 'type', 'dummy'], check=True)
        subprocess.run(['ip', 'addr', 'add', gateway_host + '/32', 'dev', 'c-gateway'], check=True)
        subprocess.run(['ip', 'link', 'set', 'c-gateway', 'up'], check=True)
        gateway_args = [Path(args.gateway).resolve(), '-bind', '0.0.0.0', '-apibind', '127.0.0.1',
            '-cert', certs / 'server.crt', '-key', certs / 'server.key']
        gateway = start(gateway_args, 'gateway', runtime, credentials)
        wait(lambda: api('/healthz', auth=False))
        jwt = api('/api/v1/user/login', {'user': credentials['FASTP2P_USER'], 'password': password}, False)['token']
        for proto, cls, handler in [('tcp', socketserver.ThreadingTCPServer, TCPEcho),
                                    ('udp', socketserver.ThreadingUDPServer, UDPEcho)]:
            server = cls(('127.0.0.1', 0), handler)
            server.daemon_threads = True
            echo_servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            results[proto + '_echo_port'] = server.server_address[1]

        cases = []
        nodes = []
        next_port = 25000
        def rules(peer, transport, label, host='127.0.0.1'):
            global next_port
            items = []
            for proto in ('tcp', 'udp'):
                next_port += 1
                items.append({'AppName': label + '-' + proto, 'Protocol': proto,
                    'SrcPort': next_port, 'PeerNode': peer, 'DstHost': '127.0.0.1',
                    'DstPort': results[proto + '_echo_port'], 'BindIP': host,
                    'UnderlayProtocol': transport, 'PunchPriority': 3 if transport == 'tcp' else 4,
                    'Enabled': 1})
                cases.append((label + '-' + proto, proto, next_port, host))
            return items

        def client(name, language, app_rules):
            nodes.append(name)
            directory = runtime / name
            directory.mkdir(mode=0o700)
            cfg = {'network': {'Node': name, 'Token': install_token, 'ServerHost': gateway_host,
                    'ServerPort': 27183, 'ShareBandwidth': 0, 'PublicIPPort': 31000 + len(nodes)},
                   'CACertFile': str(certs / 'ca.crt'), 'LogLevel': 0, 'apps': app_rules}
            config = directory / 'config.json'
            config.write_text(json.dumps(cfg))
            config.chmod(0o600)
            prefix = []
            if language == 'remote':
                index = 1 if name.endswith('TCP') else 2
                anchor = start(['unshare', '--net', '--', 'sleep', '300'], name + '-netns', directory)
                deadline = time.monotonic() + 3
                while Path(f'/proc/{anchor.pid}/ns/net').readlink() == Path('/proc/self/ns/net').readlink():
                    if time.monotonic() > deadline: raise TimeoutError('Could not initialize test network namespace')
                    time.sleep(.01)
                outer, inner = 'cp' + str(index), 'ci' + str(index)
                subprocess.run(['ip', 'link', 'add', outer, 'type', 'veth', 'peer', 'name', inner], check=True)
                subprocess.run(['ip', 'link', 'set', inner, 'netns', str(anchor.pid)], check=True)
                subprocess.run(['ip', 'addr', 'add', f'10.203.{index}.1/30', 'dev', outer], check=True)
                subprocess.run(['ip', 'link', 'set', outer, 'up'], check=True)
                prefix = ['nsenter', '-t', str(anchor.pid), '-n', '--']
                for command in (['ip', 'link', 'set', 'lo', 'up'],
                    ['ip', 'addr', 'add', f'10.203.{index}.2/30', 'dev', inner],
                    ['ip', 'link', 'set', inner, 'up'],
                    ['ip', 'route', 'add', 'default', 'via', f'10.203.{index}.1']):
                    subprocess.run(prefix + command, check=True)
            process = start(prefix + [Path(args.c_client).resolve(), '--config', config], name, directory)
            c_processes.append((process, name))
            return process

        client('fast-target-a', 'c', [])
        client('fast-target-b', 'c', [])
        for transport in ('tcp', 'quic'):
            client('fast-source-' + transport, 'c',
                rules('fast-target-a', transport, 'A-B-' + transport) +
                rules('fast-target-b', transport, 'A-C-' + transport))
            client('fast-remote-' + ('TCP' if transport == 'tcp' else 'QUIC'), 'remote',
                rules('fast-target-b', transport, 'B-C-' + transport,
                      '10.203.1.2' if transport == 'tcp' else '10.203.2.2'))

        def online():
            data = api('/api/v1/devices').get('nodes') or []
            return set(nodes) <= {n['name'] for n in data if n.get('lanip')}
        wait(online)
        results['all_six_clients_authenticated'] = True
        results['sixteen_digit_install_token'] = True
        print('Six fastp2p C clients authenticated', flush=True)
        for name, proto, port, host in cases:
            wait(lambda p=port, pr=proto, h=host: tcp_roundtrip(p,h) if pr == 'tcp' else udp_roundtrip(p,h), timeout=65)
            results[name] = {'success': True, 'bytes': 262144 if proto == 'tcp' else 1000}
            print(name + ' passed', flush=True)

        # Verify real tunnel selection in both local and routed C clients.
        for transport in ('tcp', 'quic'):
            expected = 'TCP tunnel connected' if transport == 'tcp' else 'QUIC tunnel connected'
            for name in ['fast-source-' + transport, 'fast-remote-' + ('TCP' if transport == 'tcp' else 'QUIC')]:
                assert expected in (logs / (name + '.log')).read_text()
        results['transports_confirmed_in_logs'] = True
        for name, proto, port, host in cases:
            if proto == 'tcp':
                wait(lambda p=port, h=host: tcp_final_response(p,h))
        results['final_tcp_bytes_drained_before_peer_disconnect'] = True
        print('Final TCP responses preserved before disconnect', flush=True)

        if not args.quick:
            print('Checking heartbeats for 35 seconds', flush=True)
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                assert all(p.poll() is None for p in processes)
                time.sleep(.5)
            assert online()
            for _, proto, port, host in cases:
                assert tcp_roundtrip(port,host) if proto == 'tcp' else udp_roundtrip(port,host)
            results['heartbeat_and_forwarding_after_35s'] = True
            gateway.terminate()
            gateway.wait(timeout=5)
            processes.remove(gateway)
            gateway = start(gateway_args, 'gateway-restarted', runtime, credentials)
            jwt = None
            wait(lambda: api('/healthz', auth=False))
            jwt = api('/api/v1/user/login', {'user': credentials['FASTP2P_USER'], 'password': password}, False)['token']
            wait(lambda: set(nodes) <=
                 {n['name'] for n in (api('/api/v1/devices').get('nodes') or [])})
            for name, proto, port, host in cases:
                wait(lambda p=port, pr=proto, h=host: tcp_roundtrip(p,h) if pr == 'tcp' else udp_roundtrip(p,h))
            results['gateway_restart_reconnected_c_clients'] = True
        results['success'] = True
finally:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    for server in echo_servers:
        server.shutdown()
        server.server_close()
    for handle in handles:
        handle.close()
    shutdown_errors = []
    for process, name in c_processes:
        diagnostic = (logs / (name + '.log')).read_text(errors='replace')
        if process.returncode != 0 or 'Sanitizer' in diagnostic or 'runtime error:' in diagnostic:
            shutdown_errors.append(name)
    if shutdown_errors:
        results['success'] = False
        results['shutdown_errors'] = shutdown_errors
    (logs / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))
    if shutdown_errors:
        raise RuntimeError('C client shutdown or sanitizer failure: ' + ', '.join(shutdown_errors))
