#!/usr/bin/env python3
"""IPv4/IPv6 dual-stack end to end: registration, per-family NAT levels, tunnels.

Every address here is loopback (``::1`` and ``127.0.0.1``), so the test needs no
internet IPv6 and no routing setup beyond the isolated namespace the caller
provides: a public prefix is not part of the contract being verified. What it
does verify is that the whole stack -- control connection, mapping probes, punch
negotiation, session setup and forwarding -- works when the endpoints meet over
IPv6 exactly as they do today over IPv4.

Requires root + `unshare --net`.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
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
args = parser.parse_args()
if Path('/proc/self/ns/net').readlink() == Path('/proc/1/ns/net').readlink():
    raise SystemExit('Run in a separate network namespace to avoid deployed services')
logs = Path(args.logs).resolve()
logs.mkdir(parents=True, exist_ok=True)
certs = Path(args.cert_dir).resolve()
context = ssl.create_default_context(cafile=str(certs / 'ca.crt'))

processes, handles, echo_servers, c_processes = [], [], [], []
results = {}
password = secrets.token_urlsafe(24)
install_token = secrets.randbelow(9 * 10**15) + 10**15
credentials = {'FASTP2P_USER': 'dualstack-user', 'FASTP2P_PASSWORD': password,
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


def wait(check, timeout=60, what='condition'):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('a process exited while waiting for ' + what)
        try:
            value = check()
            if value:
                return value
        except (OSError, urllib.error.URLError, ValueError) as exc:
            error = type(exc).__name__
        time.sleep(.15)
    raise TimeoutError('timed out waiting for %s (%s)' % (what, error))


class TCPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except OSError:
            pass


def tcp_roundtrip(port, host='127.0.0.1'):
    payload = secrets.token_bytes(65536)
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.settimeout(8)
        sock.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            data = sock.recv(65536)
            if not data:
                return False
            received.extend(data)
    return received == payload


def node_record(name):
    for entry in api('/api/v1/nodes?limit=100').get('nodes', []):
        if entry.get('name') == name:
            return entry
    return None


try:
    with tempfile.TemporaryDirectory(prefix='fastp2p-dualstack-') as runtime:
        runtime = Path(runtime)
        runtime.chmod(0o700)

        # --- gateway listening on both loopback families -------------------
        gateway_args = [Path(args.gateway).resolve(), '-bind', '127.0.0.1', '-bind6', '::1',
                        '-apibind', '127.0.0.1', '-cert', certs / 'server.crt',
                        '-key', certs / 'server.key']
        gateway = start(gateway_args, 'gateway', runtime, credentials)
        wait(lambda: api('/healthz', auth=False), what='the dual-stack gateway to answer')
        ready = json.loads((logs / 'gateway.log').read_text().splitlines()[0])
        assert ready.get('ipv6') == 1, 'gateway did not open its IPv6 listeners'

        # A client speaks to the gateway over IPv6 only when its name has no A
        # record at all, which "::1" guarantees.
        listening = subprocess.run(['ss', '-lnt'], capture_output=True, text=True).stdout
        assert '[::1]:27183' in listening, 'the gateway has no IPv6 WSS listener'
        results['gateway_listens_on_ipv6_and_ipv4'] = True

        # --- per-family NAT probe ports ------------------------------------
        probing = subprocess.run(['ss', '-lnu'], capture_output=True, text=True).stdout
        for port in ('27180', '27181', '27182', '27183'):
            assert '[::1]:' + port in probing, 'no IPv6 UDP probe socket on ' + port
        results['ipv6_udp_probe_ports_bound'] = True

        jwt = api('/api/v1/user/login',
                  {'user': credentials['FASTP2P_USER'], 'password': password}, False)['token']

        server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), TCPEcho)
        server.daemon_threads = True
        echo_servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        echo_port = server.server_address[1]

        def client(name, host, apps=(), public_port=0):
            directory = runtime / name
            directory.mkdir(mode=0o700)
            cfg = {'network': {'Node': name, 'Token': install_token, 'ServerHost': host,
                               'ServerPort': 27183, 'ShareBandwidth': 0},
                   'CACertFile': str(certs / 'ca.crt'), 'LogLevel': 0, 'apps': list(apps)}
            if public_port:
                cfg['network']['PublicIPPort'] = public_port
            path = directory / 'config.json'
            path.write_text(json.dumps(cfg))
            path.chmod(0o600)
            process = start([Path(args.c_client).resolve(), '--config', path], name, directory)
            c_processes.append((process, name))
            return process

        # --- two nodes meeting over IPv6 ------------------------------------
        client('dual-target-v6', '::1')
        client('dual-source-v6', '::1')
        wait(lambda: (node_record('dual-target-v6') or {}).get('isActive') and
                     (node_record('dual-source-v6') or {}).get('isActive'),
             what='both IPv6 clients to register')
        results['ipv6_only_clients_registered'] = True

        for name in ('dual-target-v6', 'dual-source-v6'):
            entry = node_record(name)
            assert int(entry.get('families') or 0) & 2, name + ' did not report IPv6 capability'
            # The gateway observed the connection itself, so the v6 address is
            # proof of a real IPv6 control connection rather than a self-report.
            assert (entry.get('ipv6') or '').strip(), name + ' has no observed IPv6 address'
            assert int(entry.get('udpNatType6') or 0) in (1, 2, 3, 4, 314), \
                name + ' reported no IPv6 UDP mapping level'
            assert int(entry.get('tcpNatType6') or 0) in (1, 2, 314), \
                name + ' reported no IPv6 TCP mapping level'
        results['per_family_nat_levels_reported_for_ipv6'] = True

        # --- forwarding across the IPv6 tunnel ------------------------------
        def rule(device, name, port, peer):
            # A successful create answers 200 with an empty body, so the stored
            # rule is what proves the call landed.
            api('/api/v1/device/%s/app' % device,
                {'appName': name, 'protocol': 'tcp', 'srcPort': port,
                 'peerNode': peer, 'dstHost': '127.0.0.1',
                 'dstPort': echo_port, 'punchPriority': 4})
            stored = api('/api/v1/device/%s/apps' % device).get('Apps') or []
            assert any(int(a.get('srcPort') or 0) == port for a in stored), \
                'the rule for %s was not stored' % device

        rule_port = 26500
        rule('dual-source-v6', 'v6-tunnel', rule_port, 'dual-target-v6')
        wait(lambda: tcp_roundtrip(rule_port), timeout=90, what='data through a v6 tunnel')
        text = (logs / 'dual-source-v6.log').read_text(errors='replace')
        assert 'tunnel connected' in text, 'no tunnel was established for the IPv6 pair'
        results['tunnel_and_forwarding_over_ipv6'] = True

        # --- the same gateway still serves IPv4 -----------------------------
        client('dual-target-v4', '127.0.0.1')
        client('dual-source-v4', '127.0.0.1')
        wait(lambda: (node_record('dual-source-v4') or {}).get('isActive') and
                     (node_record('dual-target-v4') or {}).get('isActive'),
             what='both IPv4 clients to register')
        v4_port = 26501
        rule('dual-source-v4', 'v4-tunnel', v4_port, 'dual-target-v4')
        wait(lambda: tcp_roundtrip(v4_port), timeout=90, what='data through a v4 tunnel')
        results['ipv4_path_unchanged'] = True

        # A v4-only client must still report exactly the historical fields, with
        # no IPv6 capability invented for it.
        v4_entry = node_record('dual-source-v4')
        assert int(v4_entry.get('families') or 0) == 1, 'an IPv4 client claimed another family'
        assert not (v4_entry.get('ipv6') or '').strip(), 'an IPv4 client reported an IPv6 address'
        results['ipv4_client_reports_only_ipv4'] = True

        # --- mixed family pair: must not hang -------------------------------
        # dual-source-v4 has no IPv6 at all; asking it to reach the v6 node has
        # to fail over instead of stalling. Any outcome other than a hang is
        # acceptable, so the assertion is that both clients stay alive.
        rule('dual-source-v4', 'mixed-family', 26502, 'dual-target-v6')
        time.sleep(12)
        assert all(p.poll() is None for p in processes), 'a mixed-family pair crashed a client'
        results['mixed_family_pair_degrades_without_hanging'] = True

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
    failures = []
    for process, name in c_processes:
        diagnostic = (logs / (name + '.log')).read_text(errors='replace')
        if process.returncode != 0 or 'Sanitizer' in diagnostic or 'runtime error:' in diagnostic:
            failures.append(name)
    if failures:
        results['success'] = False
        results['client_failures'] = failures
    (logs / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))
    if failures:
        raise RuntimeError('client shutdown or sanitizer failure: ' + ', '.join(failures))
