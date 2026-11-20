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
import struct
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


class IPv6TCPEchoServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6


class IPv6UDPEchoServer(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET6


class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


def socks_ipv6_roundtrip(proxy_port, target_port):
    target = b'\x04' + socket.inet_pton(socket.AF_INET6, '::1') + struct.pack('!H', target_port)
    for command in (1, 3):
        with socket.create_connection(('::1', proxy_port), timeout=8) as sock, sock.makefile('rb') as reply:
            sock.sendall(b'\x05\x01\x00')
            assert reply.read(2) == b'\x05\x00'
            requested = target if command == 1 else b'\x04' + bytes(18)
            sock.sendall(bytes((5, command, 0)) + requested)
            assert reply.read(4) == b'\x05\x00\x00\x04'
            host = socket.inet_ntop(socket.AF_INET6, reply.read(16))
            port, = struct.unpack('!H', reply.read(2))
            payload = b'IPv6 SOCKS5 payload'
            if command == 1:
                sock.sendall(payload)
                assert reply.read(len(payload)) == payload
            else:
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
                    packet = bytes(3) + target + payload
                    udp.settimeout(8)
                    udp.connect((host, port))
                    udp.send(packet)
                    assert udp.recv(4096) == packet
    return True


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

        def client(name, host, apps=(), public_port=0, socks5=(), hosts=None):
            directory = runtime / name
            directory.mkdir(mode=0o700)
            cfg = {'product': 'fastp2p', 'network': {'Node': name, 'Token': install_token, 'ServerHost': host,
                               'ServerPort': 27183, 'ShareBandwidth': 0,
                               'UDPSTUNServers': [], 'TCPNatProbe': ''},
                   'CACertFile': str(certs / 'ca.crt'), 'LogLevel': 0,
                   'apps': list(apps), 'socks5': list(socks5)}
            if public_port:
                cfg['network']['PublicIPPort'] = public_port
            path = directory / 'config.json'
            path.write_text(json.dumps(cfg))
            path.chmod(0o600)
            command = [Path(args.c_client).resolve(), '--config', path]
            if hosts:
                command = ['unshare', '--mount', '--propagation', 'private', '--', 'sh', '-c',
                           'mount --bind "$1" /etc/hosts && shift && exec "$@"', 'sh', hosts, *command]
            process = start(command, name, directory)
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
        def rule(device, name, port, peer, punch_priority=3):
            # A successful create answers 200 with an empty body, so the stored
            # rule is what proves the call landed.
            api('/api/v1/device/%s/app' % device,
                {'appName': name, 'protocol': 'tcp', 'srcPort': port,
                 'peerNode': peer, 'dstHost': '127.0.0.1',
                 'dstPort': echo_port, 'punchPriority': punch_priority})
            stored = api('/api/v1/device/%s/apps' % device).get('Apps') or []
            assert any(int(a.get('srcPort') or 0) == port for a in stored), \
                'the rule for %s was not stored' % device

        rule_port = 26500
        rule('dual-source-v6', 'v6-tunnel', rule_port, 'dual-target-v6')
        wait(lambda: tcp_roundtrip(rule_port), timeout=90, what='data through a v6 tunnel')
        text = (logs / 'dual-source-v6.log').read_text(errors='replace')
        assert 'TCP peer listener connected' in text, 'IPv6 did not use the shared TCP listener'
        peer_port = node_record('dual-target-v6')['publicIPPort']
        assert 1024 <= peer_port <= 9999
        profile = runtime / 'dual-target-v6' / 'config.json'
        assert json.loads(profile.read_text())['network']['PublicIPPort'] == peer_port
        results['tunnel_and_forwarding_over_ipv6'] = True

        assert node_record('dual-target-v6')['publicUDP'] == 1
        for suffix, app_port in [('a', 26503), ('b', 26504)]:
            name = f'quic-source-{suffix}'
            client(name, '::1')
            wait(lambda: (node_record(name) or {}).get('isActive'), what=f'{name} to register')
            rule(name, f'quic-direct-{suffix}', app_port, 'dual-target-v6', punch_priority=4)
        wait(lambda: tcp_roundtrip(26503) and tcp_roundtrip(26504),
             what='two QUIC sessions on the same UDP peer listener')
        for suffix in ('a', 'b'):
            assert 'UDP peer listener connected' in (logs / f'quic-source-{suffix}.log').read_text()
        assert (logs / 'dual-target-v6.log').read_text().count('UDP peer listener accepted connection') >= 2
        results['two_quic_peers_share_one_udp_listener'] = True

        v6_tcp = IPv6TCPEchoServer(('::1', 0), TCPEcho)
        v6_udp = IPv6UDPEchoServer(v6_tcp.server_address[:2], UDPEcho)
        for echo in (v6_tcp, v6_udp):
            echo.daemon_threads = True
            echo_servers.append(echo)
            threading.Thread(target=echo.serve_forever, daemon=True).start()
        client('socks-v6-entry', '::1', socks5=[{'Name': 'socks-ipv6', 'SrcPort': 26506,
                                               'BindIP': '::1', 'PeerNode': 'dual-target-v6',
                                               'UnderlayProtocol': 'quic'}])
        wait(lambda: (node_record('socks-v6-entry') or {}).get('isActive'), what='the SOCKS5 entry to register')
        wait(lambda: socks_ipv6_roundtrip(26506, v6_tcp.server_address[1]),
             what='SOCKS5 IPv6 CONNECT and UDP ASSOCIATE')
        results['socks5_ipv6_tcp_and_udp'] = True

        # IPv6 coordination still works while the IPv6 peer path drops traffic.
        hosts = runtime / 'dualstack-hosts'
        hosts.write_text('127.0.0.1 localhost\n::1 localhost\n')
        fallback_rules = [
            {'AppName': f'fallback-{transport}', 'Protocol': 'tcp', 'SrcPort': port,
             'PeerNode': 'dual-target-both', 'DstHost': '127.0.0.1', 'DstPort': echo_port,
             'UnderlayProtocol': transport}
            for transport, port in (('quic', 26507), ('tcp', 26508))
        ]
        blocked_v6 = [['OUTPUT', '-d', '::1', '-p', proto, '!', '--dport', '27180:27183',
                       '!', '--sport', '27180:27183', '-j', 'DROP'] for proto in ('tcp', 'udp')]
        for block in blocked_v6:
            subprocess.run(['ip6tables', '-A', *block], check=True)
        try:
            client('dual-target-both', 'localhost', hosts=hosts)
            wait(lambda: (node_record('dual-target-both') or {}).get('families') == 3,
                 what='dual-stack target registration')
            client('dual-source-both', 'localhost', apps=fallback_rules, hosts=hosts)
            wait(lambda: (node_record('dual-source-both') or {}).get('families') == 3,
                 what='dual-stack source registration')
            wait(lambda: tcp_roundtrip(26507) and tcp_roundtrip(26508),
                 timeout=65, what='TCP and QUIC forwarding after IPv6 fails')
            fallback_log = (logs / 'dual-source-both.log').read_text()
            assert fallback_log.count('IPv6 direct attempt failed; retrying over IPv4') == 2
        finally:
            for block in blocked_v6:
                subprocess.run(['ip6tables', '-D', *block], check=True)
        results['dual_stack_tcp_and_quic_fall_back_to_ipv4'] = True

        # --- the same gateway still serves IPv4 -----------------------------
        client('dual-target-v4', '127.0.0.1', public_port=8234)
        client('dual-source-v4', '127.0.0.1')
        wait(lambda: (node_record('dual-source-v4') or {}).get('isActive') and
                     (node_record('dual-target-v4') or {}).get('isActive'),
             what='both IPv4 clients to register')
        v4_port = 26501
        assert node_record('dual-target-v4')['publicIPPort'] == 8234
        blocked_port = ['OUTPUT', '-p', 'tcp', '--dport', '8234', '-j', 'DROP']
        subprocess.run(['iptables', '-A', *blocked_port], check=True)
        try:
            rule('dual-source-v4', 'v4-tunnel', v4_port, 'dual-target-v4')
            wait(lambda: tcp_roundtrip(v4_port), timeout=90, what='TCP punch after the peer listener times out')
            text = (logs / 'dual-source-v4.log').read_text(errors='replace')
            assert 'TCP punch connect attempt' in text and 'TCP peer listener connected' not in text
        finally:
            subprocess.run(['iptables', '-D', *blocked_port], check=True)
        results['blocked_tcp_peer_listener_falls_back_to_punch'] = True

        blocked_udp = ['INPUT', '-p', 'udp', '--dport', '8234', '-j', 'DROP']
        subprocess.run(['iptables', '-A', *blocked_udp], check=True)
        try:
            rule('dual-source-v4', 'blocked-quic', 26505, 'dual-target-v4', punch_priority=4)
            wait(lambda: tcp_roundtrip(26505), timeout=60,
                 what='QUIC punch after the UDP peer listener times out')
            text = (logs / 'dual-source-v4.log').read_text(errors='replace')
            assert 'tunnel establishment timed out' in text
            assert 'QUIC tunnel connected' in text and 'UDP peer listener connected' not in text
        finally:
            subprocess.run(['iptables', '-D', *blocked_udp], check=True)
        results['blocked_udp_peer_listener_falls_back_to_punch'] = True

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(('127.0.0.1', 9234))
            client('occupied-udp-port', '127.0.0.1', public_port=9234)
            wait(lambda: (node_record('occupied-udp-port') or {}).get('publicIPPort') == 9234,
                 what='the pinned TCP listener to register with its UDP port occupied')
            assert node_record('occupied-udp-port')['publicUDP'] == 0
            with socket.create_connection(('127.0.0.1', 9234), timeout=2):
                pass
        results['occupied_pinned_udp_port_retains_tcp_listener'] = True

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
        rule('dual-source-v4', 'mixed-family', 26502, 'dual-target-v6', punch_priority=4)
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
