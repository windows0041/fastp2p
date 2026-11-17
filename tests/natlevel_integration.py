#!/usr/bin/env python3
"""NAT level detection driven by a controllable STUN responder.

A real NAT is not needed here: the responder decides what comes back, which is
exactly the observable a NAT controls. Each case makes the responder behave like
one NAT flavour and asserts the level the client publishes:

    full  - answers from another address        -> NAT1
    addr  - answers from another port only      -> NAT2
    port  - answers only the exact tuple        -> NAT3
    sym   - reports a different mapping per server -> NAT4

Requires root + `unshare --net` (the gateway needs the same isolation as the
other integration tests).
"""
import argparse, json, os, secrets, socket, struct, subprocess, sys, tempfile, threading, time
from pathlib import Path
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument('--gateway', required=True)
parser.add_argument('--c-client', required=True)
parser.add_argument('--cert-dir', required=True)
parser.add_argument('--logs', required=True)
args = parser.parse_args()
if Path('/proc/self/ns/net').readlink() == Path('/proc/1/ns/net').readlink():
    raise SystemExit('Run in a separate network namespace')

logs = Path(args.logs).resolve()
logs.mkdir(parents=True, exist_ok=True)
certs = Path(args.cert_dir).resolve()
context = __import__('ssl').create_default_context(cafile=str(certs / 'ca.crt'))
processes, handles, results = [], [], {}
password = secrets.token_urlsafe(24)
token = secrets.randbelow(9 * 10**15) + 10**15
credentials = {'FASTP2P_USER': 'stun-user', 'FASTP2P_PASSWORD': password,
               'FASTP2P_TOKEN': str(token)}
jwt = None
MAGIC = 0x2112A442
ALT_IP = '127.0.0.2'


def api(path, data=None, auth=True):
    req = urllib.request.Request('https://127.0.0.1:10008' + path,
                                 data=json.dumps(data).encode() if data is not None else None,
                                 headers={'Content-Type': 'application/json'})
    if auth and jwt:
        req.add_header('Authorization', jwt)
    with urllib.request.urlopen(req, context=context, timeout=3) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


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
        except (OSError, urllib.error.URLError, ValueError, KeyError) as exc:
            error = type(exc).__name__
        time.sleep(.2)
    raise TimeoutError('timed out waiting for %s (%s)' % (what, error))


def response(transaction, mapped_port, alternate=None):
    """BINDING success with XOR-MAPPED-ADDRESS and, when the responder stands in
    for an RFC 5780 server, OTHER-ADDRESS naming the change-ip source."""
    xport = mapped_port ^ (MAGIC >> 16)
    cookie = struct.pack('!I', MAGIC)
    addr = bytes(a ^ b for a, b in zip(socket.inet_aton('127.0.0.1'), cookie))
    value = bytes([0, 1]) + struct.pack('!H', xport) + addr
    attr = struct.pack('!HH', 0x0020, len(value)) + value
    if alternate:
        other = bytes([0, 1]) + struct.pack('!H', alternate[1]) + socket.inet_aton(alternate[0])
        attr += struct.pack('!HH', 0x802C, len(other)) + other
    return struct.pack('!HHI', 0x0101, len(attr), MAGIC) + transaction + attr


class StunResponder(threading.Thread):
    """One STUN server whose answers stand in for a NAT's filtering behaviour."""

    def __init__(self, mode, port_report=None, advertise_alternate=True):
        super().__init__(daemon=True)
        self.mode = mode
        self.port_report = port_report
        # A responder that advertises OTHER-ADDRESS declares it implements
        # change-ip, so a dropped reply becomes evidence of filtering. The
        # "silent" flavour advertises nothing and ignores the attribute, which is
        # what public RFC 5389 servers do - and must not be read as NAT3.
        self.advertise_alternate = advertise_alternate
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.alt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.alt.bind(('127.0.0.1', 0))
        self.alt_ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.alt_ip.bind((ALT_IP, 0))
        self.running = True

    def run(self):
        while self.running:
            try:
                data, peer = self.sock.recvfrom(2048)
            except OSError:
                return
            if len(data) < 20:
                continue
            transaction = data[8:20]
            changed = 0
            offset = 20
            while offset + 4 <= len(data):
                atype, alen = struct.unpack('!HH', data[offset:offset + 4])
                if atype == 0x0003 and alen == 4:
                    # Attribute value follows the 4-byte TLV header.
                    changed = struct.unpack('!I', data[offset + 4:offset + 8])[0]
                    break
                offset += 4 + ((alen + 3) & ~3)
            change_port = bool(changed & 0x02)
            change_ip = bool(changed & 0x04)
            mapped = self.port_report if self.port_report else peer[1]
            alternate = (ALT_IP, self.alt_ip.getsockname()[1]) if self.advertise_alternate else None
            payload = response(transaction, mapped, alternate)
            if change_ip:
                # A server that does not implement the attribute answers from the
                # same tuple (or not at all); either way nothing is proven.
                if not self.advertise_alternate or self.mode in ('port', 'addr'):
                    continue
                self.alt_ip.sendto(payload, peer)
            elif change_port:
                if self.mode == 'port':
                    continue
                self.alt.sendto(payload, peer)
            else:
                self.sock.sendto(payload, peer)

    def stop(self):
        self.running = False
        for sock in (self.sock, self.alt, self.alt_ip):
            sock.close()


def start(command, name, directory, env=None):
    out = (logs / (name + '.log')).open('w')
    handles.append(out)
    child_env = os.environ.copy()
    child_env.update(env or {})
    child = subprocess.Popen([str(x) for x in command], cwd=directory, env=child_env,
                             stdout=out, stderr=subprocess.STDOUT)
    processes.append(child)
    return child


def node(name):
    for entry in api('/api/v1/nodes?limit=100').get('nodes', []):
        if entry.get('name') == name:
            return entry
    return None


try:
    with tempfile.TemporaryDirectory(prefix='fastp2p-stun-') as runtime:
        runtime = Path(runtime)
        runtime.chmod(0o700)
        gateway = start([Path(args.gateway).resolve(), '-bind', '127.0.0.1', '-apibind', '127.0.0.1',
                         '-cert', certs / 'server.crt', '-key', certs / 'server.key'],
                        'gateway', runtime, credentials)
        wait(lambda: api('/healthz', auth=False), what='the gateway')
        jwt = api('/api/v1/user/login',
                  {'user': credentials['FASTP2P_USER'], 'password': password}, False)['token']

        for label, mode, servers, expected, advertise in (
                ('full', 'full', 1, 1, True),
                ('addr', 'addr', 1, 2, True),
                ('port', 'port', 1, 3, True),
                ('sym', 'sym', 2, 4, True),
                # A public server that ignores CHANGE-REQUEST must not be read as
                # "port restricted": the level stays undetermined (5 = NAT1/2).
                ('silent', 'port', 1, 5, False)):
            responders = []
            endpoints = []
            for index in range(servers):
                # In "sym" every server reports a different mapping.
                port_report = None
                if mode == 'sym':
                    port_report = 40000 + index * 7
                responder = StunResponder(mode, port_report, advertise)
                responder.start()
                responders.append(responder)
                endpoints.append('127.0.0.1:%d' % responder.port)

            name = 'stun-' + label
            directory = runtime / name
            directory.mkdir()
            cfg = {'network': {'Node': name, 'Token': token, 'ServerHost': '127.0.0.1',
                               'ServerPort': 27183, 'UDPSTUNServers': endpoints},
                   'CACertFile': str(certs / 'ca.crt'), 'apps': []}
            path = directory / 'config.json'
            path.write_text(json.dumps(cfg))
            path.chmod(0o600)
            start([Path(args.c_client).resolve(), '--config', path], name, directory)

            # Wait for the *verdict line* rather than the stored field: 5 is also
            # the value before any STUN answer exists, so the field alone cannot
            # prove the "no evidence, no conclusion" rule fired.
            def verdict(n=name):
                text = (logs / (n + '.log')).read_text(errors='replace')
                marker = 'STUN NAT level: '
                index = text.rfind(marker)
                if index < 0:
                    return None
                return int(text[index + len(marker)])

            wait(verdict, timeout=60, what=label + ' to reach a STUN verdict')
            level = verdict()
            print('%s -> NAT%d (expected NAT%d)' % (label, level, expected), flush=True)
            assert level == expected, '%s: expected NAT%d, got NAT%d' % (label, expected, level)
            wait(lambda n=name, e=expected: (node(n) or {}).get('natLevel') == e,
                 timeout=30, what=label + ' to publish NAT%d' % expected)
            results['stun ' + label] = level

            for responder in responders:
                responder.stop()

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
    for handle in handles:
        handle.close()
    (logs / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))

