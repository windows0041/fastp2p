#!/usr/bin/env python3
"""TCP NAT level, driven by a controllable probe server.

The callback path itself needs two real public addresses, so that part is proved
separately (see scripts/stun/README.md). What this test pins down is the contract
the client depends on: read the greeting, ask for the probe, parse the verdict line
and turn it into a level - plus the "no answer means no level" rule that keeps the
console from inventing one.

  same-port=1 other-ip=1 -> 1
  same-port=1 other-ip=0 -> 2
  same-port=0 other-ip=0 -> 3
  silence                -> 0 (never a level)
"""
import argparse, json, os, secrets, socket, ssl, subprocess, sys, tempfile, threading, time
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
context = ssl.create_default_context(cafile=str(certs / 'ca.crt'))
processes, handles, results = [], [], {}


class ProbeServer(threading.Thread):
    """Answers the greeting and reports the callbacks it 'established'."""

    def __init__(self, verdict, answered=True):
        super().__init__(daemon=True)
        self.verdict = verdict      # e.g. 'same-port=1 other-ip=1'
        self.answered = answered    # False models a server that never reports
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.running = True

    def run(self):
        while self.running:
            try:
                conn, peer = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn, peer), daemon=True).start()

    def serve(self, conn, peer):
        try:
            conn.settimeout(20)
            conn.sendall(('mapped %s %d\n' % peer[:2]).encode())
            line = conn.makefile().readline().strip()
            if not line.startswith('probe'):
                return
            if self.answered:
                conn.sendall((self.verdict + '\n').encode())
            else:
                time.sleep(12)  # longer than the client's window
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


def wait(check, timeout=90, what='condition'):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('a process exited while waiting for ' + what)
        try:
            value = check()
            if value is not None:
                return value
        except (OSError, urllib.error.URLError, ValueError, KeyError) as exc:
            error = type(exc).__name__
        time.sleep(.2)
    raise TimeoutError('timed out waiting for %s (%s)' % (what, error))


def start(command, name, directory, env=None):
    out = (logs / (name + '.log')).open('w')
    handles.append(out)
    child_env = os.environ.copy()
    child_env.update(env or {})
    child = subprocess.Popen([str(x) for x in command], cwd=directory, env=child_env,
                             stdout=out, stderr=subprocess.STDOUT)
    processes.append(child)
    return child


def verdict_from_log(name):
    text = (logs / (name + '.log')).read_text(errors='replace')
    marker = 'TCP NAT level: '
    index = text.rfind(marker)
    if index < 0:
        return None
    return int(text[index + len(marker)])


password = secrets.token_urlsafe(24)
token = secrets.randbelow(9 * 10**15) + 10**15
credentials = {'FASTP2P_USER': 'tcp-level', 'FASTP2P_PASSWORD': password,
               'FASTP2P_TOKEN': str(token)}
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


def node(name):
    for entry in api('/api/v1/nodes?limit=100').get('nodes', []):
        if entry.get('name') == name:
            return entry
    return None


try:
    with tempfile.TemporaryDirectory(prefix='fastp2p-tcplevel-') as runtime:
        runtime = Path(runtime)
        runtime.chmod(0o700)
        start([Path(args.gateway).resolve(), '-bind', '127.0.0.1', '-apibind', '127.0.0.1',
               '-cert', certs / 'server.crt', '-key', certs / 'server.key'],
              'gateway', runtime, credentials)
        wait(lambda: api('/healthz', auth=False), what='the gateway')
        jwt = api('/api/v1/user/login',
                  {'user': credentials['FASTP2P_USER'], 'password': password}, False)['token']

        for label, verdict, answered, expected in (
                ('both', 'same-port=1 other-ip=1', True, 1),
                ('address', 'same-port=1 other-ip=0', True, 2),
                ('port', 'same-port=0 other-ip=0', True, 3),
                ('silent', 'unused', False, 0)):
            server = ProbeServer(verdict, answered)
            server.start()
            name = 'tcp-' + label
            directory = runtime / name
            directory.mkdir()
            config = {'network': {
                'Node': name, 'Token': token, 'ServerHost': '127.0.0.1', 'ServerPort': 27183,
                'TCPNatProbe': '127.0.0.1:%d' % server.port},
                'CACertFile': str(certs / 'ca.crt'), 'apps': []}
            path = directory / 'config.json'
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            start([Path(args.c_client).resolve(), '--config', path], name, directory)

            wait(lambda n=name: verdict_from_log(n), timeout=90,
                 what=label + ' to reach a verdict')
            level = verdict_from_log(name)
            print('%s -> level %d (expected %d)' % (label, level, expected), flush=True)
            assert level == expected, '%s: expected %d, got %d' % (label, expected, level)
            if expected:
                wait(lambda n=name, e=expected: (node(n) or {}).get('tcpNatLevel') == e,
                     timeout=40, what=label + ' to store level %d' % expected)
            else:
                # No verdict must never reach the gateway as a level.
                assert (node(name) or {}).get('tcpNatLevel') in (0, None), \
                    'a missing verdict must not be reported as a level'
            results['tcp ' + label] = level
            server.stop()

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
