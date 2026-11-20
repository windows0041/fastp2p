#!/usr/bin/env python3
"""Punch with a peer that reports a symmetric NAT.

A symmetric peer cannot be reached at the port it publishes, so it also
advertises a window around that port and the other side sprays it during the
punch.  Without a matching NAT the path is never exercised, so the
FASTP2P_NAT_TYPE diagnostic switch stands in for one: the responder claims an
incrementing (3), a hard (2) or a cone (1, the control) mapping.

The window is only advertised over the QUIC underlay, so `--transport quic` is
the run that exercises the announcement; the TCP run guards the opposite
property - the extra fields must not disturb a punch that uses port prediction
instead.

The test asserts the session still completes and carries traffic. It reserves
the QUIC listener ports so the peers negotiate a punch instead of dialing the
shared listener. When both sides are symmetric it also checks the punch roles.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

TOKEN = 1234567890123456
PASSWORD = 'natwindowpassword1'
USER = 'natwindow-admin'
ECHO_PORT = 9996
SOURCE_PORT = 27000


def run(command, check=True):
    return subprocess.run(command, check=check, capture_output=True, text=True)


def wait(check, timeout=60, interval=0.5, what='condition'):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except Exception as exc:  # noqa: BLE001
            error = exc
        time.sleep(interval)
    raise TimeoutError('timed out waiting for %s: %s' % (what, error))


def log_text(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return ''


def roundtrip(port, payload, expect):
    with socket.create_connection(('127.0.0.1', port), timeout=20) as sock:
        sock.settimeout(20)
        sock.sendall(payload)
        return sock.recv(len(expect)) == expect


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--cert-dir', required=True)
    parser.add_argument('--logs', required=True)
    parser.add_argument('--nat-type', default='3', choices=('1', '2', '3', '4'),
                        help='NAT type the responder claims; 1 is the control run')
    parser.add_argument('--source-nat-type', default='1', choices=('1', '2', '3', '4'))
    parser.add_argument('--legacy-source', help='Optional previous client to use for the initiator')
    parser.add_argument('--transport', default='tcp', choices=('tcp', 'quic'),
                        help='underlay to punch over; the window is QUIC-only')
    args = parser.parse_args()

    client = str(Path(args.client).resolve())
    source_client = str(Path(args.legacy_source).resolve()) if args.legacy_source else client
    gateway = str(Path(args.gateway).resolve())
    certs = Path(args.cert_dir).resolve()
    logs = Path(args.logs).resolve()
    logs.mkdir(parents=True, exist_ok=True)
    runtime = logs.parent

    env = os.environ.copy()
    env.update(FASTP2P_USER=USER, FASTP2P_PASSWORD=PASSWORD, FASTP2P_TOKEN=str(TOKEN),
               FASTP2P_TLS_CERT=str(certs / 'server.crt'), FASTP2P_TLS_KEY=str(certs / 'server.key'),
               FASTP2P_CA_FILE=str(certs / 'ca.crt'),
               FASTP2P_DATABASE=str(runtime / 'nodes.sqlite3'),
               FASTP2P_PUBLIC_HOST='127.0.0.1')

    processes = []
    reserved_udp = []

    def start(command, name, prefix=None):
        handle = (logs / (name + '.log')).open('w')
        process = subprocess.Popen((prefix or []) + command, cwd=runtime, env=env,
                                   stdout=handle, stderr=subprocess.STDOUT)
        processes.append((process, handle))
        return process

    echo = socket.socket()
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo.bind(('0.0.0.0', ECHO_PORT))
    echo.listen(16)

    def echo_serve():
        while True:
            conn, _ = echo.accept()
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)

    threading.Thread(target=echo_serve, daemon=True).start()

    results = {}
    try:
        start([gateway, '--bind', '127.0.0.1', '--apibind', '127.0.0.1'], 'gateway')
        wait(lambda: 'ready' in log_text(logs / 'gateway.log'), 25, what='gateway ready')

        def node(binary, name, apps, nat_type):
            config = {'product': 'fastp2p',
                      'network': {'ServerHost': '127.0.0.1', 'ServerPort': 27183,
                                  'Token': str(TOKEN), 'Node': name},
                      'CACertFile': str(certs / 'ca.crt'), 'apps': apps}
            if args.transport == 'quic':
                reserved = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                reserved.bind(('0.0.0.0', 0))
                reserved_udp.append(reserved)
                config['network']['PublicIPPort'] = reserved.getsockname()[1]
            path = runtime / (name + '.json')
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            return start([binary, '--config', str(path)], name, ['env', 'FASTP2P_NAT_TYPE=' + nat_type])

        node(client, 'natwindow-target', [], args.nat_type)
        node(source_client, 'natwindow-source',
             [{'AppName': 'fetch', 'Protocol': 'tcp', 'SrcPort': SOURCE_PORT,
               'PeerNode': 'natwindow-target', 'DstHost': '127.0.0.1',
               'DstPort': ECHO_PORT, 'UnderlayProtocol': args.transport, 'Enabled': 1}], args.source_nat_type)

        wait(lambda: 'forward attached to tunnel' in log_text(logs / 'natwindow-source.log'),
             60, what='session attached while the peer advertises a window')
        payload = b'window-' + os.urandom(6)
        assert roundtrip(SOURCE_PORT, payload, payload), 'echo mismatch over the windowed punch'
        if args.transport == 'quic':
            source = log_text(logs / 'natwindow-source.log')
            target = log_text(logs / 'natwindow-target.log')
            both_symmetric = '1' not in (args.source_nat_type, args.nat_type)
            ordered = both_symmetric and (args.source_nat_type, args.nat_type) != ('2', '2') and not args.legacy_source
            if ordered:
                receiver, sender = (source, target) if args.source_nat_type == '2' else (target, source)
                assert 'UDP punch receiver prepared' in receiver
                assert 'UDP punch sender started' in sender
            else:
                assert 'UDP punch receiver prepared' not in source + target
                assert 'UDP punch sender started' not in source + target
            results['ordered_udp_punch'] = bool(ordered)
        results['session_with_peer_advertising_a_window'] = args.nat_type != '1'
        results['traffic_over_windowed_punch'] = True
        results['transport'] = args.transport
        results['no_authentication_failures'] = 'authentication failed' not in log_text(
            logs / 'natwindow-source.log')
        results['success'] = True
    finally:
        for process, handle in processes:
            process.terminate()
        for process, handle in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
            handle.close()
        echo.close()
        for reserved in reserved_udp:
            reserved.close()

    print(json.dumps(results, indent=2))
    return 0 if results.get('success') else 1


if __name__ == '__main__':
    sys.exit(main())
