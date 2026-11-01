#!/usr/bin/env python3
"""Deterministic relay-escalation check.

Two endpoints live in separate network namespaces with host forwarding off, so
their punched paths can never carry a packet, while both can still reach the
gateway and a third client running on the host.  The rule is *not* forced onto a
relay: the client has to notice that the direct link never becomes ready, give
up after its attempts, and ask the gateway for a relay on its own.

This is the path the lab and the loopback integration cannot reach, because
there a punch always succeeds.
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
PASSWORD = 'escalationpassword1'
USER = 'escalation-admin'
HOST_ADDR = '10.90.0.1'
A_ADDR = '10.90.1.2'
B_ADDR = '10.90.2.2'
ECHO_PORT = 9997


def run(command, check=True, capture=False):
    return subprocess.run(command, check=check, capture_output=capture, text=True)


def wait(check, timeout=60, interval=0.5, what='condition'):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except Exception as exc:  # noqa: BLE001 - surfaced on timeout
            error = exc
        time.sleep(interval)
    raise TimeoutError('timed out waiting for %s: %s' % (what, error))


def log_text(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return ''


def roundtrip(host, port, payload, timeout=10):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        return sock.recv(len(payload))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--cert-dir', required=True)
    parser.add_argument('--logs', required=True)
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()

    client = str(Path(args.client).resolve())
    gateway = str(Path(args.gateway).resolve())
    certs = Path(args.cert_dir).resolve()
    logs = Path(args.logs).resolve()
    logs.mkdir(parents=True, exist_ok=True)
    runtime = logs.parent

    created = []

    def netns(name):
        run(['ip', 'netns', 'add', name])
        created.append(name)
        run(['ip', '-n', name, 'link', 'set', 'lo', 'up'])

    def veth(host_if, ns_if, ns, host_cidr, ns_cidr, gateway_addr):
        run(['ip', 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', ns_if])
        run(['ip', 'link', 'set', ns_if, 'netns', ns])
        run(['ip', 'addr', 'add', host_cidr, 'dev', host_if])
        run(['ip', 'link', 'set', host_if, 'up'])
        run(['ip', '-n', ns, 'addr', 'add', ns_cidr, 'dev', ns_if])
        run(['ip', '-n', ns, 'link', 'set', ns_if, 'up'])
        run(['ip', '-n', ns, 'route', 'add', 'default', 'via', gateway_addr])

    env = os.environ.copy()
    env.update(
        FASTP2P_USER=USER,
        FASTP2P_PASSWORD=PASSWORD,
        FASTP2P_TOKEN=str(TOKEN),
        FASTP2P_TLS_CERT=str(certs / 'server.crt'),
        FASTP2P_TLS_KEY=str(certs / 'server.key'),
        FASTP2P_CA_FILE=str(certs / 'ca.crt'),
        FASTP2P_DATABASE=str(runtime / 'nodes.sqlite3'),
        FASTP2P_PUBLIC_HOST='127.0.0.1',
    )
    processes = []

    def start(command, name, prefix=None):
        handle = (logs / (name + '.log')).open('w')
        full = (prefix or []) + command
        process = subprocess.Popen(full, cwd=runtime, env=env, stdout=handle,
                                   stderr=subprocess.STDOUT)
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
        # Forwarding stays off, so the two namespaces cannot reach each other.
        run(['sysctl', '-qw', 'net.ipv4.ip_forward=0'], check=False)
        run(['ip', 'link', 'add', 'esc0', 'type', 'dummy'])
        run(['ip', 'addr', 'add', HOST_ADDR + '/24', 'dev', 'esc0'])
        run(['ip', 'link', 'set', 'esc0', 'up'])
        netns('esca')
        netns('escb')
        veth('va', 'va0', 'esca', '10.90.1.1/30', A_ADDR + '/30', '10.90.1.1')
        veth('vb', 'vb0', 'escb', '10.90.2.1/30', B_ADDR + '/30', '10.90.2.1')

        start([gateway, '--bind', '0.0.0.0', '--apibind', '127.0.0.1'], 'gateway')
        wait(lambda: 'ready' in log_text(logs / 'gateway.log'), 25, what='gateway ready')

        def node(name, apps, prefix=None, server=HOST_ADDR):
            config = {
                'product': 'fastp2p',
                'network': {'ServerHost': server, 'ServerPort': 27183,
                            'Token': str(TOKEN), 'Node': name},
                'CACertFile': str(certs / 'ca.crt'),
                'apps': apps,
            }
            path = runtime / (name + '.json')
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            return start([client, '--config', str(path)], name, prefix)

        # Relay candidate sits on the host and is reachable from both namespaces.
        node('esc-relay', [])
        node('esc-target', [], ['ip', 'netns', 'exec', 'escb'])
        node('esc-source',
             [{'AppName': 'to-target', 'Protocol': 'tcp', 'SrcPort': 28100,
               'PeerNode': 'esc-target', 'DstHost': HOST_ADDR, 'DstPort': ECHO_PORT, 'BindIP': '0.0.0.0',
               'UnderlayProtocol': 'tcp', 'Enabled': 1}],
             ['ip', 'netns', 'exec', 'esca'])

        wait(lambda: 'forward attached to relay' in log_text(logs / 'esc-source.log'),
             args.timeout, what='source escalated to a relay')
        results['source_escalated_without_force_relay'] = True

        payload = b'escalation-' + os.urandom(6)
        assert roundtrip(A_ADDR, 28100, payload) == payload
        results['traffic_through_escalated_relay'] = True

        assert 'relay session paired' in log_text(logs / 'esc-relay.log')
        results['third_node_paired'] = True
        results['success'] = True
    finally:
        for process, handle in processes:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            handle.close()
        echo.close()
        for name in created:
            run(['ip', 'netns', 'del', name], check=False)
        run(['ip', 'link', 'del', 'esc0'], check=False)

    print(json.dumps(results, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
