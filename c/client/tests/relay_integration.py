#!/usr/bin/env python3
"""Relay fallback integration check for the C client and C gateway.

Three real clients share one gateway.  The source is started with the
FASTP2P_FORCE_RELAY diagnostic switch, so it never attempts a direct punch: it
must ask the gateway for a relay, punch the third node, join the session there,
and carry traffic over the spliced tunnels.  The test asserts the relay itself
reports the pairing, which only happens when the frames really traverse it.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

TOKEN = 1234567890123456
PASSWORD = 'relaypassword1'
USER = 'relay-admin'


def wait(check, timeout=60, interval=0.2, what='condition'):
    deadline = time.monotonic() + timeout
    error = None
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except Exception as exc:  # noqa: BLE001 - reported on timeout
            error = exc
        time.sleep(interval)
    raise TimeoutError('timed out waiting for %s: %s' % (what, error))


def roundtrip(port, payload, timeout=8):
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as sock:
        sock.sendall(payload)
        return sock.recv(len(payload))


def log_text(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return ''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True)
    parser.add_argument('--gateway', required=True)
    parser.add_argument('--cert-dir', required=True)
    parser.add_argument('--logs', required=True)
    args = parser.parse_args()

    client = str(Path(args.client).resolve())
    gateway = str(Path(args.gateway).resolve())
    certs = Path(args.cert_dir).resolve()
    logs = Path(args.logs).resolve()
    logs.mkdir(parents=True, exist_ok=True)
    runtime = logs.parent

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

    def start(command, name, extra_env=None):
        handle = (logs / (name + '.log')).open('w')
        child_env = dict(env)
        if extra_env:
            child_env.update(extra_env)
        process = subprocess.Popen(command, cwd=runtime, env=child_env, stdout=handle,
                                   stderr=subprocess.STDOUT)
        processes.append((process, handle))
        return process

    echo = socket.socket()
    echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    echo.bind(('127.0.0.1', 0))
    echo.listen(16)
    echo_port = echo.getsockname()[1]

    def echo_serve():
        while True:
            conn, _ = echo.accept()
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)

    import threading
    threading.Thread(target=echo_serve, daemon=True).start()

    results = {}
    try:
        start([gateway, '--bind', '127.0.0.1', '--apibind', '127.0.0.1'], 'gateway')
        wait(lambda: (logs / 'gateway.log').exists() and 'ready' in log_text(logs / 'gateway.log'),
             20, what='gateway ready')

        def node(name, apps, extra_env=None):
            config = {
                'product': 'fastp2p',
                'network': {'ServerHost': '127.0.0.1', 'ServerPort': 27183,
                            'Token': str(TOKEN), 'Node': name},
                'CACertFile': str(certs / 'ca.crt'),
                'apps': apps,
            }
            path = runtime / (name + '.json')
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            return start([client, '--config', str(path)], name, extra_env)

        node('relay-target', [])
        direct = [{'AppName':'own-'+transport,'Protocol':'tcp','SrcPort':port,
                   'PeerNode':'relay-target','DstHost':'127.0.0.1','DstPort':echo_port,
                   'UnderlayProtocol':transport,'Enabled':1}
                  for port,transport in [(26002,'tcp'),(26003,'quic')]]
        node('relay-third', direct)
        wait(lambda: log_text(logs/'relay-third.log').count('forward attached to tunnel')>=2,
             60, what='relay node owns direct TCP and QUIC sessions before relaying')
        rules = []
        for port, transport in ((26000, 'tcp'), (26001, 'quic')):
            rules.append({'AppName': 'relay-' + transport, 'Protocol': 'tcp', 'SrcPort': port,
                          'PeerNode': 'relay-target', 'DstHost': '127.0.0.1',
                          'DstPort': echo_port, 'UnderlayProtocol': transport, 'Enabled': 1})
        node('relay-source', rules, {'FASTP2P_FORCE_RELAY': '1'})

        def attached():
            return log_text(logs / 'relay-source.log').count('forward attached to relay') >= 2

        wait(attached, 70, what='both rules attached to a relay')
        results['source_attached_through_relay'] = True

        payload = b'relay-payload-' + os.urandom(8)
        assert roundtrip(26000, payload) == payload
        results['tcp_over_relay'] = True
        assert roundtrip(26001, payload) == payload
        results['quic_over_relay'] = True
        for port in (26002,26003):
            assert roundtrip(port,payload)==payload
        results['relay_node_own_direct_sessions_survive_same_peer_relay_hops'] = True

        third = log_text(logs / 'relay-third.log')
        assert third.count('relay session paired') >= 2, third
        results['third_node_paired_both_sessions'] = True

        source = log_text(logs / 'relay-source.log')
        target = log_text(logs / 'relay-target.log')
        assert 'TCP tunnel connected' in source and 'QUIC tunnel connected' in source
        assert 'relay' in source
        assert 'authentication failed' not in source + target + third
        results['no_authentication_failures'] = True
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

    print(json.dumps(results, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
