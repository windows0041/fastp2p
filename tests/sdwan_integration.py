#!/usr/bin/env python3
"""Linux clients exchange IPv4 over IPv6-only links in isolated namespaces."""

import argparse
from contextlib import ExitStack
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import time

from certificates import create_certificates


def command(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def ns(name, *arguments):
    return ('ip', 'netns', 'exec', name, *arguments)


def wait_for(test, explanation, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if test():
            return
        time.sleep(.3)
    raise AssertionError(explanation)


def ping(namespace, address, source=None):
    command_line = ['ping', '-4', '-c', '1', '-W', '1']
    if source is not None:
        command_line += ['-I', source]
    return subprocess.run(ns(namespace, *command_line, address),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def output(*arguments):
    return command(*arguments, capture_output=True, text=True).stdout


def ingress_packets(namespace):
    data = output(*ns(namespace, 'ip', '-s', '-j', 'link', 'show', 'dev', 'fastp2p0'))
    return json.loads(data)[0]['stats64']['rx']['packets']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True, type=lambda p: Path(p).resolve())
    parser.add_argument('--gateway', required=True, type=lambda p: Path(p).resolve())
    parser.add_argument('--managed', action='store_true', help='Apply and revoke topology through the gateway')
    parser.add_argument('--topology', action='store_true', help='Test a three-member Mesh and center failover')
    args = parser.parse_args()
    if args.topology:
        args.managed = True
    for namespace in ('mnt', 'net'):
        if Path('/proc/self/ns/' + namespace).readlink() == Path('/proc/1/ns/' + namespace).readlink():
            parser.error('Run as root via unshare --mount --net --propagation private')

    names = ('vps-a', 'vps-b')
    lan_names = ('lan-a', 'lan-b')
    lans = ('192.168.50', '192.168.15')
    nodes = ('sdwan-vps-a', 'sdwan-vps-b')
    if args.topology:
        names += ('vps-c',)
        lan_names += ('lan-c',)
        lans += ('192.168.60',)
        nodes += ('sdwan-vps-c',)
    gateway_ip = '2001:db8:3:2::1'
    unprivileged = ('setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', '--no-new-privs')
    net_admin = ('--bounding-set=-all,+net_admin', '--inh-caps=+net_admin', '--ambient-caps=+net_admin')
    command('mount', '--make-rprivate', '/')
    Path('/run/netns').mkdir(exist_ok=True)
    command('mount', '-t', 'tmpfs', 'tmpfs', '/run/netns')
    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'link', 'add', 'wan6', 'type', 'bridge')
    command('ip', 'link', 'set', 'wan6', 'up')
    command('ip', '-6', 'addr', 'add', gateway_ip + '/64', 'dev', 'wan6', 'nodad')
    with tempfile.TemporaryDirectory(prefix='fastp2p-sdwan-') as directory, ExitStack() as cleanup:
        root = Path(directory)
        root.chmod(0o711)
        for name in (*names, *lan_names):
            command('ip', 'netns', 'add', name)
            cleanup.callback(command, 'ip', 'netns', 'delete', name)
            command(*ns(name, 'ip', 'link', 'set', 'lo', 'up'))
        for index, name in enumerate(names):
            port = 'uplink' + str(index)
            command('ip', 'link', 'add', port, 'type', 'veth', 'peer', 'name', 'wan', 'netns', name)
            command('ip', 'link', 'set', port, 'master', 'wan6')
            command('ip', 'link', 'set', port, 'up')
            command(*ns(name, 'ip', 'link', 'set', 'wan', 'up'))
            command(*ns(name, 'ip', '-6', 'addr', 'add', f'2001:db8:3:2::{index + 2}/64',
                        'dev', 'wan', 'nodad'))
            assert not output(*ns(name, 'ip', '-4', 'addr', 'show', 'dev', 'wan')).strip()
            assert not output(*ns(name, 'ip', '-4', 'route', 'show')).strip()
            refused = subprocess.run(ns(name, *unprivileged, str(args.client), '--check-sdwan'),
                                     capture_output=True, text=True)
            assert refused.returncode and 'CAP_NET_ADMIN' in refused.stderr
            command(*ns(name, *unprivileged, *net_admin, str(args.client), '--check-sdwan'))

        certs = root / 'tls'
        create_certificates(certs, gateway_ip)
        environment = dict(os.environ, FASTP2P_USER='sdwan-fixture',
                           FASTP2P_PASSWORD=secrets.token_urlsafe(24), FASTP2P_TOKEN='9999999999999999')
        processes = []

        def stop(process):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        def start(arguments, name, env):
            log_path = root / (name + '.log')
            log = cleanup.enter_context(log_path.open('w'))
            process = subprocess.Popen(arguments, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            cleanup.callback(stop, process)
            processes.append(process)
            return process

        start([str(args.gateway), '--bind', '127.0.0.1', '--bind6', gateway_ip,
               '--apibind', '127.0.0.1', '--apibind6', gateway_ip, '--database', str(root / 'nodes.sqlite3'),
               '--cert', str(certs / 'server.crt'), '--key', str(certs / 'server.key')], 'gateway', environment)
        client_env = {key: value for key, value in environment.items()
                      if key not in ('FASTP2P_USER', 'FASTP2P_PASSWORD', 'FASTP2P_TOKEN')}
        clients = []
        profiles = []
        jwt = None
        tls = ssl.create_default_context(cafile=str(certs / 'ca.crt'))

        def api(path, body=None):
            headers = {'Content-Type': 'application/json'}
            if jwt:
                headers['Authorization'] = 'Bearer ' + jwt
            connection = http.client.HTTPSConnection(gateway_ip, 10008, context=tls, timeout=3)
            try:
                connection.request('POST' if body is not None else 'GET', path,
                                   json.dumps(body) if body is not None else None, headers)
                reply = connection.getresponse()
                return reply.status, json.loads(reply.read())
            finally:
                connection.close()

        def login():
            nonlocal jwt
            try:
                status, result = api('/api/v1/user/login', {'user': environment['FASTP2P_USER'],
                                     'password': environment['FASTP2P_PASSWORD']})
            except OSError:
                return False
            if status == 200:
                jwt = result['token']
            return bool(jwt)

        try:
            for i, name in enumerate(names):
                other = 1 - i
                config_dir = root / ('config-' + name)
                config_dir.mkdir(mode=0o700)
                os.chown(config_dir, 65534, 65534)
                profile = config_dir / 'fastp2p.conf'
                settings = {
                    'network': {'Node': nodes[i], 'ServerHost': gateway_ip, 'ServerPort': 27183,
                                'PublicIPPort': 6221, 'Token': environment['FASTP2P_TOKEN']},
                    'CACertFile': str(certs / 'ca.crt')
                }
                if not args.managed:
                    settings['sdwan'] = {'Address': f'10.3.2.{i + 1}', 'LocalRoutes': [lans[i] + '.0/24'],
                                         'Peers': [{'Node': nodes[other], 'Address': f'10.3.2.{other + 1}',
                                                    'Routes': [lans[other] + '.0/24']}]}
                profile.write_text(json.dumps(settings))
                os.chown(profile, 65534, 65534)
                profile.chmod(0o600)
                profiles.append(ns(name, *unprivileged, *net_admin, str(args.client), 'run',
                                   '--config', str(profile)))
                clients.append(start(profiles[-1], name, client_env))

            if args.managed:
                wait_for(login, 'Could not sign in to the isolated SD-WAN gateway')
                wait_for(lambda: {n['name'] for n in api('/api/v1/nodes')[1]['nodes']} == set(nodes),
                         'The SD-WAN members did not register')
                members = [{'node': node, 'address': f'10.3.2.{i + 1}', 'routes': [lans[i] + '.0/24']}
                           for i, node in enumerate(nodes)]
                subnet = '10.3.2.0/24'
                duplicate = [members[0], {**members[1], 'address': members[0]['address']}]
                assert api('/api/v1/sdwan', {'subnet': subnet, 'members': duplicate})[0] == 400
                assert api('/api/v1/sdwan')[1]['members'] == []
                assert api('/api/v1/sdwan', {'subnet': subnet, 'members': members})[0] == 200

            def virtual_ping():
                assert all(p.poll() is None for p in processes), 'A test daemon exited'
                return ping(names[0], '10.3.2.2') and ping(names[1], '10.3.2.1')

            wait_for(virtual_ping, 'The IPv4 TUN peers could not reach each other over IPv6')
            if args.managed:
                wait_for(lambda: all(n['state'] == 'applied' for n in api('/api/v1/sdwan')[1]['members']),
                         'The gateway did not receive SD-WAN application acknowledgements')
            for name in names:
                log = (root / (name + '.log')).read_text()
                assert 'resolved=+IPv6 wanted=+IPv6' in log
                assert 'SD-WAN peer attached to direct tunnel' in log
                assert not output(*ns(name, 'ip', '-4', 'route', 'show', 'default')).strip()
            print('IPv4 peer ping through a direct QUIC tunnel on IPv6-only uplinks')

            # Add an IPv4 LAN behind each VPS. Only the LAN hosts have IPv4 default routes.
            for i, name in enumerate(names):
                lan = lan_names[i]
                command('ip', 'link', 'add', 'lan', 'netns', name, 'type', 'veth',
                        'peer', 'name', 'eth0', 'netns', lan)
                command(*ns(name, 'ip', 'link', 'set', 'lan', 'up'))
                command(*ns(name, 'ip', '-4', 'addr', 'add', lans[i] + '.1/24', 'dev', 'lan'))
                command(*ns(name, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1'))
                command(*ns(lan, 'ip', 'link', 'set', 'eth0', 'up'))
                command(*ns(lan, 'ip', '-4', 'addr', 'add', lans[i] + '.3/24', 'dev', 'eth0'))
                command(*ns(lan, 'ip', '-4', 'route', 'add', 'default', 'via', lans[i] + '.1'))
            assert ping(lan_names[0], lans[1] + '.3') and ping(lan_names[1], lans[0] + '.3')
            command(*ns(lan_names[0], 'ip', '-4', 'addr', 'add', '192.168.99.3/32', 'dev', 'eth0'))
            packets = ingress_packets(names[1])
            assert not ping(lan_names[0], lans[1] + '.3', source='192.168.99.3')
            assert ingress_packets(names[1]) == packets
            print('Bidirectional IPv4 LAN routes verified; unadvertised source dropped')

            echo = """import socket, sys
with socket.create_server((sys.argv[1], 23456)) as listener:
    stream, _ = listener.accept()
    with stream:
        while data := stream.recv(65536):
            stream.sendall(data)
"""
            request = """import socket, sys
payload = bytes(range(256)) * 256
with socket.create_connection((sys.argv[1], 23456), timeout=6) as stream:
    stream.sendall(payload)
    stream.shutdown(socket.SHUT_WR)
    with stream.makefile('rb') as reply:
        assert reply.read() == payload
"""
            target = lans[1] + '.3'
            start(ns(lan_names[1], sys.executable, '-c', echo, target), 'lan-echo', client_env)
            wait_for(lambda: ':23456' in output(*ns(lan_names[1], 'ss', '-lnt')),
                     'TCP fixture did not start', timeout=5)
            command(*ns(lan_names[0], sys.executable, '-c', request, target), timeout=10)
            print('64 KiB of TCP payload forwarded across the remote subnet')

            if args.topology:
                path = '/api/v1/sdwan'

                def links_ready(mode, center, count):
                    plan = api(path)[1]
                    return (plan['mode'] == mode and plan.get('activeCenter', '') == center and
                            len(plan['links']) == count and
                            all(link['state'] == 'direct' and link['family'] == 6 for link in plan['links']))

                wait_for(lambda: links_ready('mesh', '', 3), 'The three Mesh paths were not reported as direct')
                central = {'subnet': subnet, 'mode': 'central', 'center': nodes[2], 'members': members}
                assert api(path, {**central, 'center': 'outside-node'})[0] == 400
                assert api(path, central)[0] == 200
                wait_for(lambda: links_ready('central', nodes[2], 2), 'The two center links did not come online')
                assert all(nodes[2] in (link['a'], link['b']) for link in api(path)[1]['links'])
                reply = output(*ns(names[0], 'ping', '-4', '-c', '1', '-W', '2', '10.3.2.2'))
                assert 'ttl=63' in reply, reply
                assert ping(lan_names[0], lans[1] + '.3') and ping(lan_names[1], lans[0] + '.3')
                stop(clients[2])
                wait_for(lambda: any(m['node'] == nodes[2] and m['state'] == 'offline'
                                     for m in api(path)[1]['members']), 'The center did not go offline')
                assert not ping(names[0], '10.3.2.2'), 'Branches bypassed the offline center'
                wait_for(lambda: api(path)[1]['activeCenter'] == nodes[0] and ping(names[0], '10.3.2.2'),
                         'The new center did not restore IPv4 traffic')
                clients[2] = start(profiles[2], 'rejoined-center', client_env)
                wait_for(lambda: links_ready('central', nodes[0], 2), 'The returning member did not use the new center')
                assert api(path)[1]['center'] == nodes[2]
                assert api(path, {'subnet': subnet, 'mode': 'mesh', 'members': members})[0] == 200
                wait_for(lambda: links_ready('mesh', '', 3) and ping(names[0], '10.3.2.2'),
                         'The clients did not return to Mesh')
                print('Mesh and center link telemetry, transit IPv4, center failure and recovery verified')

            if args.managed:
                assert api('/api/v1/sdwan', {'subnet': subnet, 'members': []})[0] == 200
                wait_for(lambda: all('fastp2p0' not in output(*ns(n, 'ip', 'link', 'show')) for n in names),
                         'Revoking the network did not remove its TUN devices')
                assert all(p.poll() is None for p in clients)
                print('Gateway topology persisted, acknowledged, and removed while the clients stayed online')

            for name, process in zip(names, clients):
                stop(process)
                assert 'fastp2p0' not in output(*ns(name, 'ip', 'link', 'show'))
                assert 'fastp2p0' not in output(*ns(name, 'ip', '-4', 'route', 'show'))
            print('TUN and installed routes removed on stop')
        except BaseException:
            for log in root.glob('*.log'):
                print(log.name, *log.read_text(errors='replace').splitlines()[-35:], sep='\n', file=sys.stderr)
            raise


if __name__ == '__main__':
    main()
