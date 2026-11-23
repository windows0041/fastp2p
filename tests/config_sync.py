#!/usr/bin/env python3
"""Rule-managed configuration: persistence and transactional live updates.

Drive the real gateway's /app endpoint and check the acknowledged revision,
local profile, and existing TCP streams. The portable fixture cannot render
managed rules, so it only checks the shared profile guarantees.
"""
import argparse, json, os, secrets, socket, ssl, subprocess, sys, tempfile, time
from contextlib import ExitStack, closing
from pathlib import Path
import http.client
import socketserver
import sqlite3
import struct
import threading
from certificates import create_certificates

p = argparse.ArgumentParser()
p.add_argument('--client', required=True)
p.add_argument('--gateway', required=True)
p.add_argument('--profile-probe', help='Test-only native DPAPI reader on Windows')
p.add_argument('--fixture', action='store_true',
               help='The gateway is the reduced Python double, which cannot render rules')
args = p.parse_args()
client = Path(args.client).resolve()
gateway = Path(args.gateway).resolve()

with tempfile.TemporaryDirectory(prefix='fastp2p-config-sync-') as temporary:
    root = Path(temporary)
    database = root / 'nodes.sqlite3'
    create_certificates(root / 'tls', '127.0.0.1')
    env = dict(os.environ, FASTP2P_USER='config-admin',
               FASTP2P_PASSWORD=secrets.token_urlsafe(24), FASTP2P_TOKEN='9999999999999999')
    ctx = ssl.create_default_context(cafile=str(root / 'tls/ca.crt'))
    logs = {name: (root / (name + '.log')).open('w') for name in ('gateway', 'client')}
    children = []
    jwt = None

    def wait(action, timeout=45, what='condition'):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                if action():
                    return
            except (OSError, ValueError, AssertionError, KeyError, sqlite3.OperationalError):
                pass
            time.sleep(.05)
        raise TimeoutError('timed out waiting for ' + what)

    def api(path, body=None, auth=True):
        c = http.client.HTTPSConnection('127.0.0.1', 31008, context=ctx, timeout=5)
        headers = {'Content-Type': 'application/json'}
        if auth and jwt:
            headers['Authorization'] = 'Bearer ' + jwt
        c.request('POST' if body is not None else 'GET', path,
                  json.dumps(body) if body is not None else None, headers)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, (json.loads(data) if data else None)

    def port():
        with socket.socket() as s:
            # Exclude ports already in use even on the 127.0.0.2 listener.
            s.bind(('0.0.0.0', 0))
            return s.getsockname()[1]

    def listening(number, address='127.0.0.1'):
        try:
            with socket.create_connection((address, number), timeout=.2):
                return True
        except OSError:
            return False

    config = root / 'config/fastp2p.conf'
    config.parent.mkdir()
    portable = gateway.suffix == '.py'

    def read_config():
        if args.profile_probe:
            result = subprocess.run([str(Path(args.profile_probe).resolve()), str(config)],
                                    capture_output=True, check=True)
            return json.loads(result.stdout)
        return json.loads(config.read_text())

    # A local key the gateway never manages must survive every reload: the merge
    # is per-key, so whatever the operator wrote by hand stays put.
    local = {'product': 'fastp2p',
             'network': {'Node': 'config-test-node', 'ServerHost': '127.0.0.1',
                         'ServerPort': 37183, 'Token': env['FASTP2P_TOKEN']},
             'CACertFile': str(root / 'tls/ca.crt'),
             'custom': {'nested': {'keep': 17, 'update': 1}, 'onlyLocal': 'untouched'},
             'apps': [], 'socks5': []}
    config.write_text(json.dumps(local))
    results = {}

    entry_node = 'config-test-node'
    exit_node = 'config-exit-node'
    rule_endpoint = '/api/v1/device/' + entry_node + '/app'

    def start_client(profile=config, log='client'):
        client_env = env.copy()
        client_env.pop('FASTP2P_TOKEN', None)
        process = subprocess.Popen([str(client), 'run', '--config', str(profile)],
                                   cwd=root, env=client_env, stdout=logs[log],
                                   stderr=subprocess.STDOUT)
        children.append(process)
        return process

    def online(*names):
        status, reply = api('/api/v1/nodes')
        return status == 200 and set(names) <= {
            node['name'] for node in reply['nodes'] if node['isActive']}

    def rule_forwards(source, name, target, extra=None):
        rule = {'appName': name, 'protocol': 'tcp', 'srcPort': source,
                'peerNode': exit_node, 'dstHost': '127.0.0.1', 'dstPort': target,
                'punchPriority': 2}
        if extra:
            rule.update(extra)
        return rule

    def profile_rule(source, group='apps'):
        return next((row for row in read_config().get(group, [])
                     if int(row.get('SrcPort', 0)) == source), None)

    def gateway_config_state():
        # /config intentionally returns 410. The private real gateway records
        # actual 6/8 ACKs in its database; queued submissions are not ACKs.
        with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=.2)) as db:
            return db.execute('SELECT revision, ack_revision, state FROM node_configs WHERE node=?',
                              (entry_node,)).fetchone()

    def change_rule(rule, state='applied'):
        previous = gateway_config_state()
        previous_revision = previous[0] if previous else 0
        assert api(rule_endpoint, rule)[0] == 200
        queued = gateway_config_state()
        assert queued and queued[0] > previous_revision, (rule['srcPort'], previous, queued)
        revision = queued[0]
        wait(lambda: gateway_config_state() == (revision, revision, state),
             what=f'revision {revision} to acknowledge {state}')
        return revision

    def remove_rule(source, protocol='tcp'):
        change_rule({'protocol': protocol, 'srcPort': 0,
                     'protocol0': protocol, 'srcPort0': source})

    def exact(sock, size):
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError('existing TCP stream closed early')
            data.extend(chunk)
        return bytes(data)

    class Echo(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                while line := self.rfile.readline(4096):
                    self.wfile.write(self.server.tag + b':' + line)
            except OSError:
                pass

    def echo_server(stack, tag):
        server = stack.enter_context(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo))
        server.daemon_threads = True
        server.tag = tag
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        stack.callback(thread.join)
        stack.callback(server.shutdown)
        return server.server_address[1]

    def assert_echo(sock, tag):
        payload = secrets.token_hex(12).encode() + b'\n'
        sock.sendall(payload)
        assert exact(sock, len(tag) + 1 + len(payload)) == tag + b':' + payload

    def connect_forward(source, address='127.0.0.1', timeout=3):
        return socket.create_connection((address, source), timeout=timeout)

    def finish_stream(sock):
        # Let the test peer initiate FIN so the FastP2P listener's address is
        # not held in TIME_WAIT when the persistence test restarts the client.
        sock.shutdown(socket.SHUT_WR)
        assert sock.recv(1) == b''

    def forwards_echo(source, tag, address='127.0.0.1'):
        with connect_forward(source, address, timeout=1) as sock:
            assert_echo(sock, tag)
            finish_stream(sock)
        return True

    def connect_proxy(source, target, credentials=None):
        sock = connect_forward(source)
        try:
            method = b'\x02' if credentials else b'\x00'
            sock.sendall(b'\x05\x01' + method)
            assert exact(sock, 2) == b'\x05' + method
            if credentials:
                username, password = credentials
                sock.sendall(b'\x01' + bytes([len(username)]) + username + bytes([len(password)]) + password)
                assert exact(sock, 2) == b'\x01\x00'
            sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') +
                         struct.pack('!H', target))
            reply = exact(sock, 10)
            assert reply[:4] == b'\x05\x00\x00\x01', reply
        except BaseException:
            sock.close()
            raise
        return sock

    try:
        process = subprocess.Popen(
            ([sys.executable, str(gateway)] if portable else [str(gateway)]) +
            ['--bind', '127.0.0.1', '--port', '37183', '--apiport', '31008',
             '--database', str(database), '--cert', str(root / 'tls/server.crt'),
             '--key', str(root / 'tls/server.key')],
            cwd=root, env=env, stdout=logs['gateway'], stderr=subprocess.STDOUT)
        children.append(process)
        wait(lambda: api('/healthz', auth=False)[0] == 200)
        status, value = api('/api/v1/user/login',
                            {'user': env['FASTP2P_USER'], 'password': env['FASTP2P_PASSWORD']},
                            False)
        assert status == 200
        jwt = value['token']
        current = start_client()
        wait(lambda: online(entry_node), what='the client to register')

        # Manual field configuration is gone: both methods answer 410 and the
        # console no longer offers it.
        assert api('/api/v1/device/config-test-node/config')[0] == 410
        assert api('/api/v1/device/config-test-node/config', {'fields': {}})[0] == 410
        assert api('/api/v1/device/config-test-node/config', {'fields': {}}, False)[0] != 200
        results['manual_configuration_endpoint_removed'] = True

        if args.fixture:
            # The reduced Python fixture cannot reproduce the gateway's rule
            # renderer, so the rule pipeline is exercised by the Linux job against
            # the real gateway binary. The profile guarantees still run here.
            results['fixture_gateway_skips_rule_pipeline'] = True
            saved = read_config()
            assert saved['custom'] == {'nested': {'keep': 17, 'update': 1},
                                       'onlyLocal': 'untouched'}
            assert saved['network']['Token'] == local['network']['Token']
            assert saved['CACertFile'] == local['CACertFile']
            results['unsent_keys_and_credentials_preserved_across_reload'] = True
        else:
            exit_profile = root / 'exit.json'
            exit_network = dict(local['network'], Node=exit_node)
            exit_profile.write_text(json.dumps({'network': exit_network,
                                                'CACertFile': local['CACertFile']}))
            logs['exit'] = (root / 'exit.log').open('w')
            exit_client = start_client(exit_profile, 'exit')
            wait(lambda: online(entry_node, exit_node), what='both peers to register')

            with ExitStack() as stack:
                first_target = echo_server(stack, b'first')
                second_target = echo_server(stack, b'second')
                forward = port()
                listen_address = '127.0.0.2'
                revision = change_rule(rule_forwards(forward, 'config-forward', first_target,
                                                     {'customRuleKey': 42, 'whitelist': listen_address}))
                wait(lambda: forwards_echo(forward, b'first', listen_address),
                     what='the first end-to-end TCP forward')
                assert not listening(forward)
                stored = profile_rule(forward)
                assert stored and stored['customRuleKey'] == 42, stored
                assert stored['BindIP'] == listen_address, stored
                results['rule_reaches_config_file_and_unknown_keys_survive'] = True

                saved = read_config()
                assert saved['custom'] == {'nested': {'keep': 17, 'update': 1},
                                           'onlyLocal': 'untouched'}
                assert saved['network']['Token'] == local['network']['Token']
                assert saved['CACertFile'] == local['CACertFile']
                assert saved['_fastp2pManaged']['revision'] == revision
                assert not saved['_fastp2pManaged']['pending']
                results['unsent_keys_and_credentials_preserved_across_reload'] = True

                # Keep the same stream open across all the rule changes. Polling
                # for a fresh connection could miss a full teardown and reconnect.
                stable = stack.enter_context(connect_forward(forward, listen_address))
                assert_echo(stable, b'first')
                changed = port()
                change_rule(rule_forwards(changed, 'web-rule', first_target))
                assert_echo(stable, b'first')
                wait(lambda: forwards_echo(changed, b'first'), what='the second TCP forward')

                # Edit the destination but retain the existing listening tuple.
                change_rule(rule_forwards(changed, 'web-rule', second_target,
                                          {'protocol0': 'tcp', 'srcPort0': changed}))
                assert_echo(stable, b'first')
                assert profile_rule(changed)['DstPort'] == second_target
                wait(lambda: forwards_echo(changed, b'second'), what='the edited TCP destination')
                results['adding_and_editing_tcp_rules_preserves_existing_stream'] = True

                proxy_port = port()
                proxy_rule = {'appName': 'live-proxy', 'protocol': 'socks5', 'srcPort': proxy_port,
                              'peerNode': exit_node, 'punchPriority': 2}
                change_rule(proxy_rule)
                assert profile_rule(proxy_port, 'socks5')['Name'] == 'live-proxy'
                with connect_proxy(proxy_port, second_target) as unprotected_proxy:
                    assert_echo(unprotected_proxy, b'second')
                    finish_stream(unprotected_proxy)
                assert_echo(stable, b'first')
                results['adding_socks5_preserves_existing_tcp_stream'] = True

                credentials = (b'config-user', secrets.token_hex(12).encode())
                change_rule(dict(proxy_rule, protocol0='socks5', srcPort0=proxy_port,
                                 Username=credentials[0].decode(), Password=credentials[1].decode()))
                with connect_forward(proxy_port) as unauthenticated:
                    # Use the authenticated listener without opening a stream;
                    # a SOCKS rejection is server-initiated and would put this
                    # listener in TIME_WAIT before the persistence check.
                    unauthenticated.sendall(b'\x05\x02\x00\x02')
                    assert exact(unauthenticated, 2) == b'\x05\x02'
                proxy = stack.enter_context(connect_proxy(proxy_port, second_target, credentials))
                assert_echo(proxy, b'second')
                assert_echo(stable, b'first')
                results['editing_socks5_credentials_preserves_existing_tcp_stream'] = True

                # All rules use the same peer and TCP underlay. Removing one of
                # them must not close the tunnel held by the two active streams.
                remove_rule(changed)
                assert not profile_rule(changed) and not listening(changed)
                assert_echo(stable, b'first')
                assert_echo(proxy, b'second')
                results['deleting_shared_tunnel_rule_preserves_other_streams'] = True
                results['rules_replace_as_a_set_and_disappear_when_deleted'] = True

                before = config.read_bytes()
                with socket.socket() as occupied:
                    occupied.bind(('0.0.0.0', 0))
                    occupied.listen()
                    taken = occupied.getsockname()[1]
                    change_rule(rule_forwards(taken, 'conflicting-rule', second_target), 'failed')
                    assert config.read_bytes() == before and not profile_rule(taken)
                    assert listening(forward, listen_address) and listening(proxy_port)
                    assert current.poll() is None and exit_client.poll() is None
                    assert online(entry_node, exit_node)
                    assert_echo(stable, b'first')
                    assert_echo(proxy, b'second')
                    remove_rule(taken)
                results['bind_failure_rolls_back_without_losing_working_rules'] = True

                # Force the atomic writer to fail after the candidate listener was
                # prepared, without changing permissions or the live profile.
                not_saved = port()
                temporary_profile = config.with_name(config.name + f'.tmp.{current.pid}')
                before = config.read_bytes()
                with temporary_profile.open('xb'):
                    pass
                try:
                    change_rule(rule_forwards(not_saved, 'write-failure-rule', second_target), 'failed')
                    assert config.read_bytes() == before and not profile_rule(not_saved)
                    assert not listening(not_saved), 'failed save leaked a staged listener'
                    assert_echo(stable, b'first')
                    assert_echo(proxy, b'second')
                finally:
                    temporary_profile.unlink(missing_ok=True)
                # The same gateway rule can be retried after the failure. A
                # changed payload creates another revision on the same listener.
                change_rule(rule_forwards(not_saved, 'retried-after-write-failure', second_target,
                                          {'protocol0': 'tcp', 'srcPort0': not_saved}))
                wait(lambda: forwards_echo(not_saved, b'second'), what='the retried rule to bind')
                assert_echo(stable, b'first')
                assert_echo(proxy, b'second')
                remove_rule(not_saved)
                results['save_failure_closes_staged_listener_and_preserves_existing_streams'] = True

                # A deliberate restart is a profile persistence check. Drain
                # the application streams before asking FastP2P to stop.
                finish_stream(stable)
                finish_stream(proxy)
                stable.close()
                proxy.close()
                current.terminate()
                current.wait(timeout=8)
                current = start_client()
                wait(lambda: listening(forward, listen_address) and listening(proxy_port),
                     what='restart to bind both rules from the saved profile')
                wait(lambda: online(entry_node, exit_node), what='the restarted client to register')
                assert current.poll() is None
                assert profile_rule(forward)['DstPort'] == first_target
                assert profile_rule(proxy_port, 'socks5')['Username'] == credentials[0].decode()
                assert read_config()['custom']['nested']['keep'] == 17
                results['restart_reads_the_same_config_file'] = True

        if args.fixture:
            # The fixture never triggers a managed rewrite, so the profile is still
            # the JSON this test wrote. DPAPI migration is asserted by identity_cli.py.
            results['fixture_gateway_skips_dpapi_rewrite_check'] = True
        elif os.name == 'nt':
            assert config.read_bytes().startswith(b'FPD1')
            assert env['FASTP2P_TOKEN'].encode() not in config.read_bytes()
            results['windows_DPAPI_retained_after_merge_reload_and_rollback'] = True
        else:
            assert config.stat().st_mode & 0o077 == 0
        results['success'] = True
        print(json.dumps(results, indent=2))
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=8)
        for file in logs.values():
            file.close()
        for name in logs:
            data = (root / (name + '.log')).read_text(errors='replace')
            assert 'Sanitizer' not in data and 'runtime error:' not in data
            assert env['FASTP2P_TOKEN'] not in data and env['FASTP2P_PASSWORD'] not in data
