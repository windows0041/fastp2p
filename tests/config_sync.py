#!/usr/bin/env python3
"""Rule-managed configuration: merge into fastp2p.conf, reload, persistence, rollback.

The gateway no longer accepts operator-supplied JSON fields (that endpoint now
answers 410), so the only thing that reaches the client is the desired state the
gateway renders from its forwarding rules. This test therefore drives /app and
asserts on the resulting conf file, which is what the client actually reads.
"""
import argparse, json, os, secrets, socket, ssl, subprocess, sys, tempfile, time
from pathlib import Path
import http.client
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
            except (OSError, ValueError, AssertionError, KeyError):
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
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def listening(number):
        try:
            with socket.create_connection(('127.0.0.1', number), timeout=.2):
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

    def start_client():
        client_env = env.copy()
        client_env.pop('FASTP2P_TOKEN', None)
        process = subprocess.Popen([str(client), 'run', '--config', str(config)],
                                   env=client_env, stdout=logs['client'],
                                   stderr=subprocess.STDOUT)
        children.append(process)
        return process

    def rule_forwards(source, name, extra=None):
        rule = {'appName': name, 'protocol': 'tcp', 'srcPort': source,
                'peerNode': 'offline-peer-node', 'dstHost': '127.0.0.1', 'dstPort': 22,
                'punchPriority': 2}
        if extra:
            rule.update(extra)
        return rule

    def forwards(source):
        return any(int(a.get('SrcPort', 0)) == source for a in read_config().get('apps', []))

    def rejected_rule(blocked, working):
        """The conflicting rule never lands in the file and the working rule stays up.

        The client remembers the rejected revision so a failed push is not
        replayed in a loop; what matters here is that the node keeps serving the
        rule it already had.
        """
        return not forwards(blocked) and listening(working)

    try:
        process = subprocess.Popen(
            ([sys.executable, str(gateway)] if portable else [str(gateway)]) +
            ['--bind', '127.0.0.1', '--port', '37183', '--apiport', '31008',
             '--cert', str(root / 'tls/server.crt'), '--key', str(root / 'tls/server.key')],
            cwd=root, env=env, stdout=logs['gateway'], stderr=subprocess.STDOUT)
        children.append(process)
        wait(lambda: api('/healthz', auth=False)[0] == 200)
        status, value = api('/api/v1/user/login',
                            {'user': env['FASTP2P_USER'], 'password': env['FASTP2P_PASSWORD']},
                            False)
        assert status == 200
        jwt = value['token']
        current = start_client()
        wait(lambda: any(n['isActive'] for n in api('/api/v1/nodes')[1]['nodes']),
             what='the client to register')

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
            # A forwarding rule stored by the gateway must reach the client's own
            # configuration file, and a key inside the rule that the renderer does
            # not know must survive the round trip.
            forward = port()
            assert api('/api/v1/device/config-test-node/app',
                       rule_forwards(forward, 'config-forward', {'customRuleKey': 42}))[0] == 200
            wait(lambda: listening(forward) and forwards(forward),
                 what='the rule to reach fastp2p.conf and bind')
            saved = read_config()
            stored = [a for a in saved['apps'] if int(a.get('SrcPort', 0)) == forward]
            assert stored, 'the rule never reached fastp2p.conf'
            # A key the gateway's renderer does not understand still has to survive:
            # it round-trips through the stored rule payload rather than being dropped.
            assert stored[0]['customRuleKey'] == 42, stored[0]
            results['rule_reaches_config_file_and_unknown_keys_survive'] = True

            # Unmanaged local keys and the credential material stay untouched.
            assert saved['custom'] == {'nested': {'keep': 17, 'update': 1},
                                       'onlyLocal': 'untouched'}
            assert saved['network']['Token'] == local['network']['Token']
            assert saved['CACertFile'] == local['CACertFile']
            assert current.poll() is None and not saved['_fastp2pManaged']['pending']
            results['unsent_keys_and_credentials_preserved_across_reload'] = True

            # Deleting the rule removes it again, and the listener goes with it.
            changed = port()
            assert api('/api/v1/device/config-test-node/app',
                       rule_forwards(changed, 'web-rule'))[0] == 200
            wait(lambda: listening(changed) and forwards(changed), what='the second rule')
            assert api('/api/v1/device/config-test-node/app',
                       {'protocol': 'tcp', 'srcPort': 0, 'protocol0': 'tcp',
                        'srcPort0': forward})[0] == 200
            wait(lambda: not forwards(forward) and not listening(forward),
                 what='the first rule to disappear')
            assert listening(changed)
            results['rules_replace_as_a_set_and_disappear_when_deleted'] = True

            # A restart re-reads the file the gateway wrote rather than losing it.
            current.terminate()
            current.wait(timeout=8)
            current = start_client()
            wait(lambda: listening(changed) and forwards(changed), what='restart to restore the rule')
            assert read_config()['custom']['nested']['keep'] == 17
            results['restart_reads_the_same_config_file'] = True

            # Validation still has to protect a working node: a rule whose local port        # is already taken must not be applied, and must not disturb the rule
            # that currently works.
            with socket.socket() as occupied:
                occupied.bind(('0.0.0.0', 0))
                occupied.listen()
                taken = occupied.getsockname()[1]
                assert api('/api/v1/device/config-test-node/app',
                           rule_forwards(taken, 'conflicting-rule'))[0] == 200
                wait(lambda: rejected_rule(taken, changed),
                     timeout=40, what='the conflicting rule to be rolled back')
            results['bind_failure_rolls_back_without_losing_working_rules'] = True

        if args.fixture:
            # The fixture never triggers a managed rewrite, so the profile is still
            # the JSON this test wrote. DPAPI migration is asserted by identity_cli.py.
            results['fixture_gateway_skips_dpapi_rewrite_check'] = True
        elif os.name == 'nt':
            assert config.read_bytes().startswith(b'FPD1')
            assert env['FASTP2P_TOKEN'].encode() not in config.read_bytes()
            results['windows_DPAPI_retained_after_merge_reload_and_rollback'] = True
        elif args.fixture:
            # No rule was applied, so the gateway never asked for a managed
            # rewrite and the file keeps the permissions the test created it with.
            results['fixture_gateway_skips_mode_check'] = True
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
