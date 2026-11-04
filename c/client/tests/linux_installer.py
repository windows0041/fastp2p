#!/usr/bin/env python3
"""Exercise real gateway-generated installers in private mount/network/PID namespaces.

Init commands are fixtures, not the host's service manager. Payload, enrollment,
certificate checks, filename token, filesystem changes and rollback are real.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
from certificates import create_certificates

p = argparse.ArgumentParser()
p.add_argument('--client', required=True)
p.add_argument('--gateway', required=True)
p.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
args = p.parse_args()
client, gateway = Path(args.client).resolve(), Path(args.gateway).resolve()
if not args.inside:
    assert os.geteuid() == 0, 'This isolated test requires root and mount/network namespaces'
    subprocess.run(['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc', sys.executable,
                    str(Path(__file__).resolve()), '--client', str(client), '--gateway', str(gateway),
                    '--inside'], check=True)
    sys.exit(0)

def command(*values):
    subprocess.run(values, check=True, stdout=subprocess.DEVNULL)

command('mount', '--make-rprivate', '/')
command('ip', 'link', 'set', 'lo', 'up')
with tempfile.TemporaryDirectory(prefix='fastp2p-installer-test-') as temporary:
    root = Path(temporary)
    root.chmod(0o700)
    etc = root / 'etc'; etc.mkdir()
    for name in ('passwd', 'group', 'nsswitch.conf', 'hosts', 'resolv.conf', 'ld.so.cache'):
        if (Path('/etc') / name).is_file(): shutil.copyfile(Path('/etc') / name, etc / name)
    # A private non-root account, without touching the host passwd/group files.
    with (etc / 'passwd').open('a') as f: f.write('\nfastp2p:x:32123:32123:fixture:/nonexistent:/bin/false\n')
    with (etc / 'group').open('a') as f: f.write('\nfastp2p:x:32123:\n')
    (etc / 'fastp2p').mkdir()
    (etc / 'systemd/system').mkdir(parents=True)
    (etc / 'init.d').mkdir()
    (etc / 'ssl').mkdir()
    shutil.copyfile('/etc/ssl/openssl.cnf', etc / 'ssl/openssl.cnf')
    if Path('/etc/alternatives').exists(): shutil.copytree('/etc/alternatives', etc/'alternatives', symlinks=True)
    command('mount', '--bind', str(etc), '/etc')
    original_local=root/'original-local'; original_local.mkdir()
    command('mount', '--bind', '/usr/local', str(original_local))
    command('mount', '-t', 'tmpfs', 'tmpfs', '/usr/local')
    # Official Python containers keep their stdlib here. Preserve it while
    # isolating product paths and /usr/local/bin from the host installation.
    if (original_local/'lib').is_dir():
        Path('/usr/local/lib').mkdir()
        command('mount', '--bind', str(original_local/'lib'), '/usr/local/lib')
    command('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    command('mount', '-t', 'tmpfs', 'tmpfs', '/usr/sbin')
    tools = root / 'tools'; tools.mkdir()
    events = root / 'events'
    environment = dict(os.environ, PATH=str(tools)+':/usr/bin:/bin', FIXTURE=str(root))
    def executable(path, content):
        path.write_text('#!/bin/sh\nset -eu\n'+content); path.chmod(0o755)
    executable(tools / 'systemctl', '''
if [ "$1" = --version ]; then echo "systemd ${FIXTURE_SYSTEMD:-252}"; exit; fi
if [ "$1" = cat ]; then test -f /etc/systemd/system/fastp2p-client.service; exit; fi
echo "systemd $*" >> "$FIXTURE/events"
if [ "$1" = start ] && [ -e "$FIXTURE/fail-start" ]; then rm "$FIXTURE/fail-start"; exit 1; fi
''')
    executable(tools / 'rc-service', '''
echo "openrc $*" >> "$FIXTURE/events"
if [ "${2:-}" = start ] && [ -e "$FIXTURE/fail-start" ]; then rm "$FIXTURE/fail-start"; exit 1; fi
''')
    executable(tools / 'rc-update', 'echo "openrc-enable $*" >> "$FIXTURE/events"\n')
    env = dict(environment, FASTP2P_USER='installer-admin', FASTP2P_PASSWORD=secrets.token_urlsafe(24),
               FASTP2P_TOKEN='9999999999999999')
    create_certificates(root / 'tls', '127.0.0.1')
    ctx = ssl.create_default_context(cafile=str(root / 'tls/ca.crt'))
    logs = (root / 'gateway.log').open('w')
    proc = subprocess.Popen([str(gateway), '--bind', '127.0.0.1', '--port', '37183', '--apiport', '31008',
                             '--cert', str(root/'tls/server.crt'), '--key', str(root/'tls/server.key'),
                             '--enrollment-ca', str(root/'tls/ca.crt')], cwd=root, env=env,
                            stdout=logs, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic()+15
        while True:
            assert proc.poll() is None, 'fixture gateway failed'
            try:
                with socket.create_connection(('127.0.0.1', 31008), timeout=1): break
            except OSError:
                assert time.monotonic() < deadline; time.sleep(.05)
        jwt = None
        def api(path, body=None, method=None):
            connection = http.client.HTTPSConnection('127.0.0.1', 31008, context=ctx, timeout=20)
            headers = {'Content-Type': 'application/octet-stream'}
            if jwt: headers['Authorization'] = 'Bearer '+jwt
            connection.request(method or ('POST' if body else 'GET'), path, body, headers)
            response = connection.getresponse(); data = response.read(); headers = {k.lower(): v for k,v in response.getheaders()}
            connection.close(); return response.status, headers, data
        status, _, data = api('/api/v1/user/login', json.dumps({'user': env['FASTP2P_USER'], 'password': env['FASTP2P_PASSWORD']}))
        assert status == 200
        login = json.loads(data); jwt = login['token']; key = login['installToken']
        preset = root/'gateway.json'; preset.write_text(json.dumps(login['gateway']))
        environment['FASTP2P_BOOTSTRAP_FILE'] = str(preset)
        payload = client.read_bytes()
        assert api('/api/v1/update?platform=linux&version=2.0.4', payload, 'PUT')[0] == 200
        status, headers, installer = api('/api/v1/update/install?platform=linux&version=2.0.4')
        assert status == 200 and headers['content-disposition'] == f'attachment; filename="fastp2p-{key}"'
        assert key.encode() not in installer, 'shared installer must not contain token'
        prefix, extracted = installer.split(b'__FASTP2P_PAYLOAD__\n', 1)
        assert extracted == payload and hashlib.sha256(extracted).hexdigest().encode() in prefix
        raw = api('/api/v1/update/download?platform=linux&version=2.0.4&token='+key)[2]
        assert raw == payload, 'remote upgrades must continue to receive raw ELF'
        with sqlite3.connect(root/'nodes.sqlite3') as db:
            assert db.execute('SELECT expires_at FROM package_leases WHERE platform="linux"').fetchone()[0] > time.time()
        named = root/('fastp2p-'+key); named.write_bytes(installer)
        def run(path=named, expected=0, shell='sh'):
            result = subprocess.run([shell, str(path)], env=environment, capture_output=True, timeout=50)
            assert result.returncode == expected, result.stderr.decode(errors='replace').replace(key, '[redacted]')
            assert key.encode() not in result.stdout+result.stderr
            assert b'Sanitizer' not in result.stderr and b'runtime error:' not in result.stderr
        profile = Path('/etc/fastp2p/client.json')
        controller = Path('/usr/local/fastp2p/fastp2p-service')
        results = {'gateway_filename_token_free_cache_raw_upgrade_and_download_lease': True}
        for manager in ('systemd', 'systemd219', 'procd', 'openrc'):
            for folder in ('/usr/local/fastp2p', '/etc/systemd/system', '/etc/init.d'):
                shutil.rmtree(folder, ignore_errors=True); Path(folder).mkdir(parents=True)
            for file in (profile, Path('/etc/openwrt_release'), Path('/etc/rc.common'), Path('/sbin/openrc-run')):
                file.unlink(missing_ok=True)
            shutil.rmtree('/run/systemd', ignore_errors=True)
            environment['FIXTURE_SYSTEMD'] = '219' if manager == 'systemd219' else '252'
            if manager.startswith('systemd'): Path('/run/systemd/system').mkdir(parents=True)
            elif manager == 'procd':
                Path('/etc/openwrt_release').touch()
                executable(Path('/etc/rc.common'), '''
echo "procd ${2:-}" >> "$FIXTURE/events"
if [ "${2:-}" = start ] && [ -e "$FIXTURE/fail-start" ]; then rm "$FIXTURE/fail-start"; exit 1; fi
''')
            else: executable(Path('/sbin/openrc-run'), 'exit 0\n')
            events.write_text('')
            run(shell='bash' if manager.startswith('systemd') else 'sh')
            first = json.loads(profile.read_text()); identity = first['network']['DeviceID']
            first['customSetting'] = {'preserve': True}; first['network']['UDPPort'] = 29887
            profile.write_text(json.dumps(first)); before = profile.read_bytes()
            binary = Path('/usr/local/fastp2p/bin/fastp2p')
            assert binary.read_bytes() == payload and Path('/usr/local/bin/fastp2p').read_bytes() == payload
            assert controller.stat().st_uid == 0 and not controller.stat().st_mode & 0o022
            assert Path('/usr/local/fastp2p').stat().st_uid == 0
            assert binary.parent.stat().st_uid != 0 and profile.stat().st_mode & 0o007 == 0
            if manager.startswith('systemd'):
                unit = Path('/etc/systemd/system/fastp2p-client.service').read_text()
                assert ('ProtectSystem=full' if manager == 'systemd219' else 'ProtectSystem=strict') in unit
                assert 'Restart=always' in unit and str(binary) in unit
                dropin = Path('/etc/systemd/system/fastp2p-client.service.d'); dropin.mkdir()
                (dropin/'20-remote-upgrade.conf').write_text('[Service]\nExecStart=/old/client\n')
            else:
                unit = Path('/etc/init.d/fastp2p').read_text()
                assert ('respawn 3600 3 0' if manager == 'procd' else 'supervisor="supervise-daemon"') in unit
            run()
            saved = json.loads(profile.read_text())
            assert saved['network']['DeviceID'] == identity and saved['customSetting'] == first['customSetting']
            assert saved['network']['UDPPort'] == 29887
            assert 'stop' in events.read_text() and 'start' in events.read_text()
            if manager.startswith('systemd'): assert not (dropin/'20-remote-upgrade.conf').exists()
            # Real startup failure must roll back old image, controller and profile.
            before = profile.read_bytes(); binary.write_bytes(payload+b'old-marker')
            old_controller = controller.read_bytes(); events.write_text(''); (root/'fail-start').touch()
            run(expected=1)
            assert profile.read_bytes() == before and binary.read_bytes() == payload+b'old-marker'
            assert controller.read_bytes() == old_controller and 'start' in events.read_text()
            # Corrupt payload, missing/ambiguous filename token, bad key and an
            # unreadable profile must not reach the service teardown.
            for content, filename in ((installer[:-1]+bytes([installer[-1]^1]), named.name),
                                      (installer, 'fastp2p-missing'), (installer, named.name+'-'+key),
                                      (installer, 'fastp2p-9999999999999998')):
                bad = root/filename; bad.write_bytes(content); events.write_text('')
                run(bad, 1); assert events.read_text() == '' and profile.read_bytes() == before
            named.write_bytes(installer)
            profile.write_text('{broken'); events.write_text(''); run(expected=1)
            assert profile.read_text() == '{broken' and events.read_text() == ''
            profile.write_bytes(before)
            results[manager+'_install_reinstall_preserve_config_and_rollback'] = True
        Path('/var/run/fastp2p-install.lock').mkdir(); events.write_text('')
        run(expected=1); assert events.read_text() == '' and profile.read_bytes() == before
        Path('/var/run/fastp2p-install.lock').rmdir()
        # Full uninstall delegates to the external controller and must not erase
        # gateway files that share /etc/fastp2p.
        adjacent=Path('/etc/fastp2p/gateway.env'); adjacent.write_text('keep')
        subprocess.run(['/usr/local/bin/fastp2p','uninstall'], env=environment, check=True, stdout=subprocess.DEVNULL)
        assert not profile.exists() and not controller.exists() and adjacent.read_text() == 'keep'
        assert not Path('/usr/local/bin/fastp2p').exists()
        results['installer_lock_and_full_uninstall_preserve_adjacent_gateway_files'] = True
        print(json.dumps(results, indent=2))
    finally:
        proc.terminate(); proc.wait(timeout=10); logs.close()
        diagnostic = (root/'gateway.log').read_text(errors='replace')
        assert 'Sanitizer' not in diagnostic, diagnostic[diagnostic.find('Sanitizer'):].replace(key, '[redacted]')
