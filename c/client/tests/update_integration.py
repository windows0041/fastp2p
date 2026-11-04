#!/usr/bin/env python3
"""Remote client upgrade through the gateway.

Uploads a package, orders one node to upgrade, and checks the client really did
download it, verified it, replaced its own executable and came back online.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument('--client', required=True)
p.add_argument('--gateway', required=True)
p.add_argument('--logs', required=True)
args = p.parse_args()
logs = Path(args.logs).resolve()
logs.mkdir(parents=True, exist_ok=True)
results = {}
children = []
files = []


def wait(action, timeout=90, what='condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if action():
                return
        except (OSError, AssertionError):
            pass
        time.sleep(0.2)
    raise TimeoutError('timed out waiting for ' + what)


with tempfile.TemporaryDirectory(prefix='fastp2p-update-') as temporary:
    root = Path(temporary)
    # The service owns its state directory, while the rest of the installation
    # is controlled by root. Run the client without root's write privileges.
    service_user = pwd.getpwnam('nobody') if os.geteuid() == 0 else None
    if service_user:
        root.chmod(0o711)
    try:
        # The certificate helper lives beside the other integration tests.
        from certificates import create_certificates
        create_certificates(root / 'certs', '127.0.0.1', '127.0.0.2')

        env = os.environ.copy()
        env.update(FASTP2P_USER='update-admin',
                   FASTP2P_PASSWORD=secrets.token_urlsafe(24),
                   FASTP2P_TOKEN='9999999999999999', FASTP2P_PUBLIC_HOST='127.0.0.2')
        ctx = ssl.create_default_context(cafile=str(root / 'certs' / 'ca.crt'))

        def start(command, name):
            directory = root / name
            directory.mkdir(exist_ok=True)
            f = (logs / (name + '.log')).open('a')
            files.append(f)
            child = subprocess.Popen([str(x) for x in command], cwd=directory, env=env,
                                     stdout=f, stderr=subprocess.STDOUT,
                                     user=service_user.pw_uid if service_user and name == 'client' else None,
                                     group=service_user.pw_gid if service_user and name == 'client' else None)
            children.append(child)
            return child

        start([Path(args.gateway).resolve(), '--bind', '127.0.0.2', '--apibind', '127.0.0.1',
               '--cert', root / 'certs' / 'server.crt', '--key', root / 'certs' / 'server.key'],
              'gateway')
        wait(lambda: socket.create_connection(('127.0.0.2', 27183), timeout=1).close() is None,
             what='gateway wss')

        # Run the client from a private copy: the upgrade replaces this file.
        install_dir = root / 'install'
        install_dir.mkdir()
        installed = install_dir / 'fastp2p'
        shutil.copy2(Path(args.client).resolve(), installed)
        installed.chmod(0o755)
        config = install_dir / 'config.json'
        config.write_text(json.dumps({'network': {'Node': 'update-node-1', 'ServerHost': '127.0.0.2'},
                                      'CACertFile': str(root / 'certs' / 'ca.crt'), 'apps': []}))
        if service_user:
            os.chown(install_dir, service_user.pw_uid, service_user.pw_gid)
            install_dir.chmod(0o700)
        client = start([installed, 'run', '--config', config], 'client')

        def api(path, body=None, token=None, method=None, raw=None, public=False):
            host, port = ('127.0.0.2', 27183) if public else ('127.0.0.1', 10008)
            conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=60)
            headers = {'Content-Type': 'application/json'}
            if token:
                headers['Authorization'] = 'Bearer ' + token
            payload = raw if raw is not None else (
                json.dumps(body).encode() if body is not None else None)
            conn.request(method or ('POST' if body is not None else 'GET'), path, payload, headers)
            response = conn.getresponse()
            status = response.status
            data = response.read()
            conn.close()
            return status, (json.loads(data) if data and data[:1] in b'{[' else data)

        status, body = api('/api/v1/user/login',
                           {'user': env['FASTP2P_USER'], 'password': env['FASTP2P_PASSWORD']})
        assert status == 200, (status, body)
        token = body['token']
        assert api('/', public=True)[0] == 404
        assert api('/api/v1/updates', token=token, public=True)[0] == 404
        assert api('/api/v1/update?platform=linux&version=9.9.9', token=token,
                   method='PUT', raw=b'test', public=True)[0] == 404
        results['web_and_upload_stay_on_private_port'] = True

        def online():
            status, body = api('/api/v1/nodes?query=update-node&limit=50', token=token)
            return status == 200 and any(n.get('name') == 'update-node-1' and n.get('isActive')
                                         for n in body['nodes'])
        wait(online, what='client online')
        results['client_registered'] = True

        def listening(port):
            try:
                socket.create_connection(('127.0.0.1', port), timeout=1).close()
                return True
            except OSError:
                return False

        # Give the client a listening rule first: after the upgrade the new image
        # must be able to bind the same port again, which fails if it inherited
        # the old listening socket.
        rule_port = 24470
        status, body = api('/api/v1/device/update-node-1/app',
                           {'appName': 'update-rule', 'protocol': 'tcp', 'srcPort': rule_port,
                            'peerNode': 'update-peer-9', 'dstHost': '127.0.0.1', 'dstPort': 22},
                           token)
        assert status == 200, (status, body)
        wait(lambda: listening(rule_port), what='rule listening before the upgrade')
        results['rule_listening_before_upgrade'] = True

        # A malformed file is rejected at upload. An ELF-looking but unusable
        # package can reach the client and must be rejected before shutdown.
        original = installed.read_bytes()
        assert api('/api/v1/update?platform=linux&version=9.9.8', token=token,
                   method='PUT', raw=b'not an executable')[0] == 400
        assert api('/api/v1/update?platform=linux&version=9.9.8', token=token,
                   method='PUT', raw=b'\x7fELF-invalid-program')[0] == 200
        assert api('/api/v1/device/update-node-1/upgrade', {'version': '9.9.8'}, token)[0] == 200
        wait(lambda: 'package cannot run as a fastp2p executable' in (logs / 'client.log').read_text(),
             what='invalid executable rejected before swapping')
        assert client.poll() is None and installed.read_bytes() == original
        assert online() and listening(rule_port)
        results['bad_package_does_not_replace_or_stop_client'] = True

        # --- Upload a package. It is a real executable so the swap is realistic.
        package = install_dir / 'package.bin'
        shutil.copy2(installed, package)
        with package.open('ab') as handle:
            handle.write(b'\n# upgrade marker\n')
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        status, body = api('/api/v1/update?platform=linux&version=9.9.9', token=token,
                           method='PUT', raw=package.read_bytes())
        assert status == 200 and body['sha256'] == digest, (status, body)
        results['package_uploaded_and_hashed'] = True

        status, body = api('/api/v1/updates', token=token)
        assert status == 200 and any(u['version'] == '9.9.9' for u in body['updates']), body
        results['package_listed'] = True

        # Re-uploading the same version with different content must replace the
        # entry rather than add a second one.
        with package.open('ab') as handle:
            handle.write(b'\n# second upload\n')
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        status, body = api('/api/v1/update?platform=linux&version=9.9.9', token=token,
                           method='PUT', raw=package.read_bytes())
        assert status == 200 and body['sha256'] == digest, (status, body)
        status, body = api('/api/v1/updates', token=token)
        same = [u for u in body['updates'] if u['version'] == '9.9.9']
        assert len(same) == 1 and same[0]['sha256'] == digest, body
        results['reupload_replaces_the_version'] = True

        # --- The download endpoint refuses a wrong token and unknown packages.
        assert api('/api/v1/update/download?platform=linux&version=9.9.9&token=1111111111111111',
                   token=token, public=True)[0] == 401
        assert api('/api/v1/update/download?platform=linux&version=0.0.1&token=9999999999999999',
                   token=token)[0] == 404
        results['download_requires_the_install_token'] = True

        # Populate the mirror catalog with the verified executable and a newer
        # package for an incompatible architecture. Only the native one may win.
        database = root / 'gateway/nodes.sqlite3'
        with sqlite3.connect(database, timeout=5) as db:
            sha, size, filename, uploaded = db.execute(
                "SELECT sha256,size,filename,uploaded_at FROM updates WHERE platform='linux' AND version='9.9.9'"
            ).fetchone()
            native = next(row for row in api('/api/v1/nodes', token=token)[1]['nodes']
                          if row['name'] == 'update-node-1')['os'].removesuffix('-c')
            other = 'linux-aarch64' if native != 'linux-aarch64' else 'linux-x86_64'
            db.executemany('INSERT INTO release_packages VALUES(?,?,?,?,?,?)', [
                (native, '9.9.9', sha, size, filename, uploaded),
                (other, '99.9.9', sha, size, filename, uploaded),
            ])
            db.execute("DELETE FROM updates WHERE platform='linux' AND version='9.9.9'")

        # --- Batch upgrade finds the outdated node and orders it.
        status, body = api('/api/v1/upgrades', {}, token)
        assert status == 200, body
        assert any(item['node'] == 'update-node-1' and item['to'] == '9.9.9'
                   for item in body['queued']), body
        results['batch_upgrade_queues_outdated_nodes'] = True
        results['batch_upgrade_selects_only_the_matching_architecture'] = True

        def replaced():
            if not installed.is_file():
                return False
            return hashlib.sha256(installed.read_bytes()).hexdigest() == digest
        wait(replaced, timeout=90, what='client to replace its executable')
        assert installed.with_name('fastp2p.old').read_bytes() == original
        results['client_installed_the_new_build'] = True

        # The re-exec keeps the same supervisor running, so the node must return.
        wait(online, timeout=90, what='client back online after upgrade')
        results['client_came_back_online'] = True

        # The rule is restored from the gateway and its port binds again.
        wait(lambda: listening(rule_port), timeout=60, what='rule listening after the upgrade')
        results['rule_listening_after_upgrade'] = True

        # --- An unknown version is rejected rather than silently ignored.
        assert api('/api/v1/device/update-node-1/upgrade', {'version': '8.8.8'}, token)[0] == 404
        results['unknown_version_rejected'] = True
        results['success'] = True
    finally:
        for child in children:
            child.terminate()
        for child in children:
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
        for f in files:
            f.close()

print(json.dumps(results, indent=2))
