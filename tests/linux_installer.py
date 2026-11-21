#!/usr/bin/env python3
"""Exercise real gateway-generated installers in private mount/network/PID namespaces.

Init commands are fixtures, not the host's service manager. Payload, enrollment,
certificate checks, filename token, filesystem changes and rollback are real.
"""
import argparse
from contextlib import ExitStack
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
from urllib.parse import urlsplit
from certificates import create_certificates

p = argparse.ArgumentParser()
p.add_argument('--client', required=True)
p.add_argument('--gateway', required=True)
p.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
args = p.parse_args()
client, gateway = Path(args.client).resolve(), Path(args.gateway).resolve()
version=subprocess.check_output([str(client),'--version'],text=True).split()[1]
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
with tempfile.TemporaryDirectory(prefix='fastp2p-installer-test-', dir='/var/tmp') as temporary, ExitStack() as mounts:
    root = Path(temporary)
    root.chmod(0o700)
    etc = root / 'etc'; etc.mkdir()
    for name in ('passwd', 'group', 'nsswitch.conf', 'hosts', 'resolv.conf', 'ld.so.cache'):
        if (Path('/etc') / name).is_file(): shutil.copyfile(Path('/etc') / name, etc / name)
    # All test services live on loopback. Avoid public DNS timeouts for the
    # client's default NAT probes inside the private network namespace.
    with (etc / 'hosts').open('a') as f: f.write('\n127.0.0.1 stun.fastp2p.top\n')
    # A private non-root account, without touching the host passwd/group files.
    for name in ('passwd', 'group'):
        path = etc / name
        path.write_text(''.join(line for line in path.read_text().splitlines(keepends=True) if not line.startswith('fastp2p:')))
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
    # Always detach borrowed mounts BEFORE TemporaryDirectory traverses its tree.
    # A read-only source is a second guard against deletion of host files.
    mounts.callback(command, 'umount', '-l', str(original_local))
    command('mount', '-o', 'remount,bind,ro', str(original_local))
    command('mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/usr/local')
    # Official Python containers keep their stdlib here. Preserve it while
    # isolating product paths and /usr/local/bin from the host installation.
    if (original_local/'lib').is_dir():
        Path('/usr/local/lib').mkdir()
        command('mount', '--bind', str(original_local/'lib'), '/usr/local/lib')
        command('mount', '-o', 'remount,bind,ro', '/usr/local/lib')
    command('mount', '-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', '/tmp')
    command('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    command('mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/var/lib')
    command('mount', '-t', 'tmpfs', 'tmpfs', '/usr/sbin')
    tools = root / 'tools'; tools.mkdir()
    events = root / 'events'
    environment = dict(os.environ, PATH=str(tools)+':/usr/bin:/bin', FIXTURE=str(root))
    def executable(path, content):
        path.write_text('#!/bin/sh\nset -eu\n'+content); path.chmod(0o755)
    executable(tools / 'service-fixture', '''
manager=$1; action=$2
case "$action" in
    status|is-active) test -e "$FIXTURE/client-running"; exit ;;
    enabled|is-enabled) test -e "$FIXTURE/client-enabled"; exit ;;
esac
echo "$manager $action" >> "$FIXTURE/events"
case "$action" in
    start)
        if [ -e "$FIXTURE/fail-start" ]; then rm "$FIXTURE/fail-start"; exit 1; fi
        if [ -e "$FIXTURE/fail-after-start" ]; then
            rm -f "$FIXTURE/fail-after-start" "$FIXTURE/client-running"; exit 0
        fi
        touch "$FIXTURE/client-running" ;;
    stop) rm -f "$FIXTURE/client-running" ;;
    enable) touch "$FIXTURE/client-enabled" ;;
    disable) rm -f "$FIXTURE/client-enabled" ;;
esac
''')
    executable(tools / 'systemctl', '''
if [ "$1" = --version ]; then echo "systemd ${FIXTURE_SYSTEMD:-252}"; exit; fi
if [ "$1" = cat ]; then test -f /etc/systemd/system/fastp2p-client.service; exit; fi
if [ "$1" = is-active ] && [ "${3:-}" != fastp2p-client.service ]; then test -e "$FIXTURE/gateway-active"; exit; fi
exec "$FIXTURE/tools/service-fixture" systemd "$1"
''')
    executable(tools / 'rc-service', '''
exec "$FIXTURE/tools/service-fixture" openrc "$2"
''')
    executable(tools / 'rc-update', '''
case "$1" in
    show) if [ -e "$FIXTURE/client-enabled" ]; then echo ' fastp2p | default'; fi ;;
    add) exec "$FIXTURE/tools/service-fixture" openrc-boot enable ;;
    del) exec "$FIXTURE/tools/service-fixture" openrc-boot disable ;;
esac
''')
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
        def api(path, body=None, method=None, extra_headers=None, port=31008):
            connection = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=20)
            headers = {'Content-Type': 'application/octet-stream'}
            if jwt: headers['Authorization'] = 'Bearer '+jwt
            if extra_headers: headers.update(extra_headers)
            connection.request(method or ('POST' if body else 'GET'), path, body, headers)
            response = connection.getresponse(); data = response.read(); headers = {k.lower(): v for k,v in response.getheaders()}
            connection.close(); return response.status, headers, data
        status, _, data = api('/api/v1/user/login', json.dumps({'user': env['FASTP2P_USER'], 'password': env['FASTP2P_PASSWORD']}))
        assert status == 200
        login = json.loads(data); jwt = login['token']; key = login['installToken']
        preset = root/'gateway.json'; preset.write_text(json.dumps(login['gateway']))
        environment['FASTP2P_BOOTSTRAP_FILE'] = str(preset)
        payload = client.read_bytes()
        assert api(f'/api/v1/update?platform=linux&version={version}', payload, 'PUT')[0] == 200
        status, headers, installer = api('/api/v1/update/install?platform=linux')
        assert status == 200 and headers['content-disposition'] == f'attachment; filename="fastp2p-{key}"'
        assert key.encode() not in installer, 'shared installer must not contain token'
        assert len(installer)<128*1024 and b'__FASTP2P_PAYLOAD__' not in installer
        assert hashlib.sha256(payload).hexdigest().encode() in installer
        assert api(f'/api/v1/update/install?platform=linux-x86_64&version={version}')[2]==installer
        cached=next((root/'updates').glob('installer-*.sh'))
        cached.write_bytes(installer[:-1]+bytes([installer[-1]^1]))
        assert api(f'/api/v1/update/install?platform=linux&version={version}')[2] == installer
        status, _, link = api('/api/v1/install/link', json.dumps({'platform': 'linux'}))
        assert status == 200
        url = urlsplit(json.loads(link)['url'])
        path = url.path + '?' + url.query
        status, headers, personal = api(path, extra_headers={'Authorization': 'unused'}, port=37183)
        assert status == 200 and headers['cache-control'] == 'no-store'
        assert f"token='{key}'".encode() in personal
        assert api(path, port=37183)[0] == 403
        assert all(key.encode() not in script.read_bytes() for script in (root/'updates').glob('installer-*.sh'))
        short_name = root/'install.sh'; short_name.write_bytes(personal)
        raw = api(f'/api/v1/update/download?platform=linux&version={version}&token='+key)[2]
        assert raw == payload, 'remote upgrades must continue to receive raw ELF'
        endpoint=f'/api/v1/update/download?platform=linux&version={version}'
        assert api(endpoint,extra_headers={'Authorization':'FastP2P '+key},port=37183)[2]==payload
        assert api(endpoint,extra_headers={'Authorization':'FastP2P 9999999999999998'},port=37183)[0]==401
        assert api('/api/v1/updates',extra_headers={'Authorization':'FastP2P '+key})[0]==401
        with sqlite3.connect(root/'nodes.sqlite3') as db:
            assert db.execute('SELECT expires_at FROM package_leases WHERE platform="linux"').fetchone()[0] > time.time()
        named = root/('fastp2p-'+key); named.write_bytes(installer)
        def run(path=named, expected=0, shell='sh'):
            result = subprocess.run([shell, str(path)], env=environment, capture_output=True, timeout=50)
            if result.returncode != expected:
                diagnostic = (result.stdout + result.stderr).decode(errors='replace')
                raise AssertionError(diagnostic.replace(key, '[redacted]'))
            assert key.encode() not in result.stdout+result.stderr
            assert b'Sanitizer' not in result.stderr and b'runtime error:' not in result.stderr
            return result
        profile = Path('/etc/fastp2p/config.conf')
        binary = Path('/usr/local/fastp2p/fastp2p')
        cli = Path('/usr/local/bin/fastp2p')
        controller = Path('/usr/local/fastp2p/fastp2p-service')
        adjacent = Path('/etc/fastp2p/gateway.env')
        adjacent.write_text('keep')
        results = {'gateway_filename_token_free_cache_raw_upgrade_and_download_lease': True}
        minimal = root/'procd-tools'
        minimal.mkdir()
        for name in ('sh','id','awk','uname','sha256sum','mktemp','chmod','cp','wc','rm','rmdir',
                     'mkdir','mv','grep','curl','cat','ls','sleep','touch','ln'):
            (minimal/name).symlink_to(shutil.which(name))
        native_path = environment['PATH']

        def native(*args):
            return subprocess.run([str(cli), *args], env=environment, capture_output=True, timeout=15)

        for manager in ('systemd', 'systemd219', 'procd', 'openrc'):
            environment['PATH'] = str(minimal) if manager == 'procd' else native_path
            for file in ('/etc/openwrt_release', '/etc/rc.common', '/sbin/openrc-run'):
                Path(file).unlink(missing_ok=True)
            shutil.rmtree('/run/systemd', ignore_errors=True)
            environment['FIXTURE_SYSTEMD'] = '219' if manager == 'systemd219' else '252'
            if manager.startswith('systemd'):
                Path('/run/systemd/system').mkdir(parents=True)
                unit = Path('/etc/systemd/system/fastp2p-client.service')
            else:
                unit = Path('/etc/init.d/fastp2p')
                if manager == 'procd':
                    Path('/etc/openwrt_release').write_text("DISTRIB_ID='ImmortalWrt'\n")
                    executable(Path('/etc/rc.common'), 'exec "$FIXTURE/tools/service-fixture" procd "$2"\n')
                else:
                    executable(Path('/sbin/openrc-run'), 'exit 0\n')

            for failure in ('fail-start', 'fail-after-start'):
                (root/failure).touch()
                run(expected=1)
                assert not any(path.exists() for path in (unit, profile, binary, cli, controller))
                assert not any(profile.parent.glob('config.conf.ca.*.pem'))
                assert not (root/'client-running').exists() and not (root/'client-enabled').exists()
                assert adjacent.read_text() == 'keep'

            if manager == 'procd':
                stats = os.statvfs('/usr/local')
                original_size = stats.f_blocks * stats.f_frsize
                command('mount','-o',f'remount,size={len(payload)+512*1024}','/usr/local')
            try:
                run(short_name if manager == 'procd' else named)
            finally:
                if manager == 'procd':
                    command('mount','-o',f'remount,size={original_size}','/usr/local')
            assert (root/'client-running').exists() and (root/'client-enabled').exists()
            assert binary.read_bytes() == payload and cli.is_symlink() and binary.samefile(cli)
            assert not (binary.parent/'bin').exists()
            assert profile.stat().st_uid == 0 and profile.stat().st_mode & 0o777 == 0o600
            assert subprocess.check_output([str(client),'--service-profile'],text=True).strip() == str(profile)
            config = json.loads(profile.read_text())
            ca_file = Path(config['CACertFile'])
            assert ca_file.parent == profile.parent and ca_file.name.startswith('config.conf.ca.')
            assert ca_file.read_bytes() == (root/'tls/ca.crt').read_bytes()
            text = unit.read_text()
            assert str(profile) in text and '--background' in text
            if manager.startswith('systemd'):
                assert ('ProtectSystem=full' if manager == 'systemd219' else 'ProtectSystem=strict') in text
                assert 'PrivateTmp' not in text and 'User=root' in text
            elif manager == 'procd':
                assert 'procd_set_param user root' in text and not controller.exists()
            else:
                assert 'command_user="root:root"' in text
            if manager == 'systemd':
                runtime_log = Path('/tmp/fastp2p/fastp2p.log')
                linked = root/'do-not-write'
                linked.write_text('keep')
                runtime_log.parent.symlink_to(root)
                call = ['run','--config',str(profile),'--background','--run-seconds','2']
                assert native(*call).returncode != 0 and linked.read_text() == 'keep'
                runtime_log.parent.unlink()
                native_result = native(*call)
                assert native_result.returncode == 0, native_result.stderr
                assert b'gateway authenticated' in runtime_log.read_bytes()
                assert runtime_log.stat().st_mode & 0o777 == 0o600
                assert key.encode() not in runtime_log.read_bytes()
                results['runtime_log_is_private_and_rejects_symlink'] = True
            before = profile.read_bytes()
            events.write_text('')
            run(expected=1)
            assert events.read_text() == '' and profile.read_bytes() == before
            if manager == 'procd':
                lock = Path('/var/run/fastp2p-install.lock')
                lock.mkdir()
                try:
                    assert native('uninstall').returncode != 0 and unit.exists()
                finally:
                    lock.rmdir()
                assert native('stop').returncode == 0 and not (root/'client-running').exists()

            keep = manager == 'openrc'
            removed = native('uninstall', '--keep-config') if keep else native('uninstall')
            assert removed.returncode == 0, removed.stderr.decode(errors='replace')
            assert not any(path.exists() for path in (cli, binary, unit, controller))
            assert not (root/'client-enabled').exists() and not (root/'client-running').exists()
            if keep:
                assert profile.read_bytes() == before and ca_file.exists()
            else:
                assert not profile.exists() and not ca_file.exists()
            assert adjacent.read_text() == 'keep'
            results[manager+'_fresh_install_rollback_and_uninstall'] = True

        # Exercise the real downloader against all manifest platforms, without
        # executing wrong-architecture images. Corrupt the fetched byte count
        # deliberately and verify every failure precedes any service change.
        arches=('x86_64','aarch64','armv7','i686','riscv64','s390x','ppc64le','mips64el')
        with sqlite3.connect(root/'nodes.sqlite3') as db:
            for arch in arches:
                db.execute("INSERT INTO release_packages SELECT ?,version,sha256,size,filename,uploaded_at FROM updates WHERE platform='linux'",('linux-'+arch,))
            db.execute("INSERT INTO release_packages SELECT platform,'99.99.99',sha256,size,filename,uploaded_at FROM release_packages WHERE platform='linux-x86_64'")
        latest=api('/api/v1/update/install?platform=linux')[2]
        assert b"x86_64) package_platform='linux-x86_64'; expected_version='99.99.99'" in latest
        assert f"aarch64) package_platform='linux-aarch64'; expected_version='{version}'".encode() in latest
        assert b"expected_version='99.99.99'" not in api(f'/api/v1/update/install?platform=linux&version={version}')[2]
        with sqlite3.connect(root/'nodes.sqlite3') as db:
            db.execute("DELETE FROM release_packages WHERE version='99.99.99'")
        universal=api('/api/v1/update/install?platform=linux')[2]
        assert len(universal)<128*1024 and key.encode() not in universal
        assert all(('package_platform=\'linux-'+arch+'\'').encode() in universal for arch in arches)
        alternate=root/('alternate-fastp2p-'+key);alternate.write_bytes(universal)
        executable(tools/'uname','printf "%s\\n" "${FIXTURE_CPU:-x86_64}"\n')
        executable(tools/'dd',r'''
case "$1 $2 $3" in 'if=/proc/'*'/exe bs=1 count=6') ;; *) exit 1 ;; esac
printf '\177ELF%b%b' "\\0${FIXTURE_CLASS:-2}" "\\0${FIXTURE_ENDIAN:-1}"
''')
        (tools/'curl').write_text('''#!/usr/bin/python3
import os,pathlib,stat,subprocess,sys
args=sys.argv[1:]
assert not any('Authorization:' in arg or 'token=' in arg for arg in args)
config=pathlib.Path(args[args.index('--config')+1])
assert stat.S_IMODE(config.stat().st_mode)==0o600
assert b'Authorization: FastP2P ' in config.read_bytes()
pathlib.Path(os.environ['FIXTURE'],'download-url').write_text(args[-1])
code=subprocess.call(['/usr/bin/curl',*args])
if code:sys.exit(code)
with open(args[args.index('--output')+1],'ab') as output:output.write(b'corrupt')
''');(tools/'curl').chmod(0o755)
        for cpu,arch in [(a,a) for a in arches]+[('arm64','aarch64'),('armv7l','armv7'),('powerpc64le','ppc64le'),('mips64','mips64el'),('mips','mips64el')]:
            environment['FIXTURE_CPU']=cpu
            events.write_text('');run(alternate,1)
            assert (root/'download-url').read_text().endswith('platform=linux-'+arch+'&version='+version)
            assert key not in (root/'download-url').read_text()
            assert events.read_text()=='' and profile.read_bytes()==before
        for cpu,elf_class,endian in [('mips64','2','2'),('mips','1','1'),('i586','2','1'),('unknown-cpu','2','1')]:
            environment.update(FIXTURE_CPU=cpu,FIXTURE_CLASS=elf_class,FIXTURE_ENDIAN=endian)
            (root/'download-url').unlink(missing_ok=True);events.write_text('');run(alternate,1)
            assert not (root/'download-url').exists() and events.read_text()=='' and profile.read_bytes()==before
        # A lease can keep a previous release around after the new release has
        # dropped some architectures. New installers should use only current packages.
        current_arches=('x86_64','aarch64','armv7','riscv64','mips64el')
        with sqlite3.connect(root/'nodes.sqlite3') as db:
            for arch in current_arches:
                db.execute("INSERT INTO release_packages SELECT platform,'99.99.99',sha256,size,filename,uploaded_at FROM release_packages WHERE platform=?",('linux-'+arch,))
            db.execute("INSERT INTO release_sync VALUES(1,'99.99.99',99)")
        current=api('/api/v1/update/install?platform=linux')[2]
        assert all(f"package_platform='linux-{arch}'; expected_version='99.99.99'".encode() in current for arch in current_arches)
        assert all(f"package_platform='linux-{arch}'".encode() not in current for arch in ('i686','s390x','ppc64le'))
        assert b"package_platform='linux-i686'" in api(f'/api/v1/update/install?platform=linux-i686&version={version}')[2]
        alternate.write_bytes(current)
        lock=Path('/var/run/fastp2p-install.lock')
        lock.mkdir()
        try:
            environment['FIXTURE_CPU']='i686'
            events.write_text('')
            response=run(alternate,1)
            assert '此安装脚本没有 i686 的客户端包'.encode() in response.stderr
            assert all(arch.encode() in response.stderr for arch in current_arches)
            assert not (root/'download-url').exists() and events.read_text()=='' and profile.read_bytes()==before
        finally:
            lock.rmdir()
            with sqlite3.connect(root/'nodes.sqlite3') as db:
                db.execute("DELETE FROM release_packages WHERE version='99.99.99'")
                db.execute("DELETE FROM release_sync WHERE id=1")
        results['new_installers_follow_the_current_release_architectures']=True
        environment['FIXTURE_CPU']='aarch64';events.write_text('')
        run(named,1) # Old manifest has only the real native manual package.
        assert events.read_text()=='' and profile.read_bytes()==before
        for name in ('curl','uname','dd'): (tools/name).unlink()
        for name in ('FIXTURE_CPU','FIXTURE_CLASS','FIXTURE_ENDIAN'): environment.pop(name,None)
        # A wrong public CA must fail before enrollment or service teardown.
        create_certificates(root/'wrong-tls','127.0.0.1')
        wrong_ca=installer.replace((root/'tls/ca.crt').read_bytes(),(root/'wrong-tls/ca.crt').read_bytes())
        alternate.write_bytes(wrong_ca);events.write_text('');run(alternate,1)
        assert events.read_text()=='' and profile.read_bytes()==before
        # A minimal x86_64 PATH has no od, dd or stat. Exercise both downloaders.
        for downloader in ('curl','wget'):
            if not shutil.which(downloader):
                continue
            fallback=root/(downloader+'-tools');fallback.mkdir()
            for name in ('sh','id','awk','uname','sha256sum','mktemp','chmod','cp','wc','rm','rmdir','mkdir','mv','grep',downloader,'cat','ls'):
                (fallback/name).symlink_to(shutil.which(name))
            for name in ('rc-service','rc-update'):(fallback/name).symlink_to(tools/name)
            environment['PATH']=str(fallback)
            # Fail on an intentionally wrong digest, proving TLS/auth download
            # completed but never reaching the native installer or old service.
            alternate.write_bytes(installer.replace(hashlib.sha256(payload).hexdigest().encode(),b'0'*64))
            events.write_text('');response=run(alternate,1)
            assert b'SHA-256' in response.stderr and events.read_text()=='' and profile.read_bytes()==before
            environment['PATH']=str(tools)+':/usr/bin:/bin'
        results['native_x86_64_download_with_no_od_dd_or_stat']=True
        results['universal_arch_selection_tls_header_auth_and_download_failures_preserve_service']=True
        Path('/var/run/fastp2p-install.lock').mkdir(); events.write_text('')
        run(expected=1); assert events.read_text() == '' and profile.read_bytes() == before
        Path('/var/run/fastp2p-install.lock').rmdir()
        run()
        assert profile.read_bytes() == before
        removed = native('uninstall')
        assert removed.returncode == 0, removed.stderr.decode(errors='replace')
        assert not profile.exists() and not controller.exists() and adjacent.read_text() == 'keep'
        assert not cli.exists()
        results['retained_config_reinstall_and_merged_gateway_directory'] = True
        print(json.dumps(results, indent=2))
    finally:
        proc.terminate(); proc.wait(timeout=10); logs.close()
        diagnostic = (root/'gateway.log').read_text(errors='replace')
        assert 'Sanitizer' not in diagnostic, diagnostic[diagnostic.find('Sanitizer'):].replace(key, '[redacted]')
