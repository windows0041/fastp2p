#!/usr/bin/env python3
"""Install using one token, with real CA/hostname/key verification and no OS changes."""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from certificates import create_certificates

p=argparse.ArgumentParser();p.add_argument('--client',required=True);p.add_argument('--gateway',required=True)
p.add_argument('--output',default='build/enrollment-result.json');args=p.parse_args()
result={};gateway=None
with tempfile.TemporaryDirectory(prefix='fastp2p-enrollment-') as temporary:
    root=Path(temporary).resolve();assert root.parent==Path(tempfile.gettempdir()).resolve()
    create_certificates(root/'tls','127.0.0.1');create_certificates(root/'untrusted','127.0.0.1')
    environment=os.environ.copy();environment.update(FASTP2P_USER='install-admin',FASTP2P_PASSWORD=secrets.token_urlsafe(24),FASTP2P_TOKEN='9999999999999999')
    client_environment=environment.copy();client_environment.pop('FASTP2P_TOKEN',None)
    context=ssl.create_default_context(cafile=str(root/'tls/ca.crt'))
    log=(root/'gateway.log').open('w')
    command=[str(Path(args.gateway).resolve())]
    if command[0].endswith('.py'):command.insert(0,sys.executable)
    try:
        gateway=subprocess.Popen(command+['--cert',str(root/'tls/server.crt'),'--key',str(root/'tls/server.key'),
            '--enrollment-ca',str(root/'tls/ca.crt'),'--bind','127.0.0.1','--port','37183','--apiport','31008'],cwd=root,env=environment,stdout=log,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+20
        while True:
            assert gateway.poll() is None,'Gateway did not start'
            try:
                with socket.create_connection(('127.0.0.1',31008),timeout=1):break
            except OSError:
                assert time.monotonic()<deadline;time.sleep(.05)
        connection=http.client.HTTPSConnection('127.0.0.1',31008,context=context,timeout=5)
        connection.request('POST','/api/v1/user/login',json.dumps({'user':environment['FASTP2P_USER'],'password':environment['FASTP2P_PASSWORD']}),{'Content-Type':'application/json'})
        response=connection.getresponse();body=json.loads(response.read());connection.close();assert response.status==200
        token=body['installToken'];assert len(token)==16 and token.isdecimal()
        payload={'v':1,**body['gateway'],'key':token}
        assert payload['host']=='127.0.0.1' and payload['port']==37183 and payload['key']=='9999999999999999'
        preset=root/'public-gateway.json';preset.write_text(json.dumps({k:payload[k] for k in ['host','port','ca']}))
        client_environment['FASTP2P_BOOTSTRAP_FILE']=str(preset)
        result['sixteen_digits_with_trusted_public_gateway_preset']=True
        profile=root/'client.profile';token_file=root/'install.token';token_file.write_text(token)
        def install(expected=0):
            completed=subprocess.run([str(Path(args.client).resolve()),'install','--token-file',str(token_file),
                '--config',str(profile),'--no-service'],env=client_environment,cwd=root,capture_output=True,timeout=40)
            if completed.returncode != expected:
                diagnostic = completed.stdout.decode(errors='replace') + completed.stderr.decode(errors='replace')
                # The installer intentionally keeps normal event logging quiet.
                # Reproduce only in this private test directory using the same
                # gateway identity, so CI failures expose the transport reason.
                probe=root/'failed-install-probe.json'
                probe.write_text(json.dumps({'product':'fastp2p','network':{'AutoNode':True,
                    'ServerHost':payload['host'],'ServerPort':payload['port'],'Token':payload['key']},
                    'CACertFile':str(root/'tls/ca.crt')}))
                trace=subprocess.run([str(Path(args.client).resolve()),'run','--config',str(probe),'--run-seconds','3'],
                    env=client_environment,capture_output=True,timeout=15)
                diagnostic += trace.stdout.decode(errors='replace') + trace.stderr.decode(errors='replace')
                if Path(args.gateway).suffix == '.py':
                    diagnostic += (root/'gateway.log').read_text(errors='replace')[-4000:]
                raise AssertionError((completed.returncode, diagnostic.replace(token,'[fixture-key]').replace(payload['key'],'[fixture-key]')))
            assert token.encode() not in completed.stdout+completed.stderr and payload['key'].encode() not in completed.stdout+completed.stderr
            assert b'Sanitizer' not in completed.stderr and b'runtime error:' not in completed.stderr
            return completed
        initial=install();assert b'gateway identity verified' in initial.stdout
        if sys.platform.startswith('linux') and os.geteuid() != 0:
            named = root / ('fastp2p-linux-v2.0.2-' + token)
            shutil.copy2(args.client, named)
            named_environment = dict(client_environment, XDG_CONFIG_HOME=str(root / 'named-config'))
            completed = subprocess.run([str(named), '--no-service'], cwd=root, env=named_environment,
                                       capture_output=True, timeout=40)
            assert completed.returncode == 0 and b'gateway identity verified' in completed.stdout
            assert token.encode() not in completed.stdout + completed.stderr
            named_profile = root / 'named-config/fastp2p/client.json'
            completed = subprocess.run([str(Path(args.client).resolve()), 'run', '--config', str(named_profile),
                                        '--run-seconds', '3'], env=named_environment, capture_output=True, timeout=20)
            assert completed.returncode == 0 and b'gateway authenticated' in completed.stdout
            result['filename_token_enrolls_without_token_arguments'] = True
        trust=next(root.glob(profile.name+'.ca.*.pem'))
        trust_stat=trust.stat()
        def same_trust_file():
            current=trust.stat()
            return (current.st_ino,current.st_uid,current.st_gid,current.st_mode)==(trust_stat.st_ino,trust_stat.st_uid,trust_stat.st_gid,trust_stat.st_mode)
        original=profile.read_bytes()
        if os.name=='nt':
            # Default-path migration is isolated from the real user's profile and
            # never installs or removes a service/autostart entry.
            appdata=root/'legacy-user';old=appdata/'fastp2p/client.dat';old.parent.mkdir(parents=True)
            old.write_bytes(original)
            migration_env=dict(client_environment,LOCALAPPDATA=str(appdata))
            migrated=old.parent/'config/fastp2p.conf'
            completed=subprocess.run([str(Path(args.client).resolve()),'install','--token-file',str(token_file),'--no-service'],
                env=migration_env,capture_output=True,timeout=40)
            assert completed.returncode==0 and not old.exists() and migrated.read_bytes().startswith(b'FPD1')
            assert Path(str(migrated)+'.migrated').is_file() and token.encode() not in migrated.read_bytes()
            completed=subprocess.run([str(Path(args.client).resolve()),'run','--config',str(migrated),'--run-seconds','3'],
                env=migration_env,capture_output=True,timeout=20)
            assert completed.returncode==0 and b'gateway authenticated' in completed.stdout
            result['legacy_windows_DPAPI_profile_migrates_to_config_fastp2p_conf']=True
        if os.name=='nt':assert original.startswith(b'FPD1') and payload['key'].encode() not in original
        else:assert profile.stat().st_mode & 0o077==0
        install();assert same_trust_file();result['verified_private_profile_and_repeat_install']=True
        completed=subprocess.run([str(Path(args.client).resolve()),'run','--config',str(profile),'--run-seconds','3'],
            env=client_environment,capture_output=True,timeout=20)
        assert completed.returncode==0 and b'gateway authenticated' in completed.stdout
        result['saved_profile_connects_without_token_or_CA_arguments']=True
        before=profile.read_bytes()
        def replace(change):
            bad={**payload,**change};preset.write_text(json.dumps({k:bad[k] for k in ['host','port','ca']}));token_file.write_text(bad['key'])
            install(1);assert profile.read_bytes()==before and same_trust_file()
        replace({'ca':(root/'untrusted/ca.crt').read_text()});result['wrong_CA_rejected_without_replacing_profile']=True
        replace({'host':'localhost'});result['wrong_hostname_rejected_without_replacing_profile']=True
        replace({'key':'9999999999999998'});result['wrong_access_key_rejected_without_replacing_profile']=True
        for malformed in ['FP1.invalid','123456789012345','12345678901234567','0000000000000000','abcdefghijklmnop']:
            token_file.write_text(malformed);install(2);assert profile.read_bytes()==before
        result['malformed_token_rejected']=True;result['existing_CA_identity_and_permissions_preserved']=True;result['success']=True
    finally:
        if gateway and gateway.poll() is None:gateway.terminate();gateway.wait(timeout=8)
        log.close()
        assert 'Sanitizer' not in (root/'gateway.log').read_text(errors='replace')
        output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
