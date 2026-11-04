#!/usr/bin/env python3
"""Real config merge, automatic reload, persistence and rollback over TLS/WSS."""
import argparse, hashlib, http.client, json, os
from pathlib import Path
import secrets, socket, ssl, subprocess, sys, tempfile, time
from certificates import create_certificates

p=argparse.ArgumentParser();p.add_argument('--client',required=True);p.add_argument('--gateway',required=True)
p.add_argument('--profile-probe',help='Test-only native DPAPI reader on Windows')
args=p.parse_args();client=Path(args.client).resolve();gateway=Path(args.gateway).resolve()
with tempfile.TemporaryDirectory(prefix='fastp2p-config-sync-') as temporary:
    root=Path(temporary);create_certificates(root/'tls','127.0.0.1')
    env=dict(os.environ,FASTP2P_USER='config-admin',FASTP2P_PASSWORD=secrets.token_urlsafe(24),FASTP2P_TOKEN='9999999999999999')
    ctx=ssl.create_default_context(cafile=str(root/'tls/ca.crt'))
    logs={name:(root/(name+'.log')).open('w') for name in ('gateway','client')};children=[];jwt=None
    def wait(action,timeout=45):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            try:
                if action():return
            except (OSError,ValueError,AssertionError):pass
            time.sleep(.05)
        raise TimeoutError('configuration acceptance condition timed out')
    def api(path,body=None,auth=True):
        c=http.client.HTTPSConnection('127.0.0.1',31008,context=ctx,timeout=5)
        headers={'Content-Type':'application/json'}
        if auth and jwt:headers['Authorization']='Bearer '+jwt
        c.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,headers)
        r=c.getresponse();data=r.read();c.close();return r.status,json.loads(data) if data else None
    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    def listening(number):
        try:
            with socket.create_connection(('127.0.0.1',number),timeout=.2):return True
        except OSError:return False
    config=root/'config/fastp2p.conf';config.parent.mkdir()
    portable=gateway.suffix=='.py'
    def read_config():
        if args.profile_probe:
            result=subprocess.run([str(Path(args.profile_probe).resolve()),str(config)],capture_output=True,check=True)
            return json.loads(result.stdout)
        return json.loads(config.read_text())
    local={'product':'fastp2p','network':{'Node':'config-test-node','ServerHost':'127.0.0.1','ServerPort':37183,'Token':env['FASTP2P_TOKEN']},
        'CACertFile':str(root/'tls/ca.crt'),'custom':{'nested':{'keep':17,'update':1},'onlyLocal':'untouched'},'apps':[],'socks5':[]}
    config.write_text(json.dumps(local));endpoint='/api/v1/device/config-test-node/config'
    results={}
    def start_client():
        client_env=env.copy();client_env.pop('FASTP2P_TOKEN',None)
        process=subprocess.Popen([str(client),'run','--config',str(config)],env=client_env,stdout=logs['client'],stderr=subprocess.STDOUT)
        children.append(process);return process
    def applied(revision):
        value=api(endpoint)[1];return value['revision']>=revision and value['state']=='applied'
    def push(fields):
        status,value=api(endpoint,{'fields':fields});assert status==200;return value['revision']
    try:
        process=subprocess.Popen(([sys.executable,str(gateway)] if portable else [str(gateway)])+['--bind','127.0.0.1','--port','37183','--apiport','31008',
            '--cert',str(root/'tls/server.crt'),'--key',str(root/'tls/server.key')],cwd=root,env=env,stdout=logs['gateway'],stderr=subprocess.STDOUT)
        children.append(process);wait(lambda:api('/healthz',auth=False)[0]==200)
        status,value=api('/api/v1/user/login',{'user':env['FASTP2P_USER'],'password':env['FASTP2P_PASSWORD']},False)
        assert status==200;jwt=value['token'];current=start_client()
        wait(lambda:any(n['isActive'] for n in api('/api/v1/nodes')[1]['nodes']))
        assert api(endpoint,{'fields':{}},False)[0]==401
        revision=push({'custom':{'nested':{'update':2},'new':True,'unicode':'中文配置'},'network':{'PublicIPPort':port()}})
        wait(lambda:applied(revision));saved=read_config()
        assert saved['custom']=={'nested':{'keep':17,'update':2},'onlyLocal':'untouched','new':True,'unicode':'中文配置'}
        assert saved['network']['Token']==local['network']['Token'] and saved['CACertFile']==local['CACertFile']
        assert current.poll() is None and not saved['_fastp2pManaged']['pending']
        results['nested_field_merge_preserves_unsent_keys_and_reloads_in_same_process']=True
        forward=port();rule={'AppName':'config-forward','Protocol':'tcp','SrcPort':forward,
            'PeerNode':'offline-peer-node','DstHost':'127.0.0.1','DstPort':22,'UnderlayProtocol':'tcp','customRuleKey':42}
        revision=push({'apps':[rule]});wait(lambda:applied(revision) and listening(forward))
        assert read_config()['apps'][0]['customRuleKey']==42
        revision=push({'custom':{'new':False}});wait(lambda:applied(revision))
        assert listening(forward) and len(read_config()['apps'])==1
        # Web rule edits must also reach fastp2p.conf and survive restart.
        changed=forward
        if not portable:
            changed=port()
            status,_=api('/api/v1/device/config-test-node/app',{'appName':'web-rule','protocol':'tcp','srcPort':changed,
                'peerNode':'offline-peer-node','dstHost':'127.0.0.1','dstPort':22,'punchPriority':2})
            assert status==200
            wait(lambda:listening(changed) and any(a['SrcPort']==changed for a in read_config()['apps']))
        wait(lambda:api(endpoint)[1]['state']=='applied')
        current.terminate();current.wait(timeout=8);current=start_client()
        wait(lambda:listening(changed) and api(endpoint)[1]['state']=='applied')
        assert read_config()['custom']['nested']['keep']==17
        results['arrays_replace_when_supplied_web_rules_persist_and_restart_reads_conf']=True
        before=read_config();old_port=before['network']['PublicIPPort']
        # Validation errors do not write or interrupt the working client.
        revision=push({'network':{'ServerPort':'invalid'}})
        wait(lambda:api(endpoint)[1]['state']=='failed')
        assert read_config()==before and listening(changed)
        revision=push({'network':{'ServerPort':37183},'product':None})
        wait(lambda:api(endpoint)[1]['state']=='failed')
        assert read_config()==before and listening(changed)
        # Fix desired schema, then force a real bind failure after validation.
        with socket.socket() as occupied:
            occupied.bind(('0.0.0.0',0));occupied.listen()
            revision=push({'product':'fastp2p','network':{'ServerPort':37183,'PublicIPPort':occupied.getsockname()[1]}})
            wait(lambda:api(endpoint)[1]['state']=='failed')
            wait(lambda:listening(changed))
            assert read_config()['network']['PublicIPPort']==old_port
        results['invalid_fields_do_not_write_and_bind_failure_rolls_back_without_replay_loop']=True
        # A valid shape can still point at an unreachable/untrusted gateway.
        revision=push({'network':{'PublicIPPort':old_port,'ServerPort':37184}})
        wait(lambda:api(endpoint)[1]['state']=='failed',timeout=40)
        assert read_config()['network']['ServerPort']==37183 and listening(changed)
        revision=push({'network':{'ServerPort':37183},'custom':{'recovered':True}})
        wait(lambda:applied(revision))
        assert read_config()['custom']['recovered'] and current.poll() is None
        results['failed_gateway_change_rolls_back_and_new_revision_can_recover']=True
        if os.name=='nt':
            assert config.read_bytes().startswith(b'FPD1') and env['FASTP2P_TOKEN'].encode() not in config.read_bytes()
            results['windows_DPAPI_retained_after_merge_reload_and_rollback']=True
        else:assert config.stat().st_mode&0o077==0
        results['success']=True;print(json.dumps(results,indent=2))
    finally:
        for child in reversed(children):
            if child.poll() is None:child.terminate();child.wait(timeout=8)
        for file in logs.values():file.close()
        for name in logs:
            data=(root/(name+'.log')).read_text(errors='replace')
            assert 'Sanitizer' not in data and 'runtime error:' not in data
            assert env['FASTP2P_TOKEN'] not in data and env['FASTP2P_PASSWORD'] not in data
