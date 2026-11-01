#!/usr/bin/env python3
"""Real auto-named C clients: local identity, database recovery and forwarding.

Run in fresh network AND UTS namespaces. The short/duplicate hostnames set here
must never change the developer's or CI runner's actual hostname.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'client/tests'))
from certificates import create_certificates

p=argparse.ArgumentParser();p.add_argument('--gateway',required=True);p.add_argument('--client',required=True)
p.add_argument('--output',default='build/registry/result.json');args=p.parse_args()
gateway,client=Path(args.gateway).resolve(),Path(args.client).resolve()
for namespace in ['net','uts']:
    assert Path('/proc/self/ns/'+namespace).readlink()!=Path('/proc/1/ns/'+namespace).readlink(), 'Use isolated net and UTS namespaces'
result={};children=[];handles=[];process=None;echo=None
with tempfile.TemporaryDirectory(prefix='openp2p-c-registry-') as temporary:
    root=Path(temporary);assert root.resolve().parent==Path(tempfile.gettempdir()).resolve()
    create_certificates(root/'certs','127.0.0.1')
    environment=os.environ.copy();environment.update(OPENP2P_USER='registry-admin',OPENP2P_PASSWORD=secrets.token_urlsafe(24),OPENP2P_TOKEN=str(2**64-1))
    context=ssl.create_default_context(cafile=str(root/'certs/ca.crt'));jwt=None
    def start(command,name):
        log=(root/(name+'.log')).open('w');handles.append(log)
        child=subprocess.Popen([str(value) for value in command],cwd=root,env=environment,stdout=log,stderr=subprocess.STDOUT)
        return child
    def api(path,body=None):
        conn=http.client.HTTPSConnection('127.0.0.1',31008,context=context,timeout=3)
        try:
            conn.request('POST' if body is not None else 'GET',path,None if body is None else json.dumps(body),
                         {'Content-Type':'application/json',**({'Authorization':jwt} if jwt else {})})
            response=conn.getresponse();raw=response.read();data=json.loads(raw) if raw else {'error':0};assert response.status==200,(response.status,path)
            return data
        finally:conn.close()
    def wait(check,timeout=30):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            assert process.poll() is None, 'Gateway stopped; inspect private test logs'
            try:
                value=check()
                if value:return value
            except (OSError,AssertionError):pass
            time.sleep(.05)
        raise TimeoutError('Registry test timed out')
    def boot(name):
        return start([gateway,'--cert',root/'certs/server.crt','--key',root/'certs/server.key','--database',root/'nodes.sqlite3',
                      '--port','37183','--apiport','31008'],name)
    def node(label):
        child=start([client,'--serverhost','127.0.0.1','--port','37183','--cacert',root/'certs/ca.crt',
                     '--identity-file',root/(label+'.identity')],label+'-'+str(len(children)))
        children.append(child);return child
    def mapping():
        with sqlite3.connect(root/'nodes.sqlite3') as database:
            return dict(database.execute('SELECT device_id,name FROM nodes WHERE device_id IS NOT NULL'))
    def stop(child):
        child.terminate();assert child.wait(timeout=10)==0
    def ready(count):
        wait(lambda:len(api('/api/v1/devices')['nodes'])==count)
        time.sleep(.3)  # Let clients process the login/report acknowledgements before shutdown.
    try:
        socket.sethostname(b'pc')
        process=boot('gateway');wait(lambda:api('/healthz')['status']=='ok')
        jwt=api('/api/v1/user/login',{'user':environment['OPENP2P_USER'],'password':environment['OPENP2P_PASSWORD']})['token']
        one=node('one');two=node('two');ready(2)
        original=mapping();assert len(original)==2
        assert all(name.startswith('pc') and len(name)==8 and name[2:].isdigit() for name in original.values())
        identities={label:(root/(label+'.identity')).read_bytes() for label in ['one','two']}
        stop(one);ready(1)
        rows=api('/api/v1/nodes');assert rows['total']==2 and sum(n['isActive'] for n in rows['nodes'])==1
        one=node('one');ready(2);assert mapping()==original
        assert all((root/(label+'.identity')).read_bytes()==value for label,value in identities.items())
        result['hostname_numeric_padding_and_persistent_CLI_identity']=True
        process.kill();assert process.wait(timeout=10)==-9
        stop(one);stop(two)
        process=boot('gateway-recovered');wait(lambda:api('/healthz')['status']=='ok')
        rows=api('/api/v1/nodes');assert rows['total']==2 and all(not n['isActive'] for n in rows['nodes'])
        with sqlite3.connect(root/'nodes.sqlite3') as database:assert database.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert mapping()==original
        result['crash_recovery_retains_names_and_clears_online_flags']=True
        socket.sethostname(b'identical-host')
        three=node('three');four=node('four');ready(2)
        names=[n['name'] for n in api('/api/v1/devices')['nodes']]
        assert len(set(names))==2 and 'identical-host' in names
        assert all(name=='identical-host' or (name.startswith('identical-host-') and name[15:].isdigit()) for name in names)
        result['duplicate_hostnames_get_distinct_canonical_names']=True
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                while data:=self.request.recv(65536):self.request.sendall(data)
        echo=socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo);echo.daemon_threads=True
        threading.Thread(target=echo.serve_forever,daemon=True).start()
        for transport,priority in [('tcp',3),('quic',1)]:
            with socket.socket() as free:free.bind(('127.0.0.1',0));port=free.getsockname()[1]
            reply=api('/api/v1/device/'+names[0]+'/app',{'appName':'auto-'+transport,'protocol':'tcp','srcPort':port,
                      'peerNode':names[1],'dstHost':'127.0.0.1','dstPort':echo.server_address[1],'punchPriority':priority})
            assert reply['error']==0
            def transfer():
                with socket.create_connection(('127.0.0.1',port),timeout=2) as stream:
                    stream.settimeout(5);payload=secrets.token_bytes(16384);stream.sendall(payload);data=bytearray()
                    while len(data)<len(payload):
                        part=stream.recv(len(payload)-len(data))
                        if not part:return False
                        data.extend(part)
                    return data==payload
            wait(transfer,45);result['canonical_name_'+transport+'_forwarding']=True
        stop(three);stop(four)
        process.terminate();assert process.wait(timeout=10)==0
        result['success']=True
    finally:
        for child in children:
            if child.poll() is None:child.terminate();child.wait(timeout=10)
        if process and process.poll() is None:process.terminate();process.wait(timeout=10)
        if echo:echo.shutdown();echo.server_close()
        for handle in handles:handle.close()
        for log in root.glob('*.log'):
            text=log.read_text(errors='replace');assert 'Sanitizer' not in text and 'runtime error:' not in text, 'Sanitizer failure in private fixture logs'
        output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
