#!/usr/bin/env python3
"""Real TLS/WSS tests for persistent accounts and offline-only registry deletion."""
import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlencode

p=argparse.ArgumentParser();p.add_argument('--gateway',required=True);p.add_argument('--cert-dir',required=True);p.add_argument('--logs',required=True)
args=p.parse_args();logs=Path(args.logs);logs.mkdir(parents=True,exist_ok=True)
ctx=ssl.create_default_context(cafile=str(Path(args.cert_dir)/'ca.crt'))
user='admin-before';password=secrets.token_urlsafe(24);changed=secrets.token_urlsafe(24);key='9999999999999999'
process=None;peers=[];results={};jwt=None

def api(path,body=None,auth=True,method=None):
    c=http.client.HTTPSConnection('127.0.0.1',31008,context=ctx,timeout=5)
    headers={'Content-Type':'application/json'}
    if auth and jwt:headers['Authorization']='Bearer '+jwt
    c.request(method or ('POST' if body is not None else 'GET'),path,json.dumps(body).encode() if body is not None else None,headers)
    r=c.getresponse();status=r.status;data=r.read();c.close()
    return status,json.loads(data) if data else None
def wait(check):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        assert process.poll() is None
        try:
            if check():return
        except OSError:pass
        time.sleep(.05)
    raise TimeoutError('Account/registry test condition timed out')
def peer(device,host):
    raw=ctx.wrap_socket(socket.create_connection(('127.0.0.1',37183),timeout=3),server_hostname='127.0.0.1')
    query=urlencode({'node':host,'token':key,'protocol':'fastp2p1','version':'1.0.0','autonode':1,'deviceid':device,'hostname':host})
    raw.sendall(('GET /api/v1/login?'+query+' HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+base64.b64encode(secrets.token_bytes(16)).decode()+'\r\n\r\n').encode())
    data=bytearray()
    while b'\r\n\r\n' not in data:data.extend(raw.recv(4096))
    assert b' 101 ' in data.split(b'\r\n',1)[0]
    peers.append(raw)
    wait(lambda:any(n['name']==host and n['isActive'] for n in api('/api/v1/nodes')[1]['nodes']))
    return raw
def delete(name,auth=True):return api('/api/v1/nodes/'+name,auth=auth,method='DELETE')[0]

with tempfile.TemporaryDirectory(prefix='fastp2p-admin-') as temporary:
    directory=Path(temporary);directory.chmod(0o700)
    env=os.environ.copy();env.update(FASTP2P_USER=user,FASTP2P_PASSWORD=password,FASTP2P_TOKEN=key)
    log=(logs/'gateway.log').open('w')
    def start():
        global process
        process=subprocess.Popen([str(Path(args.gateway).resolve()),'--cert',str(Path(args.cert_dir).resolve()/'server.crt'),'--key',str(Path(args.cert_dir).resolve()/'server.key'),'--port','37183','--apiport','31008'],cwd=directory,env=env,stdout=log,stderr=subprocess.STDOUT)
        wait(lambda:api('/healthz',auth=False)[0]==200)
    try:
        start()
        status,login=api('/api/v1/user/login',{'user':user,'password':password},False);assert status==200
        jwt=login['token'];install=login['installToken']
        live=peer('1'*32,'keep-online-node');offline=peer('2'*32,'remove-offline-node')
        assert delete('keep-online-node')==409
        assert delete('remove-offline-node',False)==401
        offline.close();peers.remove(offline)
        wait(lambda:any(n['name']=='remove-offline-node' and not n['isActive'] for n in api('/api/v1/nodes')[1]['nodes']))
        assert delete('remove-offline-node')==200 and delete('remove-offline-node')==404
        assert not any(n['name']=='remove-offline-node' for n in api('/api/v1/nodes')[1]['nodes'])
        reconnect=peer('2'*32,'remove-offline-node')
        results['offline_deletion_authorization_online_guard_and_reenrollment']=True
        body={'user':'admin-after','currentPassword':'incorrect','newPassword':changed}
        assert api('/api/v1/user/account',body)[0]==403
        body['currentPassword']=password;body['newPassword']='short'
        assert api('/api/v1/user/account',body)[0]==400 and api('/api/v1/status')[0]==200
        body['newPassword']=changed
        # A request authorized before the password change cannot mutate afterward.
        delayed=http.client.HTTPSConnection('127.0.0.1',31008,context=ctx,timeout=5)
        stale=json.dumps({'user':'stale','currentPassword':password,'newPassword':secrets.token_urlsafe(24)}).encode()
        delayed.putrequest('POST','/api/v1/user/account');delayed.putheader('Authorization','Bearer '+jwt)
        delayed.putheader('Content-Type','application/json');delayed.putheader('Content-Length',str(len(stale)));delayed.endheaders();delayed.send(stale[:1]);time.sleep(.1)
        assert api('/api/v1/user/account',body)[0]==200
        delayed.send(stale[1:]);response=delayed.getresponse();assert response.status==401;response.read();delayed.close()
        assert api('/api/v1/status')[0]==401
        assert api('/api/v1/user/login',{'user':user,'password':password},False)[0]==401
        status,after=api('/api/v1/user/login',{'user':'admin-after','password':changed},False);assert status==200 and after['installToken']==install
        jwt=after['token'];assert api('/api/v1/status')[1]['user']=='admin-after'
        assert len([n for n in api('/api/v1/nodes')[1]['nodes'] if n['isActive']])==2
        results['custom_account_password_verification_session_revocation_and_live_clients_unchanged']=True
        for connection in peers:connection.close()
        peers.clear();process.terminate();assert process.wait(timeout=8)==0
        start() # Bootstrap environment is deliberately still the old account.
        assert api('/api/v1/user/login',{'user':user,'password':password},False)[0]==401
        assert api('/api/v1/user/login',{'user':'admin-after','password':changed},False)[0]==200
        with sqlite3.connect(directory/'nodes.sqlite3') as db:
            row=db.execute('SELECT username,length(salt),length(password_hash),iterations FROM admin').fetchone()
            assert row==('admin-after',16,32,600000)
            assert db.execute('PRAGMA user_version').fetchone()[0]==2
            assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        data=(directory/'nodes.sqlite3').read_bytes()
        assert password.encode() not in data and changed.encode() not in data
        results['salted_password_hash_and_account_persist_after_restart']=True
        process.terminate();assert process.wait(timeout=8)==0
        command=[str(Path(args.gateway).resolve()),'--cert',str(Path(args.cert_dir).resolve()/'server.crt'),'--key',str(Path(args.cert_dir).resolve()/'server.key'),'--reset-admin']
        reset=subprocess.run(command,cwd=directory,env=env,capture_output=True,timeout=10)
        assert reset.returncode==0 and b'account reset' in reset.stdout
        start()
        assert api('/api/v1/user/login',{'user':user,'password':password},False)[0]==200
        status,reset_login=api('/api/v1/user/login',{'user':user,'password':password},False);assert status==200
        jwt=reset_login['token'];assert len(api('/api/v1/nodes')[1]['nodes'])==2
        results['stopped_gateway_admin_recovery_preserves_node_records']=True
        results['success']=True
    finally:
        for connection in peers:connection.close()
        if process and process.poll() is None:process.terminate();process.wait(timeout=8)
        log.close()
        diagnostic=(logs/'gateway.log').read_text(errors='replace')
        assert 'Sanitizer' not in diagnostic and 'runtime error:' not in diagnostic
        (logs/'result.json').write_text(json.dumps(results,indent=2)+'\n')
        print(json.dumps(results,indent=2))
