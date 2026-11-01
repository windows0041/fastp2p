#!/usr/bin/env python3
"""Exercise the real TLS/HTTP/WebSocket and NAT endpoints without a WS package.

Run in an isolated Linux network namespace. Test credentials and TLS keys remain
in a private temporary directory; only boolean results are printed.
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlencode

p = argparse.ArgumentParser()
p.add_argument('--gateway', required=True)
p.add_argument('--cert-dir', required=True)
p.add_argument('--logs', required=True)
args = p.parse_args()
if Path('/proc/self/ns/net').readlink() == Path('/proc/1/ns/net').readlink():
    raise SystemExit('Use the isolated network test wrapper')
logs = Path(args.logs).resolve(); logs.mkdir(parents=True, exist_ok=True)
certs = Path(args.cert_dir).resolve()
context = ssl.create_default_context(cafile=str(certs/'ca.crt'))
token = 9999999999999999
user, password = 'gateway-protocol-test', secrets.token_urlsafe(24)
results, clients = {}, []
process = None

def crc(text):
    value = (1 << 64)-1
    for c in text.encode():
        value ^= c
        for _ in range(8): value = (value >> 1) ^ (0xd800000000000000 if value & 1 else 0)
    return value ^ ((1 << 64)-1)

def message(main, sub, body=None):
    if not isinstance(body, bytes): body = json.dumps(body,separators=(',', ':')).encode()
    return struct.pack('<IHH',len(body),main,sub)+body

def api(path, body=None, jwt=None, connection=None, timeout=3):
    conn = connection or http.client.HTTPSConnection('127.0.0.1',10008,context=context,timeout=timeout)
    headers = {'Content-Type': 'application/json'}
    if jwt: headers['Authorization'] = jwt
    try:
        conn.request('POST' if body is not None else 'GET',path,
            json.dumps(body).encode() if body is not None else None,headers)
        response = conn.getresponse();data = response.read()
        return response.status,json.loads(data) if data else None
    finally:
        if connection is None: conn.close()

def wait(check, timeout=10):
    deadline = time.monotonic()+timeout
    while time.monotonic()<deadline:
        assert process.poll() is None,'Gateway exited; inspect the private log'
        try:
            if check(): return
        except (OSError,ValueError): pass
        time.sleep(.05)
    raise TimeoutError('Protocol integration step timed out')

class WS:
    def __init__(self,name,credential=token,source='127.0.0.1',port=27183,path='/api/v1/login',expected=101,device=None,hostname=None):
        raw=socket.create_connection(('127.0.0.1',port),timeout=3,source_address=(source,0))
        self.socket=context.wrap_socket(raw,server_hostname='127.0.0.1');self.buffer=bytearray();self.name=name
        key=base64.b64encode(secrets.token_bytes(16)).decode()
        extra='&'+urlencode({'autonode':1,'deviceid':device,'hostname':hostname}) if device is not None else ''
        request=(f'GET {path}?node={name}&token={credential}&protocol=fastp2p2&version=2.0.0&nattype=1{extra} HTTP/1.1\r\n'
            f'Host: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n')
        self.socket.sendall(request.encode())
        while b'\r\n\r\n' not in self.buffer:
            part=self.socket.recv(4096)
            if not part: raise AssertionError('Upgrade closed without status')
            self.buffer.extend(part)
        header,left=self.buffer.split(b'\r\n\r\n',1);self.buffer=bytearray(left)
        status=int(header.split(b' ',2)[1]);assert status==expected,('upgrade status',status,expected)
        if expected!=101:self.socket.close();return
        accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        assert accept.lower() in header.lower()
        clients.append(self)
        login=json.loads(self.until(0,0));assert login['token']==token
        if device is None:assert login['node']==name
        self.name=login['node']
    def exact(self,n):
        while len(self.buffer)<n:
            data=self.socket.recv(max(4096,n-len(self.buffer)))
            if not data:raise EOFError()
            self.buffer.extend(data)
        data=bytes(self.buffer[:n]);del self.buffer[:n];return data
    def send(self,data,opcode=2,fin=True):
        n=len(data);head=bytes([(0x80 if fin else 0)|opcode])
        if n<126:head+=bytes([0x80|n])
        elif n<65536:head+=bytes([0xfe])+struct.pack('>H',n)
        else:head+=bytes([0xff])+struct.pack('>Q',n)
        mask=secrets.token_bytes(4)
        self.socket.sendall(head+mask+bytes(b^mask[i%4] for i,b in enumerate(data)))
    def receive(self):
        result=bytearray()
        while True:
            first,second=self.exact(2);n=second&127
            if n==126:n=struct.unpack('>H',self.exact(2))[0]
            if n==127:n=struct.unpack('>Q',self.exact(8))[0]
            assert not second&0x80 and n<=2*1024*1024
            data=self.exact(n);opcode=first&15
            if opcode==8:
                try:self.send(data,8)
                except OSError:pass
                raise EOFError()
            if opcode==9:self.send(data,10);continue
            if opcode==10:continue
            assert opcode in (0,2)
            result.extend(data)
            if first&0x80:return bytes(result)
    def until(self,main,sub):
        for _ in range(40):
            frame=self.receive();length,m,s=struct.unpack('<IHH',frame[:8])
            assert length==len(frame)-8
            if (m,s)==(main,sub):return frame[8:]
        raise AssertionError('Expected frame not received')
    def report(self):
        self.send(message(6,0,{'os':'test-c-peer','lanIP':'127.0.0.1','version':'2.0.0','hasIPv4':1,'publicIPPort':31000}))
        assert json.loads(self.until(6,7))=={}
    def query(self,peer,credential=token):
        self.send(message(7,0,{'peerNode':peer.name,'token':credential}))
        return json.loads(self.until(7,1))
    def push(self,peer,sub,body,from_id=None):
        payload=struct.pack('<QQ',crc(self.name) if from_id is None else from_id,crc(peer.name))+json.dumps(body).encode()
        self.send(message(3,sub,payload));return json.loads(self.until(3,0))
    def closed(self):
        try:
            for _ in range(40):self.receive()
        except (EOFError,ssl.SSLError,ConnectionError):return True
        return False
    def close(self):
        try:self.send(b'',8)
        except OSError:pass
        self.socket.close()

try:
    with tempfile.TemporaryDirectory(prefix='fastp2p-c-gateway-protocol-') as temp, (logs/'gateway.log').open('w') as output:
        directory=Path(temp)
        env=os.environ.copy();env.update(FASTP2P_USER=user,FASTP2P_PASSWORD=password,FASTP2P_TOKEN=str(token))
        process=subprocess.Popen([str(Path(args.gateway).resolve()),'--cert',str(certs/'server.crt'),'--key',str(certs/'server.key'),
            '--bind','127.0.0.1'],cwd=directory,env=env,stdout=output,stderr=subprocess.STDOUT)
        wait(lambda:api('/healthz')[0]==200)
        assert api('/api/v1/devices')[0]==401
        assert api('/api/v1/user/login',{'user':user,'password':'incorrect'})[0]==401
        assert api('/api/v1/user/login',{'user':user,'password':password+'\0suffix'})[0]==401
        empty=http.client.HTTPSConnection('127.0.0.1',10008,context=context,timeout=3)
        empty.request('POST','/api/v1/user/login',b'');response=empty.getresponse()
        assert response.status==400;response.read();empty.close()
        status,login=api('/api/v1/user/login',{'user':user,'password':password});assert status==200 and len(login['installToken'])==16
        jwt=login['token'];head,body,sig=jwt.split('.')
        assert api('/api/v1/status')[0]==401
        status,overview=api('/api/v1/status',jwt=jwt)
        assert status==200 and overview['version']=='2.0.0' and overview['capacity']==256
        assert overview['nodeStorage']=='sqlite' and overview['totalNodes']==0
        assert 'nodeToken' not in overview and password not in json.dumps(overview)
        for path,kind in [('/','text/html'),('/index.html','text/html'),('/app.js','text/javascript'),('/style.css','text/css'),('/favicon.svg','image/svg+xml')]:
            conn=http.client.HTTPSConnection('127.0.0.1',10008,context=context,timeout=3)
            conn.request('GET',path);response=conn.getresponse();asset=response.read()
            assert response.status==200 and kind in response.getheader('Content-Type') and asset
            assert "script-src 'self'" in response.getheader('Content-Security-Policy')
            assert response.getheader('X-Frame-Options')=='DENY' and response.getheader('Cache-Control')=='no-store'
            assert password.encode() not in asset
            conn.close()
        conn=http.client.HTTPSConnection('127.0.0.1',27183,context=context,timeout=3)
        conn.request('GET','/');response=conn.getresponse();assert response.status==404;response.read();conn.close()
        assert api('/server.key',jwt=jwt)[0]==404
        results['embedded_web_assets_security_headers_and_protected_status']=True
        with sqlite3.connect(directory/'nodes.sqlite3') as database: signing_secret=database.execute('SELECT jwt_secret FROM admin WHERE id=1').fetchone()[0]
        expected=hmac.new(signing_secret.encode(),(head+'.'+body).encode(),hashlib.sha256).digest()
        assert hmac.compare_digest(base64.urlsafe_b64encode(expected).decode().rstrip('='),sig)
        assert json.loads(base64.urlsafe_b64decode(body+'='*(-len(body)%4)))['installToken']==str(token)
        assert api('/api/v1/devices',jwt=jwt)[0]==200 and api('/api/v1/devices',jwt='Bearer '+jwt)[0]==200
        assert api('/api/v1/devices',jwt=jwt[:-4]+'AAAA')[0]==401
        limited=WS('web-c-capability')
        limited.send(message(6,0,{'os':'linux-c','version':'2.0.0'}));limited.until(6,7)
        nodes=api('/api/v1/devices',jwt=jwt)[1]['nodes']
        capability=next(n['capabilities'] for n in nodes if n['name']==limited.name)
        assert capability['addForward'] and not capability['editForward'] and not capability['switchForward']
        assert api('/api/v1/device/'+limited.name+'/switchapp',{'srcPort':23456,'enabled':0},jwt)[0]==501
        assert api('/api/v1/device/'+limited.name+'/app',{'srcPort0':23456,'protocol0':'tcp'},jwt)[0]==501
        limited.close()
        wait(lambda:limited.name not in [n['name'] for n in api('/api/v1/devices',jwt=jwt)[1]['nodes']])
        results['C_client_management_capabilities_enforced']=True
        def signed(claims,algorithm='HS256'):
            encode=lambda obj:base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')
            data=encode({'alg':algorithm})+'.'+encode(claims)
            sig=hmac.new(signing_secret.encode(),data.encode(),hashlib.sha256).digest()
            return data+'.'+base64.urlsafe_b64encode(sig).decode().rstrip('=')
        claims={'user':user,'installToken':str(token),'iss':'fastp2p.cn','exp':int(time.time())-1}
        assert api('/api/v1/devices',jwt=signed(claims))[0]==401
        claims['exp']=int(time.time())+100
        assert api('/api/v1/devices',jwt=signed(claims,'none'))[0]==401
        results['JWT_HS256_uint64_expiry_algorithm_and_tamper']=True
        try:
            untrusted=ssl.create_default_context()
            with untrusted.wrap_socket(socket.create_connection(('127.0.0.1',10008)),server_hostname='127.0.0.1'):
                raise AssertionError('Untrusted TLS accepted')
        except ssl.SSLCertVerificationError:pass
        results['private_CA_required']=True
        for port in range(27180,27184):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.settimeout(2);sock.bind(('127.0.0.1',0));local=sock.getsockname()[1]
                sock.sendto(message(2,0),('127.0.0.1',port));data,peer=sock.recvfrom(2048)
                assert peer[1]==port and json.loads(data[8:])['port']==local
                sock.sendto(message(2,1,{'echoPort':local}),('127.0.0.1',port));data,_=sock.recvfrom(2048)
                assert struct.unpack('<HH',data[4:8])==(2,1)
                sock.sendto(struct.pack('<IHH',100,2,0)+b'{}',('127.0.0.1',port))
                sock.settimeout(.08)
                try:sock.recvfrom(2048);raise AssertionError('Malformed NAT frame answered')
                except TimeoutError:pass
        for port in (27180,27181):
            with socket.create_connection(('127.0.0.1',port),timeout=2) as sock:
                local=sock.getsockname()[1];sock.sendall(b'1');assert sock.recv(128)==f'127.0.0.1:{local}'.encode()
        results['four_UDP_ports_echo_and_single_byte_TCP_probes']=True
        WS('member-node-a',0,expected=401)
        WS('short',expected=400)
        WS('member-node-a',port=10008,expected=404)
        results['WSS_authentication_and_listener_separation']=True
        a=WS('member-node-a',source='127.0.0.2');b=WS('member-node-b',source='127.0.0.3');r=WS('relay-node-c',source='127.0.0.4')
        for c in (a,b,r):c.report()
        assert a.push(b,2,{'from':a.name,'id':1})['error']==1
        assert a.query(b)['online']==1 and a.query(r)['online']==1
        assert a.push(b,2,{'from':a.name,'id':2})['error']==0
        assert struct.unpack('<QQ',b.until(3,2)[:16])==(crc(a.name),crc(b.name))
        assert a.push(r,2,{'from':a.name,'id':3})['error']==0;r.until(3,2)
        assert b.push(r,2,{'from':b.name,'id':4})['error']==1
        assert a.push(b,2,{'id':5},from_id=crc(r.name))['error']==1
        assert a.push(b,1,{'from':r.name,'token':token})['error']==1
        assert b.query(r)['online']==1
        results['query_grants_no_transitivity_and_spoof_rejection']=True
        # Receive fragmented WS input, emit fragmented output, and preserve a large uint64.
        payload=message(6,0,{'os':'test-c-peer','lanIP':'127.0.0.1','version':'2.0.0'})
        a.send(payload[:9],fin=False);a.send(payload[9:],opcode=0);a.until(6,7)
        large={'peer':'x','session':token,'secret':'00'*32,'padding':'x'*96000}
        assert a.push(b,13,large)['error']==0
        assert json.loads(b.until(3,13)[16:])==large
        a.send(message(1,0)+message(1,0))
        for _ in range(2):assert abs(struct.unpack('<Q',a.until(1,0))[0]-time.time_ns())<2_000_000_000
        results['WS_fragmentation_large_messages_uint64_and_coalesced_frames']=True
        a.send(message(5,0,{'peerNode':b.name}));relay=json.loads(a.until(5,1))
        assert relay['relay']==r.name and relay['error']==0
        r.send(message(5,0,{'peerNode':b.name}));assert json.loads(r.until(5,1))['relay']==a.name
        results['relay_offer_selects_a_third_node_and_never_an_endpoint']=True
        responses=[]
        thread=threading.Thread(target=lambda:responses.append(api('/api/v1/device/'+a.name+'/apps',jwt=jwt)));thread.start()
        a.until(3,7);a.send(message(6,3,{'Apps':[{'appName':'reply','srcPort':12345}]}));thread.join(4)
        assert responses==[(200,{'Apps':[{'appName':'reply','srcPort':12345}]})]
        assert api('/api/v1/device/'+a.name+'/app',{'appName':'new','srcPort':12345},jwt)[0]==200
        assert json.loads(a.until(3,9))['appName']=='new'
        assert api('/api/v1/device/'+a.name+'/switchapp',{'srcPort':12345,'enabled':0},jwt)[0]==200;a.until(3,10)
        assert api('/api/v1/device/'+a.name+'/restart',jwt=jwt)[0]==200;a.until(3,11)
        results['management_apps_async_edit_switch_restart']=True
        replacement=WS(a.name,source='127.0.0.2');assert a.closed();replacement.report()
        assert replacement.push(b,2,{'id':8})['error']==1
        names=lambda:[n['name'] for n in api('/api/v1/devices',jwt=jwt)[1]['nodes']]
        assert names().count(a.name)==1
        results['duplicate_login_replaces_session_and_revokes_grants']=True
        bad=WS('malformed-node');bad.send(struct.pack('<IHH',1048577,7,0));assert bad.closed()
        bad.close()
        wait(lambda:'malformed-node' not in names())
        time.sleep(.15)
        before=len(list(Path('/proc',str(process.pid),'fd').iterdir()))
        for i in range(80):
            client=WS('cycle-'+str(i).zfill(8));client.close()
        wait(lambda:len(names())==3)
        time.sleep(.15)
        after=len(list(Path('/proc',str(process.pid),'fd').iterdir()))
        assert after<=before,(before,after)
        results['malformed_frames_and_80_session_cycles_no_FD_growth']=True
        persistent=http.client.HTTPSConnection('127.0.0.1',10008,context=context,timeout=3)
        for _ in range(40):assert api('/healthz',connection=persistent)[0]==200
        persistent.close();results['HTTP_keepalive_transactions']=True
        # A waiting HTTP request never blocks the node's WebSocket callbacks.
        replies=[]
        thread=threading.Thread(target=lambda:replies.append(api('/api/v1/device/'+replacement.name+'/apps',jwt=jwt,timeout=15)))
        thread.start();replacement.until(3,7)
        assert api('/api/v1/device/'+replacement.name+'/apps',jwt=jwt)[0]==409
        thread.join(13);assert replies and replies[0][0]==504
        disconnected=[]
        thread=threading.Thread(target=lambda:disconnected.append(api('/api/v1/device/'+replacement.name+'/apps',jwt=jwt)))
        thread.start();replacement.until(3,7);replacement.close();thread.join(4)
        assert disconnected and disconnected[0][0]==503
        results['pending_HTTP_concurrency_timeout_and_peer_disconnect']=True
        conn=http.client.HTTPSConnection('127.0.0.1',10008,context=context,timeout=3)
        conn.request('PUT','/healthz');response=conn.getresponse();assert response.status==405;response.read();conn.close()
        conn=http.client.HTTPSConnection('127.0.0.1',10008,context=context,timeout=3)
        conn.request('POST','/api/v1/user/login',b'{}',{'Content-Length':'70000'})
        response=conn.getresponse();assert response.status==413;response.read();conn.close()
        results['HTTP_methods_and_oversized_body_rejected']=True
        WS('auto-fixture',credential=0,device='1'*32,hostname='fixture-host',expected=401)
        WS('auto-fixture',device='invalid',hostname='fixture-host',expected=400)
        auto_a=WS('auto-fixture',device='1'*32,hostname='fixture-host')
        auto_b=WS('auto-fixture',device='2'*32,hostname='fixture-host')
        assert auto_a.name=='fixture-host' and auto_b.name.startswith('fixture-host-') and auto_a.name!=auto_b.name
        WS(auto_a.name,expected=409)
        auto_name=auto_b.name;auto_b.close()
        wait(lambda:auto_name not in names())
        rows=api('/api/v1/nodes?search=fixture-host',jwt=jwt)[1]
        assert rows['total']==2 and any(n['name']==auto_name and not n['isActive'] for n in rows['nodes'])
        auto_b=WS('auto-fixture',device='2'*32,hostname='renamed-host');assert auto_b.name==auto_name
        results['automatic_identity_names_unique_reserved_and_stable']=True
        results['SQLite_offline_records_and_authenticated_search']=True
        process.terminate();process.wait(timeout=6);assert process.returncode==0
        process=subprocess.Popen([str(Path(args.gateway).resolve()),'--cert',str(certs/'server.crt'),'--key',str(certs/'server.key'),
            '--bind','127.0.0.1','--max-clients','2','--heartbeat-timeout','5'],cwd=directory,env=env,stdout=output,stderr=subprocess.STDOUT)
        wait(lambda:api('/healthz')[0]==200)
        rows=api('/api/v1/nodes?search=fixture-host',jwt=jwt)[1]
        assert rows['total']==2 and all(not n['isActive'] for n in rows['nodes'])
        results['SQLite_records_survive_gateway_restart_without_false_online_state']=True
        first=WS('capacity-node-a');second=WS('capacity-node-b');WS('capacity-node-c',expected=503)
        first.socket.settimeout(8);assert first.closed()
        second.socket.settimeout(8);assert second.closed()
        wait(lambda:not api('/api/v1/devices',jwt=jwt)[1]['nodes'])
        results['configured_capacity_and_idle_heartbeat_timeout']=True
        cap_a=WS('auto-fixture',device='a'*32,hostname='capacity-auto')
        cap_b=WS('auto-fixture',device='b'*32,hostname='capacity-auto')
        WS(cap_a.name,device='c'*32,hostname='capacity-auto',expected=503)
        cap_name=cap_b.name
        cap_replacement=WS('auto-fixture',device='b'*32,hostname='changed-host')
        assert cap_replacement.name==cap_name and cap_b.closed()
        assert len(api('/api/v1/devices',jwt=jwt)[1]['nodes'])==2
        results['automatic_reconnect_at_capacity_keeps_the_same_name']=True
        results['success']=True
finally:
    for c in clients:
        try:c.close()
        except OSError:pass
    if process:
        process.terminate()
        try:process.wait(timeout=6)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        diagnostic=(logs/'gateway.log').read_text(errors='replace')
        assert process.returncode==0 and 'Sanitizer' not in diagnostic and 'runtime error:' not in diagnostic,'Gateway shutdown or sanitizer failure'
    (logs/'result.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))
