#!/usr/bin/env python3
"""Real SOCKS5 entry -> encrypted TCP/QUIC tunnel -> C exit; private local fixtures.

The gateway needs its normal NAT ports: use a disposable runner or net namespace.
No public service or existing deployment is contacted.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from certificates import create_certificates

p=argparse.ArgumentParser()
p.add_argument('--client',required=True)
p.add_argument('--gateway',required=True)
p.add_argument('--legacy-client')
p.add_argument('--logs',required=True)
p.add_argument('--quick',action='store_true')
args=p.parse_args()
logs=Path(args.logs).resolve();logs.mkdir(parents=True,exist_ok=True)
results={};children=[];files=[];servers=[]

class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(12)
        try:
            while True:
                data=self.request.recv(65536)
                if not data:return
                self.request.sendall(data)
        except OSError:pass

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request;sock.sendto(data,self.client_address)

def wait(action,timeout=60):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        assert all(c.poll() is None for c in children),'A child exited; inspect private logs'
        try:
            if action():return
        except (OSError,AssertionError):pass
        time.sleep(.15)
    raise TimeoutError('SOCKS5 integration condition timed out')

def exact(sock,n):
    result=bytearray()
    while len(result)<n:
        data=sock.recv(n-len(result))
        if not data:raise ConnectionError('SOCKS5 connection closed early')
        result.extend(data)
    return bytes(result)

def address(host,port,domain=False):
    if domain:
        text=host.encode('ascii');encoded=b'\x03'+bytes([len(text)])+text
    else:encoded=b'\x01'+socket.inet_aton(host)
    return encoded+struct.pack('!H',port)

def greeting(port,auth=False,fragment=False,password=b'secret'):
    sock=socket.create_connection(('127.0.0.1',port),timeout=3);sock.settimeout(8)
    request=b'\x05\x02\x00\x02'
    if fragment:
        for byte in request:sock.sendall(bytes([byte]));time.sleep(.002)
    else:sock.sendall(request)
    assert exact(sock,2)==(b'\x05\x02' if auth else b'\x05\x00')
    if auth:
        request=b'\x01\x05alice'+bytes([len(password)])+password
        for byte in request:sock.sendall(bytes([byte]))
        assert exact(sock,2)==b'\x01\x00'
    return sock

def connect(port,target,host='127.0.0.1',domain=False,auth=False):
    sock=greeting(port,auth,True)
    sock.sendall(b'\x05\x01\x00'+address(host,target,domain))
    reply=exact(sock,10)
    assert reply[:4]==b'\x05\x00\x00\x01',reply[:4]
    return sock

def tcp(port,target,domain=False,auth=False):
    with connect(port,target,'localhost' if domain else '127.0.0.1',domain,auth) as sock:
        data=secrets.token_bytes(262144);sock.sendall(data)
        assert exact(sock,len(data))==data
    return True

def associate(port,auth=False):
    control=greeting(port,auth)
    control.sendall(b'\x05\x03\x00'+address('0.0.0.0',0))
    reply=exact(control,10);assert reply[:4]==b'\x05\x00\x00\x01'
    relay=(socket.inet_ntoa(reply[4:8]),struct.unpack('!H',reply[8:])[0])
    assert relay[0]=='127.0.0.1' and relay[1]
    return control,relay

def udp_case(port,targets,auth=False):
    control,relay=associate(port,auth)
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(8)
            for target in targets:
                for length,domain in [(0,False),(1000,True),(4096,False)]:
                    data=secrets.token_bytes(length)
                    sock.sendto(b'\0\0\0'+address('localhost' if domain else '127.0.0.1',target,domain)+data,relay)
                    reply,source=sock.recvfrom(8192)
                    assert source==relay and reply[:4]==b'\0\0\0\x01'
                    assert socket.inet_ntoa(reply[4:8])=='127.0.0.1'
                    assert struct.unpack('!H',reply[8:10])[0]==target and reply[10:]==data
            sock.settimeout(.4)
            sock.sendto(b'\0\0\x01'+address('127.0.0.1',targets[0])+b'fragment',relay)
            try:sock.recvfrom(8192);raise AssertionError('UDP fragments accepted')
            except TimeoutError:pass
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as other:
                other.settimeout(.4);other.sendto(b'\0\0\0'+address('127.0.0.1',targets[0])+b'wrong-source',relay)
                try:other.recvfrom(8192);raise AssertionError('Unpinned UDP source accepted')
                except TimeoutError:pass
            control.close();time.sleep(.15)
            sock.sendto(b'\0\0\0'+address('127.0.0.1',targets[0])+b'closed',relay)
            try:sock.recvfrom(8192);raise AssertionError('Closed association remained usable')
            except (TimeoutError,ConnectionResetError):pass
    finally:control.close()
    return True

def rejected(port,target):
    with greeting(port) as sock:
        sock.sendall(b'\x05\x01\0'+address('127.0.0.1',target))
        assert exact(sock,10)[1]==5
    return True

with tempfile.TemporaryDirectory(prefix='op2p-socks-') as temporary:
    root=Path(temporary)
    try:
        create_certificates(root/'certs','127.0.0.1')
        env=os.environ.copy();env.update(OPENP2P_USER='socks-test',OPENP2P_PASSWORD=secrets.token_urlsafe(24),OPENP2P_TOKEN=str(secrets.randbits(63)|(1<<63)|1))
        def start(command,name):
            directory=root/name;directory.mkdir(exist_ok=True)
            f=(logs/(name+'.log')).open('w');files.append(f)
            child=subprocess.Popen([str(x) for x in command],cwd=directory,env=env,stdout=f,stderr=subprocess.STDOUT)
            children.append(child);return child
        gateway_command=[Path(args.gateway).resolve(),'-bind','127.0.0.1','-apibind','127.0.0.1','-cert',root/'certs/server.crt','-key',root/'certs/server.key']
        gateway=start(gateway_command,'gateway')
        def listening():
            with socket.create_connection(('127.0.0.1',27183),timeout=1):return True
        wait(listening)
        targets={'tcp':[],'udp':[]}
        for proto,cls,handler in [('tcp',socketserver.ThreadingTCPServer,TCP),('udp',socketserver.ThreadingUDPServer,UDP)]:
            for _ in range(2):
                server=cls(('127.0.0.1',0),handler);server.daemon_threads=True;servers.append(server)
                targets[proto].append(server.server_address[1]);threading.Thread(target=server.serve_forever,daemon=True).start()
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));refused_port=sock.getsockname()[1]
        def client(name,proxies=None):
            directory=root/name;directory.mkdir()
            config={'network':{'Node':name,'ServerHost':'127.0.0.1'},'CACertFile':str(root/'certs/ca.crt'),'socks5':proxies or []}
            path=directory/'config.json';path.write_text(json.dumps(config))
            return start([Path(args.client).resolve(),'--config',path],name)
        client('socks-exit-node')
        proxies=[];ports={}
        for transport in ['tcp','quic']:
            for auth in [False,True]:
                with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
                ports[transport,auth]=port
                proxies.append({'Name':transport+str(auth),'SrcPort':port,'PeerNode':'socks-exit-node','UnderlayProtocol':transport,
                    'Username':'alice' if auth else '', 'Password':'secret' if auth else ''})
        entry=client('socks-entry-node',proxies)
        for transport in ['tcp','quic']:
            for auth in [False,True]:
                port=ports[transport,auth]
                wait(lambda:tcp(port,targets['tcp'][0],True,auth))
                assert tcp(port,targets['tcp'][1],False,auth)
                assert udp_case(port,targets['udp'],auth)
                results[transport+('_auth' if auth else '_noauth')+'_TCP_UDP']=True
                print(transport+' auth='+str(auth)+' TCP/UDP passed',flush=True)
        port=ports['tcp',False]
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            actions=[lambda i=i:tcp(port,targets['tcp'][i%2],bool(i%2)) for i in range(10)]+[lambda:rejected(port,refused_port)]*2
            assert all(pool.map(lambda action:action(),actions))
        results['concurrent_destinations_and_correlated_errors']=True
        with socket.create_connection(('127.0.0.1',port),timeout=3) as sock:
            sock.settimeout(8);data=secrets.token_bytes(16000)
            sock.sendall(b'\x05\x01\0'+b'\x05\x01\0'+address('localhost',targets['tcp'][0],True)+data)
            assert exact(sock,2)==b'\x05\0' and exact(sock,10)[1]==0 and exact(sock,len(data))==data
        results['coalesced_handshake_and_early_payload']=True
        with socket.create_connection(('127.0.0.1',ports['tcp',True]),timeout=3) as sock:
            sock.settimeout(3);sock.sendall(b'\x05\x01\0');assert exact(sock,2)==b'\x05\xff' and sock.recv(1)==b''
        with socket.create_connection(('127.0.0.1',ports['tcp',True]),timeout=3) as sock:
            sock.settimeout(3);sock.sendall(b'\x05\x01\x02');assert exact(sock,2)==b'\x05\x02'
            sock.sendall(b'\x01\x05alice\x05wrong');assert exact(sock,2)==b'\x01\x01' and sock.recv(1)==b''
        for request,code in [(b'\x05\x02\0'+address('127.0.0.1',80),7),(b'\x05\x01\0\x04'+b'\0'*18,8),(b'\x05\x01\x01'+address('127.0.0.1',80),1)]:
            with greeting(port) as sock:sock.sendall(request);assert exact(sock,10)[1]==code and sock.recv(1)==b''
        results['authentication_and_unsupported_requests_rejected']=True
        # Both incomplete greetings and authenticated request abandonment release sockets.
        time.sleep(.2)
        fd_path=Path('/proc')/str(entry.pid)/'fd'
        before=len(list(fd_path.iterdir())) if fd_path.exists() else None
        for _ in range(80):
            with greeting(port) as sock:pass
        time.sleep(.2)
        if before is not None:assert len(list(fd_path.iterdir()))<=before
        results['80_abandoned_handshakes_released']=True
        if args.legacy_client:
            start([Path(args.legacy_client).resolve(),'-node','socks-legacy-exit','-serverhost','127.0.0.1','-cacert',root/'certs/ca.crt','-sharebandwidth','0','-nv'],'legacy')
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));legacy_port=sock.getsockname()[1]
            client('socks-legacy-entry',[{'SrcPort':legacy_port,'PeerNode':'socks-legacy-exit','UnderlayProtocol':'tcp'}])
            def legacy_rejected():
                with greeting(legacy_port) as sock:
                    sock.sendall(b'\x05\x01\0'+address('127.0.0.1',targets['tcp'][0]));return exact(sock,10)[1]==7
            wait(legacy_rejected);results['legacy_exit_rejected_without_false_success']=True
        log=(logs/'socks-entry-node.log').read_text(errors='replace')
        assert 'TCP tunnel connected' in log and 'QUIC tunnel connected' in log
        results['both_transports_confirmed']=True
        if not args.quick:
            gateway.terminate();gateway.wait(timeout=8);children.remove(gateway)
            if os.name!='nt':assert gateway.returncode==0
            gateway=start(gateway_command,'gateway-restarted')
            for transport in ['tcp','quic']:
                wait(lambda t=transport:tcp(ports[t,True],targets['tcp'][0],True,True))
                assert udp_case(ports[transport,False],targets['udp'])
            results['gateway_restart_new_sessions_recover']=True
            time.sleep(35)
            for transport in ['tcp','quic']:
                assert tcp(ports[transport,False],targets['tcp'][1])
                assert udp_case(ports[transport,True],targets['udp'],True)
            results['heartbeat_35s_after_recovery']=True
        results['success']=True
    finally:
        for child in reversed(children):
            if child.poll() is None:child.terminate()
        for child in children:
            try:child.wait(timeout=8)
            except subprocess.TimeoutExpired:child.kill();child.wait()
        for server in servers:server.shutdown();server.server_close()
        for f in files:f.close()
        for log in logs.glob('socks-*.log'):
            text=log.read_text(errors='replace')
            assert 'AddressSanitizer' not in text and 'runtime error:' not in text,'Sanitizer failure'
        (logs/'result.json').write_text(json.dumps(results,indent=2)+'\n')
        print(json.dumps(results,indent=2))
