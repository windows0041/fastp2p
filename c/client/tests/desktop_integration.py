#!/usr/bin/env python3
"""Native desktop smoke test using the real Go gateway and Go/C destinations.

Use on a disposable CI runner: the gateway uses its standard local ports.
QUIC is forced by the C initiator; quic_interop.py separately covers both TLS roles.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from certificates import create_certificates

parser = argparse.ArgumentParser()
parser.add_argument('--build', required=True)
args = parser.parse_args()
build = Path(args.build).resolve()
suffix = '.exe' if os.name == 'nt' else ''
processes, files, servers, results = [], [], [], {}

def wait(action, timeout=60):
    deadline = time.monotonic()+timeout
    while time.monotonic()<deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError('A child exited before validation completed')
        try:
            if action(): return
        except (OSError, ValueError) as error:
            results['last_wait_error']=str(error)[:300]
        time.sleep(.2)
    raise TimeoutError('Native gateway integration timed out')

class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                data=self.request.recv(65536)
                if not data: return
                self.request.sendall(data)
        except OSError: pass

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock=self.request
        sock.sendto(data,self.client_address)

def roundtrip(proto, port):
    data=secrets.token_bytes(262144 if proto=='tcp' else 1000)
    if proto=='udp':
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(3);s.sendto(data,('127.0.0.1',port))
            return s.recvfrom(2048)[0]==data
    with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
        s.settimeout(8);s.sendall(data);received=bytearray()
        while len(received)<len(data):
            chunk=s.recv(65536)
            if not chunk:return False
            received.extend(chunk)
        return bytes(received)==data

runtime=tempfile.TemporaryDirectory(prefix='op2p-desktop-')
try:
    root=Path(runtime.name)
    gateway_host='127.0.0.1'
    if sys.platform=='darwin':
        # The Go reference binds P2P sockets to its primary interface. macOS
        # refuses some connections from that interface to a loopback address.
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
            probe.connect(('192.0.2.1',9));gateway_host=probe.getsockname()[0]
    results['phase']='gateway WSS readiness'
    create_certificates(root/'certs',gateway_host)
    token=str(secrets.randbits(63)|(1<<63)|1)
    environment=os.environ.copy()
    environment.update(OPENP2P_USER='desktop-test',OPENP2P_PASSWORD=secrets.token_urlsafe(24),OPENP2P_TOKEN=token)
    environment['NO_PROXY']=environment.get('NO_PROXY','')+','+gateway_host+',127.0.0.1,localhost'
    environment['no_proxy']=environment['NO_PROXY']
    def start(command,name,directory):
        f=(root/(name+'.log')).open('w');files.append(f)
        p=subprocess.Popen([str(x) for x in command],cwd=directory,env=environment,stdout=f,stderr=subprocess.STDOUT)
        processes.append(p);return p
    gateway=start([build/('gateway'+suffix),'-bind',gateway_host,'-apibind',gateway_host,
        '-cert',root/'certs/server.crt','-key',root/'certs/server.key'],'gateway',root)
    def listening():
        with socket.create_connection((gateway_host,27183),timeout=2):return True
    wait(listening)
    # Check readiness through the product protocol itself: strict private-CA
    # WSS authentication, using the same native client as all subsequent cases.
    probe=start([build/('openp2p-c'+suffix),'--node','desktop-c-probe','--serverhost',gateway_host,
        '--cacert',root/'certs/ca.crt','--run-seconds','5'],'desktop-c-probe',root)
    probe.wait(timeout=15)
    assert probe.returncode==0,'Native WSS authentication probe failed'
    processes.remove(probe)
    results['native_WSS_authentication']=True
    ports={}
    for proto,cls,handler in [('tcp',socketserver.ThreadingTCPServer,TCP),('udp',socketserver.ThreadingUDPServer,UDP)]:
        s=cls(('127.0.0.1',0),handler);s.daemon_threads=True;servers.append(s)
        threading.Thread(target=s.serve_forever,daemon=True).start();ports[proto]=s.server_address[1]
    def client(name,go=False,apps=None):
        d=root/name;d.mkdir()
        config={'network':{'Node':name,'Token':0,'ServerHost':gateway_host,'ServerPort':27183,'ShareBandwidth':0},
            'CACertFile':str(root/'certs/ca.crt'),'apps':apps or [],'LogLevel':0}
        (d/'config.json').write_text(json.dumps(config))
        if go:
            return start([build/('go-client'+suffix),'-node',name,'-serverhost',gateway_host,
                '-cacert',root/'certs/ca.crt','-sharebandwidth','0','-nv'],name,d)
        return start([build/('openp2p-c'+suffix),'--config',d/'config.json','--run-seconds','100'],name,d)
    client('desktop-go-target',True)
    client('desktop-c-target')
    cases=[];apps=[]
    for peer in ('desktop-go-target','desktop-c-target'):
        for transport in ('tcp','quic'):
            for proto in ('tcp','udp'):
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM) as s:
                    s.bind(('127.0.0.1',0));port=s.getsockname()[1]
                label=peer+'-'+transport+'-'+proto
                apps.append({'AppName':label,'PeerNode':peer,'SrcPort':port,'DstHost':'127.0.0.1',
                    'DstPort':ports[proto],'Protocol':proto,'UnderlayProtocol':transport})
                cases.append((label,proto,port))
    client('desktop-c-source',apps=apps)
    for label,proto,port in cases:
        results['phase']=label
        wait(lambda pr=proto,p=port:roundtrip(pr,p))
        results[label]=True;print(label+' passed',flush=True)
    log=(root/'desktop-c-source.log').read_text()
    assert 'TCP tunnel connected' in log and 'QUIC tunnel connected' in log
    results['both_transports_confirmed']=True
    results.pop('last_wait_error',None)
    results['phase']='complete'
    results['success']=True
finally:
    for p in reversed(processes):
        if p.poll() is None:p.terminate()
    for p in processes:
        try:p.wait(timeout=6)
        except subprocess.TimeoutExpired:p.kill();p.wait()
    for s in servers:s.shutdown();s.server_close()
    for f in files:f.close()
    if not results.get('success'):
        gateway_log=Path(runtime.name)/'gateway.log'
        if gateway_log.exists() and results.get('phase')=='gateway WSS readiness':
            results['gateway-startup']=gateway_log.read_text(errors='replace').splitlines()[-8:]
        for name in ['desktop-c-probe','desktop-c-source','desktop-c-target']:
            p=Path(runtime.name)/(name+'.log')
            if p.exists():results[name+'-events']=p.read_text(errors='replace').splitlines()[-50:]
    runtime.cleanup()
    (build/'desktop-result.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))
