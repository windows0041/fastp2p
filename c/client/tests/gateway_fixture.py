#!/usr/bin/env python3
"""Portable test-only TLS coordinator for native Windows/macOS client checks.

The product gateway is C/Linux and receives the complete Linux integration
suite. This small fixture supplies signaling to real native C clients, without
a second implementation of the client or any production deployment role.
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import ssl
import struct
import threading
import time
from urllib.parse import parse_qs,urlsplit

p=argparse.ArgumentParser()
for name in ['cert','key','bind','apibind','enrollment-ca','database']:
    p.add_argument('--'+name,'-'+name,default='127.0.0.1' if name in ['bind','apibind'] else None)
p.add_argument('--port',type=int,default=27183);p.add_argument('--apiport',type=int,default=10008)
args=p.parse_args();key=int(os.environ['FASTP2P_TOKEN']);user=os.environ['FASTP2P_USER'];password=os.environ['FASTP2P_PASSWORD']
nodes={};lock=threading.RLock();stopped=threading.Event();jwt=secrets.token_urlsafe(32)
def crc(text):
    value=2**64-1
    for byte in text.encode():
        value^=byte
        for _ in range(8):value=(value>>1)^(0xd800000000000000 if value&1 else 0)
    return value^(2**64-1)
def packet(main,sub,body):
    if not isinstance(body,bytes):body=json.dumps(body,separators=(',',':'),ensure_ascii=True).encode()
    return struct.pack('<IHH',len(body),main,sub)+body
def install_token():
    ca=Path(args.enrollment_ca or str(Path(args.cert).with_name('ca.crt'))).read_text()
    payload={'v':1,'host':'127.0.0.1','port':args.port,'key':str(key),'ca':ca}
    return 'FP1.'+base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=').decode()
class ThreadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address=True;daemon_threads=True
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        if len(data)<8:return
        length,main,sub=struct.unpack('<IHH',data[:8])
        if main!=2 or length!=len(data)-8:return
        peer=self.client_address
        if sub==1:
            try:peer=(peer[0],int(json.loads(data[8:])['echoPort']))
            except (ValueError,KeyError,TypeError):return
        sock.sendto(packet(2,sub,{'IP':peer[0],'port':peer[1],'isPublicIP':0}),peer)
class Probe(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        try:
            while self.request.recv(1024):self.request.sendall((self.client_address[0]+':'+str(self.client_address[1])).encode())
        except OSError:pass
class HTTP(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def reply(self,body,status=200):
        data=json.dumps(body,separators=(',',':')).encode();self.send_response(status)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.send_header('Connection','close');self.end_headers();self.wfile.write(data)
    def do_POST(self):
        try:body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        except (ValueError,TypeError):self.reply({},400);return
        if self.path=='/api/v1/user/login' and body=={'user':user,'password':password}:
            self.reply({'token':jwt,'installToken':install_token(),'error':0})
        else:self.reply({},401)
    def do_GET(self):
        path=urlsplit(self.path);query=parse_qs(path.query)
        if self.headers.get('Upgrade','').lower()=='websocket':
            name=query.get('node',[''])[0]
            if path.path!='/api/v1/login' or query.get('protocol')!=['fastp2p1'] or query.get('token')!=[str(key)] or not 8<=len(name)<=31:
                self.reply({},401);return
            self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade')
            self.send_header('Sec-WebSocket-Accept',base64.b64encode(hashlib.sha1((self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode());self.end_headers()
            self.node=name;self.send_lock=threading.Lock();self.metadata={};self.close_connection=True
            with lock:nodes[name]=self
            try:
                self.send(packet(0,0,{'error':0,'token':key,'node':name,'protocol':'fastp2p1','user':user,'ts':int(time.time())}))
                while True:
                    first,second=self.exact(2);length=second&127
                    if length==126:length=struct.unpack('!H',self.exact(2))[0]
                    if length==127:length=struct.unpack('!Q',self.exact(8))[0]
                    if length>1048584:return
                    mask=self.exact(4) if second&128 else b'';payload=self.exact(length)
                    if mask:payload=bytes(byte^mask[i%4] for i,byte in enumerate(payload))
                    opcode=first&15
                    if opcode==8:return
                    if opcode==9:self.send(payload,10);continue
                    if opcode!=2:continue
                    offset=0
                    while offset+8<=len(payload):
                        size,main,sub=struct.unpack_from('<IHH',payload,offset);offset+=8
                        if size>len(payload)-offset:return
                        self.dispatch(main,sub,payload[offset:offset+size]);offset+=size
            except (OSError,EOFError,ValueError,KeyError,TypeError):pass
            finally:
                with lock:
                    if nodes.get(name) is self:nodes.pop(name,None)
            return
        if path.path=='/healthz':self.reply({'status':'ok','implementation':'fixture'});return
        if self.headers.get('Authorization','').removeprefix('Bearer ')!=jwt:self.reply({},401);return
        if path.path in ['/api/v1/devices','/api/v1/nodes']:
            with lock:result=[{'name':n,'isActive':1,'lanip':client.metadata.get('lanIP',''),'os':client.metadata.get('os',''),'version':'1.0.0'} for n,client in nodes.items()]
            self.reply({'nodes':result,'total':len(result)})
        else:self.reply({},404)
    def exact(self,length):
        data=self.rfile.read(length)
        if len(data)!=length:raise EOFError()
        return data
    def send(self,payload,opcode=2):
        length=len(payload);header=bytes([128|opcode,length]) if length<126 else bytes([128|opcode,126])+struct.pack('!H',length) if length<65536 else bytes([128|opcode,127])+struct.pack('!Q',length)
        with self.send_lock:self.connection.sendall(header+payload)
    def dispatch(self,main,sub,data):
        if main==1:self.send(packet(1,0,struct.pack('<Q',time.time_ns())));return
        if main==3:
            if len(data)<16:return
            sender,target=struct.unpack('<QQ',data[:16])
            if sender!=crc(self.node):return
            with lock:peer=next((value for name,value in nodes.items() if crc(name)==target),None)
            if peer:
                try:peer.send(packet(main,sub,data))
                except OSError:pass
            self.send(packet(3,0,{'error':0 if peer else 1}));return
        body=json.loads(data)
        if main==6 and sub==0:self.metadata=body;self.send(packet(6,7,{}))
        elif main==7 and sub==0:
            with lock:peer=nodes.get(body.get('peerNode'))
            if not peer:self.send(packet(7,1,{'online':0}));return
            meta=peer.metadata
            self.send(packet(7,1,{'online':1,'peerNode':peer.node,'version':'1.0.0','IPv4':peer.client_address[0],
                'lanIP':meta.get('lanIP','127.0.0.1'),'natType':1,'hasIPv4':meta.get('hasIPv4',0),'hasUPNPorNATPMP':0}))
        elif main==8:self.send(packet(8,1,{'tunnelNum':2,'mtu':1420}))
        elif main==5:self.send(packet(5,1,{'mode':'private','relayName':'','relayToken':0}))
servers=[]
try:
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(args.cert,args.key)
    for port,host in [(args.port,args.bind),(args.apiport,args.apibind)]:
        server=ThreadServer((host,port),HTTP);server.socket=context.wrap_socket(server.socket,server_side=True);servers.append(server)
    for port in [27180,27181]:servers.append(ThreadServer((args.bind,port),Probe))
    for port in range(27180,27184):servers.append(UDPServer((args.bind,port),UDP))
    for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
    signal.signal(signal.SIGTERM,lambda *_:stopped.set());signal.signal(signal.SIGINT,lambda *_:stopped.set())
    stopped.wait()
finally:
    for server in servers:server.shutdown();server.server_close()
