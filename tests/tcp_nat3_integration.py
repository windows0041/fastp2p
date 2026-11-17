#!/usr/bin/env python3
"""Real clients behind two port-preserving, endpoint-filtered Linux NAT routers.

Requires root inside an already isolated network namespace. Nested namespaces
are owned by child processes, with no named-netns or host mount mutations.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from certificates import create_certificates

p=argparse.ArgumentParser()
p.add_argument('--client',required=True)
p.add_argument('--gateway',required=True)
p.add_argument('--logs',required=True)
p.add_argument('--legacy-client',help='Optional previous client binary, for capability negotiation coverage')
args=p.parse_args()
if os.geteuid() or Path('/proc/self/ns/net').readlink()==Path('/proc/1/ns/net').readlink():
    raise SystemExit('Run as root with unshare --net; never run in the host network namespace')
root=Path(args.logs).resolve();root.mkdir(parents=True,exist_ok=True);root.chmod(0o700)
client=str(Path(args.client).resolve());gateway=str(Path(args.gateway).resolve())
children=[];handles=[];anchors=[];results={};jwt=None
token='9999999999999999';password=secrets.token_urlsafe(24)
env=dict(os.environ,FASTP2P_TOKEN=token,FASTP2P_USER='nat3-admin',FASTP2P_PASSWORD=password,
         FASTP2P_DATABASE=str(root/'nodes.sqlite3'),FASTP2P_PUBLIC_HOST='192.0.2.1')
env.pop('FASTP2P_FORCE_RELAY',None);env.pop('FASTP2P_NAT_TYPE',None)

def run(command,pid=None,**kwargs):
    try:
        return subprocess.run((['nsenter','-t',str(pid),'-n','--'] if pid else [])+command,
                              check=True,capture_output=True,text=True,**kwargs)
    except subprocess.CalledProcessError as error:
        (root/'command-error.log').write_text(error.stderr or '')
        raise RuntimeError('Namespace command failed; inspect command-error.log') from None
def start(command,name,pid=None,extra=None):
    log=(root/(name+'.log')).open('w');handles.append(log)
    process=subprocess.Popen((['nsenter','-t',str(pid),'-n','--'] if pid else [])+command,
        env=dict(env,**(extra or {})),cwd=root,stdout=log,stderr=subprocess.STDOUT)
    children.append(process);return process
def wait(check,timeout=60):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            if check():return
        except (OSError,ValueError,KeyError,AssertionError):pass
        time.sleep(.05)
    raise TimeoutError('NAT3 condition timed out; inspect private test logs')
def namespace(name):
    child=start(['unshare','--net','--','sleep','600'],name);anchors.append(child)
    wait(lambda:Path(f'/proc/{child.pid}/ns/net').readlink()!=Path('/proc/self/ns/net').readlink(),3)
    run(['ip','link','set','lo','up'],child.pid);return child.pid
def interface(name,peer,pid,address,other_pid=None,other_address=None):
    run(['ip','link','add',name,'type','veth','peer','name',peer])
    run(['ip','link','set',peer,'netns',str(pid)])
    if other_pid:
        run(['ip','link','set',name,'netns',str(other_pid)])
        run(['ip','addr','add',other_address,'dev',name],other_pid)
        run(['ip','link','set',name,'up'],other_pid)
    else:
        run(['ip','link','set',name,'master','nat3wan']);run(['ip','link','set',name,'up'])
    run(['ip','addr','add',address,'dev',peer],pid);run(['ip','link','set',peer,'up'],pid)
def api(path,body=None,auth=True):
    connection=http.client.HTTPSConnection('127.0.0.1',31008,context=context,timeout=3)
    headers={'Content-Type':'application/json'}
    if jwt and auth:headers['Authorization']='Bearer '+jwt
    connection.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,headers)
    response=connection.getresponse();data=response.read();connection.close()
    assert response.status==200;return json.loads(data)
def text(name):return (root/(name+'.log')).read_text(errors='replace')
def stop(process):
    if process.poll() is None:
        process.terminate()
        try:process.wait(timeout=8)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)

def stun_server(address):
    listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind((address,3478));listener.listen();listener.settimeout(.2)
    def serve():
        while not finished.is_set():
            try:connection,peer=listener.accept()
            except socket.timeout:continue
            except OSError:return
            def reply(connection,peer):
                with connection:
                    try:
                        connection.settimeout(3);request=b''
                        while len(request)<20:
                            part=connection.recv(20-len(request))
                            if not part:return
                            request+=part
                        assert request[:8]==bytes.fromhex('000100002112a442')
                        ip=struct.unpack('!I',socket.inet_aton(peer[0]))[0]
                        body=struct.pack('!HHBBHI',0x0020,8,0,1,peer[1]^0x2112,ip^0x2112a442)
                        response=struct.pack('!HHI',0x0101,len(body),0x2112a442)+request[8:20]+body
                        for at in range(0,len(response),3):connection.sendall(response[at:at+3]);time.sleep(.002)
                        # Keep the tuple established until the client ends sampling.
                        while connection.recv(16):pass
                    except (OSError,AssertionError):pass
            threading.Thread(target=reply,args=(connection,peer),daemon=True).start()
    threading.Thread(target=serve,daemon=True).start();return listener

finished=threading.Event();stun_listeners=[]
try:
    create_certificates(root/'tls','192.0.2.1','127.0.0.1')
    env.update(FASTP2P_TLS_CERT=str(root/'tls/server.crt'),FASTP2P_TLS_KEY=str(root/'tls/server.key'),FASTP2P_CA_FILE=str(root/'tls/ca.crt'))
    context=ssl.create_default_context(cafile=str(root/'tls/ca.crt'))
    run(['ip','link','set','lo','up']);run(['ip','link','add','nat3wan','type','bridge'])
    for address in ('192.0.2.1/24','192.0.2.21/24','192.0.2.22/24'):run(['ip','addr','add',address,'dev','nat3wan'])
    run(['ip','link','set','nat3wan','up'])
    ra,rb,ca,cb=(namespace(name) for name in ('router-a','router-b','client-a-ns','client-b-ns'))
    for suffix,router,node,public,network in (('a',ra,ca,'192.0.2.11','10.101.0'),('b',rb,cb,'192.0.2.12','10.102.0')):
        interface('wan-'+suffix,'wan',router,public+'/24')
        interface('lan','eth0',node,network+'.2/24',router,network+'.1/24')
        run(['ip','route','add','default','via',network+'.1'],node)
        run(['ip','route','add','default','via','192.0.2.1'],router)
        run(['sysctl','-qw','net.ipv4.ip_forward=1'],router)
        run(['iptables','-P','FORWARD','DROP'],router)
        # A SYN arriving before the outbound tuple exists must be filtered,
        # rather than reaching the router's own TCP stack and eliciting RST.
        run(['iptables','-A','INPUT','-i','wan','-p','tcp','--syn','-j','DROP'],router)
        run(['iptables','-A','FORWARD','-p','udp','-m','comment','--comment','FP-UDP-DROP','-j','DROP'],router)
        run(['iptables','-A','FORWARD','-i','lan','-o','wan','-j','ACCEPT'],router)
        run(['iptables','-A','FORWARD','-i','wan','-o','lan','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT'],router)
        run(['iptables','-t','nat','-A','POSTROUTING','-o','wan','-j','SNAT','--to-source',public],router)
    # The WAN gateway never routes between the two private LANs.
    results['two_separate_nat_routers_with_endpoint_filtering']=True
    for address in ('192.0.2.21','192.0.2.22'):stun_listeners.append(stun_server(address))
    gateway_process=start([gateway,'--bind','0.0.0.0','--apibind','127.0.0.1','--apiport','31008'],'gateway')
    wait(lambda:api('/healthz',auth=False)['status']=='ok',15)
    jwt=api('/api/v1/user/login',{'user':'nat3-admin','password':password},False)['token']
    echo_code="""import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',38180));s.listen()
def echo(c):
 with c:
  while True:
   d=c.recv(65536)
   if not d:return
   c.sendall(d)
while True:
 c,_=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()
"""
    start([sys.executable,'-u','-c',echo_code],'echo',cb)
    payload=bytes((i*17+3)&255 for i in range(262144));expected=hashlib.sha256(payload).hexdigest()
    transfer="""import socket,hashlib
p=bytes((i*17+3)&255 for i in range(262144))
with socket.create_connection(('127.0.0.1',28100),timeout=10) as s:
 s.sendall(p);s.shutdown(socket.SHUT_WR);r=bytearray()
 while True:
  d=s.recv(65536)
  if not d:break
  r.extend(d)
assert len(r)==len(p),(len(r),len(p));print(hashlib.sha256(r).hexdigest())
"""
    cases=[('udp-blocked',None),('udp-hard-mapping','2')]
    if args.legacy_client:cases.append(('legacy-peer',None))
    for label,override in cases:
        names={'a':'nat3-source-'+label,'b':'nat3-target-'+label}
        processes=[]
        for side,pid in (('b',cb),('a',ca)):
            config={'product':'fastp2p','network':{'Node':names[side],'Token':token,'ServerHost':'192.0.2.1','ServerPort':27183,
                'TCPSTUNServers':['192.0.2.21:3478','192.0.2.22:3478']},'CACertFile':str(root/'tls/ca.crt'),'apps':[]}
            if side=='a':config['apps']=[{'AppName':'tcp-through-nat3','Protocol':'tcp','SrcPort':28100,'PeerNode':names['b'],
                'DstHost':'127.0.0.1','DstPort':38180,'UnderlayProtocol':'tcp','Enabled':1}]
            path=root/(label+'-'+side+'.json');path.write_text(json.dumps(config));path.chmod(0o600)
            executable=str(Path(args.legacy_client).resolve()) if label=='legacy-peer' and side=='b' else client
            processes.append(start([executable,'run','--config',str(path)],label+'-'+side,pid,
                {'FASTP2P_NAT_TYPE':override} if override else {}))
        wait(lambda:'forward attached to tunnel' in text(label+'-a'),70)
        observed=api('/api/v1/nodes')['nodes'];observed={n['name']:n for n in observed}
        for side,name in names.items():
            node=observed[name]
            if label=='legacy-peer' and side=='b':assert int(node['tcpNatType'])==314
            else:assert int(node['tcpNatType'])==1 and int(node['tcpNatSamples'])==4 and int(node['tcpNatDestinationIPs'])==3
            assert int(node['udpNatType'])==(2 if override else 314)
        command=transfer
        if label=='legacy-peer':
            command=command.replace('s.shutdown(socket.SHUT_WR);','').replace('while True:\n  d=s.recv','while len(r)<len(p):\n  d=s.recv')
        for _ in range(3):assert run([sys.executable,'-c',command],ca,timeout=20).stdout.strip()==expected
        connections=run(['ss','-tnH'],ca).stdout
        assert '192.0.2.12:' in connections, 'no direct TCP socket to the other NAT WAN address'
        for side in ('a','b'):
            diagnostic=text(label+'-'+side)
            if label!='legacy-peer':assert 'TCP punch connect attempt' in diagnostic
            assert 'forward attached to relay' not in diagnostic and 'tunnel authentication failed' not in diagnostic
        results[label]={'direct_tcp':True,'three_256k_roundtrips':True,'half_close':label!='legacy-peer','tcp_mapping_samples':4,'tcp_destination_ips':3,
                        'udp_nat_type':2 if override else 314}
        for process in processes:stop(process)
        wait(lambda:all(not int(n['isActive']) for n in api('/api/v1/nodes')['nodes'] if n['name'] in names.values()),10)
        persisted={n['name']:n for n in api('/api/v1/nodes')['nodes']}
        assert all(int(persisted[name]['tcpNatType'])==(314 if label=='legacy-peer' and side=='b' else 1) for side,name in names.items())
    for router in (ra,rb):
        counters=run(['iptables','-L','FORWARD','-vnx'],router).stdout
        rows=[line.split() for line in counters.splitlines() if 'FP-UDP-DROP' in line]
        assert rows and int(rows[0][0])>0
    results['udp_packets_really_blocked']=True;results['offline_mapping_results_persisted']=True;results['success']=True
finally:
    finished.set()
    for listener in stun_listeners:listener.close()
    for process in reversed(children):stop(process)
    for handle in handles:handle.close()
    for path in root.glob('*.log'):
        diagnostic=path.read_text(errors='replace')
        assert 'ERROR: AddressSanitizer' not in diagnostic and 'runtime error:' not in diagnostic
    (root/'result.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
