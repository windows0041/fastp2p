#!/usr/bin/env python3
"""Browser test against the compiled gateway and disposable WSS node fixtures.

Windows may launch the Linux gateway in WSL with --wsl. Browser certificate
exceptions apply only to this isolated fixture context, never to the product.
"""
import argparse
import base64
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
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'client/tests'))
from certificates import create_certificates
from playwright.sync_api import sync_playwright, expect

def frame(main, sub, obj):
    body=json.dumps(obj,separators=(',',':')).encode()
    return struct.pack('<IHH',len(body),main,sub)+body

class Peer:
    def __init__(self,name,system,token,ca):
        self.name=name;self.apps=[];self.commands=[];self.lock=threading.Lock();self.stop=threading.Event();self.error=None
        self.sock=ssl.create_default_context(cafile=str(ca)).wrap_socket(socket.create_connection(('127.0.0.1',37183),timeout=3),server_hostname='127.0.0.1')
        key=base64.b64encode(secrets.token_bytes(16)).decode()
        request=(f'GET /api/v1/login?node={name}&token={token}&version=3.25.11&nattype=1 HTTP/1.1\r\nHost: 127.0.0.1:37183\r\n'
            f'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n')
        self.sock.sendall(request.encode());self.buffer=bytearray()
        while b'\r\n\r\n' not in self.buffer:self.buffer.extend(self.sock.recv(4096))
        head,self.buffer=self.buffer.split(b'\r\n\r\n',1);assert b' 101 ' in head
        self.buffer=bytearray(self.buffer)
        self.sock.settimeout(None)
        self.send(frame(6,0,{'os':system,'version':'3.25.11','lanIP':'192.0.2.8','hasIPv4':1}))
        self.reader=threading.Thread(target=self.read_loop,daemon=True);self.reader.start()
        self.heartbeat=threading.Thread(target=self.heartbeat_loop,daemon=True);self.heartbeat.start()
    def exact(self,n):
        while len(self.buffer)<n:
            part=self.sock.recv(4096)
            if not part:raise EOFError()
            self.buffer.extend(part)
        data=bytes(self.buffer[:n]);del self.buffer[:n];return data
    def send(self,data,opcode=2):
        mask=secrets.token_bytes(4);n=len(data)
        header=bytes([0x80|opcode,0x80|n]) if n<126 else bytes([0x80|opcode,0xfe])+struct.pack('!H',n)
        with self.lock:self.sock.sendall(header+mask+bytes(c^mask[i%4] for i,c in enumerate(data)))
    def heartbeat_loop(self):
        while not self.stop.wait(3):
            try:self.send(frame(1,0,None))
            except OSError:return
    def read_loop(self):
        try:
            while not self.stop.is_set():
                first,second=self.exact(2);n=second&127
                if n==126:n=struct.unpack('!H',self.exact(2))[0]
                if n==127:n=struct.unpack('!Q',self.exact(8))[0]
                payload=self.exact(n);opcode=first&15
                if opcode==8:return
                if opcode==9:self.send(payload,10);continue
                if opcode not in (0,2):continue
                length,main,sub=struct.unpack('<IHH',payload[:8]);assert length==len(payload)-8
                if main!=3:continue
                if sub not in (7,9,10):continue
                body=json.loads(payload[8:]);self.commands.append((sub,body))
                if sub==7:self.send(frame(6,3,{'Apps':self.apps}))
                elif sub==9:
                    if body.get('srcPort0'):
                        self.apps=[a for a in self.apps if (a['srcPort'],a['protocol'])!=(body['srcPort0'],body['protocol0'])]
                    if body.get('srcPort'):
                        self.apps.append({**body,'enabled':1,'isActive':1,'linkMode':'ipv4' if body.get('punchPriority')==3 else 'udppunch'})
                elif sub==10:
                    for app in self.apps:
                        if (app['srcPort'],app['protocol'])==(body['srcPort'],body['protocol']):app.update(enabled=body['enabled'],isActive=body['enabled'])
        except (OSError,EOFError):pass
        except Exception as error:self.error=type(error).__name__
    def close(self):
        self.stop.set()
        try:self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.sock.close();self.reader.join(timeout=2);self.heartbeat.join(timeout=2)

def main():
    p=argparse.ArgumentParser();p.add_argument('--gateway',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--wsl',action='store_true');p.add_argument('--browser-executable')
    p.add_argument('--client',help='Optional real C client; exercises legacy JSON compatibility')
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    peers=[];process=None;client=None;client_log=None;results={}
    with tempfile.TemporaryDirectory(prefix='op2p-web-') as directory:
        root=Path(directory)
        assert root.resolve().parent == Path(tempfile.gettempdir()).resolve() and root.name.startswith('op2p-web-')
        create_certificates(root/'certs','127.0.0.1')
        username='web-admin';password=secrets.token_urlsafe(24);token=str(2**64-1)
        env=os.environ.copy();env.update(OPENP2P_USER=username,OPENP2P_PASSWORD=password,OPENP2P_TOKEN=token)
        if args.wsl:
            remote=subprocess.check_output(['wsl.exe','-d','Debian','-u','maoyu','--','wslpath','-a',root.as_posix()],text=True).strip()
            (root/'launch.sh').write_text('#!/bin/bash\nset -e\necho $$ > "$1/gateway.pid"\nshift\nexec "$@"\n',newline='\n')
            env['WSLENV']=env.get('WSLENV','')+':OPENP2P_USER:OPENP2P_PASSWORD:OPENP2P_TOKEN'
            command=['wsl.exe','-d','Debian','-u','maoyu','--','bash',remote+'/launch.sh',remote,args.gateway,
                     '--cert',remote+'/certs/server.crt','--key',remote+'/certs/server.key']
        else:command=[str(Path(args.gateway).resolve()),'--cert',str(root/'certs/server.crt'),'--key',str(root/'certs/server.key')]
        command+=['--bind','127.0.0.1','--apibind','127.0.0.1','--port','37183','--apiport','31008','--run-seconds','600']
        log=(root/'gateway.log').open('w')
        try:
            process=subprocess.Popen(command,env=env,stdout=log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+20
            while True:
                assert process.poll() is None,'Gateway exited before readiness; private fixture log available during test'
                try:
                    with socket.create_connection(('127.0.0.1',31008),timeout=1):break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.1)
            if args.client:
                client_log=(root/'client.log').open('w')
                if args.wsl:
                    (root/'launch-client.sh').write_text('#!/bin/bash\nset -e\necho $$ > "$1/client.pid"\nshift\nexec "$@"\n',newline='\n')
                    client_command=['wsl.exe','-d','Debian','-u','maoyu','--','bash',remote+'/launch-client.sh',remote,args.client,
                        '--cacert',remote+'/certs/ca.crt']
                else:client_command=[str(Path(args.client).resolve()),'--cacert',str(root/'certs/ca.crt')]
                client_command+=['--node','web-c-node','--serverhost','127.0.0.1','--port','37183','--run-seconds','600']
                client=subprocess.Popen(client_command,env=env,stdout=client_log,stderr=subprocess.STDOUT)
                c=SimpleNamespace(name='web-c-node')
            else:
                c=Peer('web-c-node','linux-c',token,root/'certs/ca.crt');peers.append(c)
            go=Peer('web-go-node','<img src=x onerror=globalThis.__xss=1>',token,root/'certs/ca.crt');peers.append(go)
            go.apps=[{'appName':'<img src=x onerror=globalThis.__xss=1>','protocol':'tcp','srcPort':23456,'dstHost':'127.0.0.1','dstPort':22,'peerNode':c.name,'enabled':1,'isActive':1,'linkMode':'udppunch'}]
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,**({'executable_path':args.browser_executable} if args.browser_executable else {}))
                context=browser.new_context(ignore_https_errors=True,viewport={'width':1440,'height':1040})
                page=context.new_page();errors=[];mutations=[];page.on('pageerror',lambda error:errors.append(str(error)))
                page.on('response',lambda response:mutations.append(response) if response.url.endswith('/app') else None)
                response=page.goto('https://127.0.0.1:31008/');assert response.status==200
                assert "script-src 'self'" in response.headers['content-security-policy']
                expect(page.get_by_role('heading',name='欢迎回来')).to_be_visible()
                page.locator('#username').fill(username);page.locator('#password').fill('invalid')
                page.locator('#login-submit').click();expect(page.locator('#login-error')).to_contain_text('不正确')
                def login():
                    page.locator('#username').fill(username);page.locator('#password').fill(password);page.locator('#login-submit').click()
                    expect(page.locator('#online-count')).to_have_text('2',timeout=15000)
                login();results['login_and_authenticated_overview']=True
                page.locator('#token-button').click();expect(page.locator('#install-token')).to_have_value(token)
                assert page.locator('#install-token').get_attribute('type')=='password'
                page.locator('#reveal-token').click();assert page.locator('#install-token').get_attribute('type')=='text'
                page.locator('#close-token').click();expect(page.locator('#install-token')).to_have_value('')
                results['uint64_token_mask_and_clear']=True
                page.locator('#node-search').fill('no-match');expect(page.locator('#nodes-empty')).to_be_visible()
                page.locator('#node-search').fill('web-c-node');expect(page.locator('#nodes tr')).to_have_count(1)
                page.locator('#nodes').get_by_role('button').click();expect(page.locator('#rule-message')).to_contain_text('此 C 客户端')
                page.locator('#add-rule').click();page.locator('#rule-name').fill('浏览器测试转发');page.locator('#rule-source').fill('24567')
                page.locator('#rule-peer').fill(go.name);page.locator('#rule-target').fill('80');page.locator('#rule-transport').select_option('tcp')
                page.locator('#save-rule').click()
                try:expect(page.locator('#rules')).to_contain_text('浏览器测试转发')
                except AssertionError:
                    results['add_diagnostic']={'requests':[s for s,b in getattr(c,'commands',[])], 'peer_error':getattr(c,'error',None),
                        'message':page.locator('#rule-message').text_content(), 'form_error':page.locator('#rule-error').text_content(),
                        'invalid_fields':page.locator('#rule-form').evaluate('(form)=>Array.from(form.elements).filter(e=>e.validity&&!e.validity.valid).map(e=>[e.id,e.validationMessage])'),
                        'responses':[(r.status,r.text(),r.request.post_data) for r in mutations]}
                    page.screenshot(path=str(args.output/'failure.png'),full_page=True)
                    raise
                if not args.client:assert any(sub==9 and body.get('punchPriority')==3 for sub,body in c.commands)
                else:results['real_C_client_Chinese_rule_roundtrip']=True
                expect(page.locator('#rules').get_by_role('button',name='编辑')).to_have_count(0)
                results['C_capabilities_and_add_forward']=True
                page.locator('#node-search').fill('');page.locator('#nodes tr').filter(has_text=go.name).get_by_role('button').click()
                expect(page.locator('#rules')).to_contain_text('<img src=x onerror=globalThis.__xss=1>')
                assert page.evaluate('globalThis.__xss') is None
                page.locator('#rules').get_by_role('button',name='编辑',exact=True).click();page.locator('#rule-name').fill('Go edited')
                page.locator('#rule-target').fill('8080');page.locator('#save-rule').click();expect(page.locator('#rules')).to_contain_text('Go edited')
                page.locator('#rules').get_by_role('button',name='停用',exact=True).click();page.locator('#confirm-action').click()
                expect(page.locator('#rules')).to_contain_text('已停用')
                page.locator('#rules').get_by_role('button',name='启用',exact=True).click();page.locator('#confirm-action').click()
                expect(page.locator('#rules')).to_contain_text('已连接')
                page.screenshot(path=str(args.output/'desktop.png'),full_page=True)
                page.locator('#rules').get_by_role('button',name='删除',exact=True).click();page.locator('#confirm-action').click()
                expect(page.locator('#rules tr')).to_have_count(0)
                results['Go_edit_switch_delete_and_XSS_escaping']=True
                page.set_viewport_size({'width':390,'height':844});page.locator('#nodes tr').filter(has_text=c.name).get_by_role('button').click()
                expect(page.locator('#rules')).to_contain_text('浏览器测试转发')
                if not page.evaluate('document.documentElement.scrollWidth <= innerWidth'):
                    results['mobile_overflow']=page.evaluate('Array.from(document.querySelectorAll("body *")).filter(e=>e.getBoundingClientRect().right>innerWidth+1).slice(0,12).map(e=>[e.id,e.className,Math.round(e.getBoundingClientRect().width),Math.round(e.getBoundingClientRect().right)])')
                    page.screenshot(path=str(args.output/'mobile-failure.png'),full_page=True)
                    raise AssertionError('Mobile page overflows viewport')
                page.screenshot(path=str(args.output/'mobile.png'),full_page=True);results['responsive_mobile_layout']=True
                page.set_viewport_size({'width':1440,'height':1040})
                page.route('**/api/v1/devices',lambda route:route.fulfill(status=401,content_type='application/json',body='{"error":1}'))
                page.locator('#refresh').click();expect(page.locator('#login-screen')).to_be_visible()
                expect(page.locator('#login-error')).to_contain_text('过期');page.unroute('**/api/v1/devices');login()
                results['expired_session_returns_to_login']=True
                go.close();peers.remove(go);page.locator('#refresh').click();expect(page.locator('#online-count')).to_have_text('1')
                results['offline_node_removed']=True
                page.locator('#logout').click();expect(page.locator('#login-screen')).to_be_visible()
                assert not errors,errors
                context.close();browser.close()
            assert all(peer.error is None for peer in peers)
            results['success']=True
        finally:
            if client and client.poll() is None:
                if args.wsl and (root/'client.pid').exists():
                    subprocess.run(['wsl.exe','-d','Debian','-u','maoyu','--','kill','-TERM',(root/'client.pid').read_text().strip()],check=True)
                else:client.terminate()
                try:client.wait(timeout=10)
                except subprocess.TimeoutExpired:client.kill();client.wait()
            if client_log:
                client_log.close()
                diagnostic=(root/'client.log').read_text(errors='replace')
                assert client.returncode==0 and 'Sanitizer' not in diagnostic and 'runtime error:' not in diagnostic,'C client failure'
            for peer in peers:peer.close()
            if process and process.poll() is None:
                if args.wsl and (root/'gateway.pid').exists():
                    subprocess.run(['wsl.exe','-d','Debian','-u','maoyu','--','kill','-TERM',(root/'gateway.pid').read_text().strip()],check=True)
                else:process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            log.close()
            diagnostic=(root/'gateway.log').read_text(errors='replace')
            assert process is None or process.returncode==0,'Gateway did not shut down cleanly'
            assert 'Sanitizer' not in diagnostic and 'runtime error:' not in diagnostic,'Sanitizer failure'
            (args.output/'result.json').write_text(json.dumps(results,indent=2)+'\n')
            print(json.dumps(results,indent=2))
if __name__=='__main__':main()
