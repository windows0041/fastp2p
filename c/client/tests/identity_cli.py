#!/usr/bin/env python3
"""Check private identity persistence and failure handling using the native CLI."""
import argparse
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile

p=argparse.ArgumentParser();p.add_argument('--client',required=True);args=p.parse_args()
client=Path(args.client).resolve()
with tempfile.TemporaryDirectory(prefix='op2p-identity-') as temporary, socket.socket() as listener:
    root=Path(temporary).resolve();assert root.parent==Path(tempfile.gettempdir()).resolve()
    listener.bind(('127.0.0.1',0));listener.listen()
    environment=os.environ.copy();environment['OPENP2P_TOKEN']='1'
    def run(*extra,expected=1):
        result=subprocess.run([str(client),'--serverhost','127.0.0.1','--port',str(listener.getsockname()[1]),
                                '--run-seconds','1',*map(str,extra)],env=environment,capture_output=True,timeout=20)
        assert result.returncode==expected,(result.returncode,result.stderr.decode(errors='replace'))
        assert b'Sanitizer' not in result.stderr and b'runtime error:' not in result.stderr
        return result
    identity=root/'private/client.identity'
    run('--identity-file',identity)
    original=identity.read_bytes();assert re.fullmatch(rb'[0-9a-f]{32}\n',original)
    if os.name!='nt':assert identity.stat().st_mode & 0o077==0
    run('--identity-file',identity);assert identity.read_bytes()==original
    identity.write_bytes(b'corrupt-fixture')
    run('--identity-file',identity,expected=2);assert identity.read_bytes()==b'corrupt-fixture'
    fixed=root/'fixed.identity';run('--identity-file',fixed,'--node','fixed-test-node');assert not fixed.exists()
    config=root/'auto.json';config.write_text('{"network":{"AutoNode":true}}')
    run('--config',config);assert re.fullmatch(rb'[0-9a-f]{32}\n',Path(str(config)+'.identity').read_bytes())
    if os.name!='nt':
        target=root/'target';target.write_bytes(original)
        link=root/'symlink.identity';link.symlink_to(target)
        run('--identity-file',link,expected=2);assert target.read_bytes()==original
print('Native CLI identity persistence, permissions, corrupt-file rejection and explicit-name compatibility passed')
