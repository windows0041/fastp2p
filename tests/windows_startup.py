#!/usr/bin/env python3
"""Check the shipped EXE's console behavior using real Windows processes."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument('--client', required=True)
p.add_argument('--worker', choices=('detached', 'console'))
args = p.parse_args()
assert os.name == 'nt', 'Windows-only test'
client = Path(args.client).resolve()
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.GetConsoleWindow.restype = ctypes.c_void_p

# Subsystem is decided before any client code runs. This catches a regression
# even if code hides the resulting window too quickly for an observer to see.
image = client.read_bytes()
pe = struct.unpack_from('<I', image, 0x3c)[0]
assert image[pe:pe + 4] == b'PE\0\0'
assert struct.unpack_from('<H', image, pe + 24 + 68)[0] == 2, 'EXE must use Windows GUI subsystem'

if not args.worker:
    for mode in ('detached', 'console'):
        startup = subprocess.STARTUPINFO()
        flags = subprocess.DETACHED_PROCESS
        if mode == 'console':
            # A hidden parent console exercises foreground shell attachment
            # without flashing a test window on the developer's desktop.
            flags = subprocess.CREATE_NEW_CONSOLE
            startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = subprocess.SW_HIDE
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--client', str(client),
                                 '--worker', mode], capture_output=True, timeout=40,
                                creationflags=flags, startupinfo=startup)
        assert result.returncode == 0, (mode, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'))
    print('Windows startup stays console-free; foreground shell attachment, pipes, logs and exit codes passed')
    sys.exit(0)

assert bool(kernel.GetConsoleWindow()) == (args.worker == 'console')
probe = '''
import ctypes, sys
k = ctypes.WinDLL('kernel32', use_last_error=True)
k.FreeConsole()
if not k.AttachConsole(int(sys.argv[1])):
    sys.exit(0 if sys.argv[2] == 'none' and ctypes.get_last_error() == 6 else 11)
if sys.argv[2] == 'none':
    sys.exit(12)
owners = (ctypes.c_ulong * 256)()
count = k.GetConsoleProcessList(owners, 256)
sys.exit(0 if int(sys.argv[2]) in owners[:count] else 13)
'''

def console_is(process, owner):
    assert process.poll() is None, 'client exited before console inspection'
    result = subprocess.run([sys.executable, '-c', probe, str(process.pid), str(owner)],
                            capture_output=True, creationflags=subprocess.DETACHED_PROCESS, timeout=10)
    assert result.returncode == 0, ('console probe', owner, result.returncode)

environment = os.environ.copy()
environment.pop('FASTP2P_TOKEN', None)
for option, text in (('--version', b'fastp2p '), ('--help', b'fastp2p install')):
    result = subprocess.run([str(client), option], env=environment, capture_output=True, timeout=10)
    assert result.returncode == 0 and text in result.stdout, (option, result.returncode, result.stdout, result.stderr)

with tempfile.TemporaryDirectory(prefix='fastp2p-startup-') as temporary, socket.socket() as listener:
    root = Path(temporary)
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    config = root / 'fastp2p.conf'
    config.write_text(json.dumps({'network': {'Node': 'startup-test-node', 'DeviceID': 'a' * 32,
        'ServerHost': '127.0.0.1', 'ServerPort': listener.getsockname()[1], 'Token': '9999999999999999'},
        'apps': [], 'socks5': []}))
    for background in (False, True):
        command = [str(client), 'run', '--config', str(config), '--run-seconds', '3']
        if background:
            command.append('--background')
        process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(.15)
            console_is(process, 'none' if background or args.worker == 'detached' else os.getpid())
            out, err = process.communicate(timeout=15)
            assert process.returncode in (0, 1), (process.returncode, err)
            if background:
                log = Path(str(config) + '.log')
                assert log.exists() and b'"event"' in log.read_bytes(), 'background output must go to the profile log'
                assert out == b'' and err == b'', (out, err)
            else:
                assert b'"event"' in out, 'redirected foreground output was lost during console attachment'
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=10)
    result = subprocess.run([str(client), 'run', '--config', str(root / 'missing.conf')],
                            env=environment, capture_output=True, timeout=10)
    assert result.returncode == 2 and b'Invalid JSON configuration' in result.stderr
