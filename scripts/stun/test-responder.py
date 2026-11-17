#!/usr/bin/env python3
"""Check the responder's wire behaviour end to end.

Starts the server on two loopback addresses and verifies the four socket roles, the
attribute set and its order, that OTHER-ADDRESS is only advertised when a second
address really exists, and that RESPONSE-PORT redirects the reply.

    python3 scripts/stun/test-responder.py [--port 13478]
"""
import argparse
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAGIC = 0x2112A442
PRIMARY = '127.0.0.1'
ALTERNATE = '127.0.0.2'


def request(change_ip=False, change_port=False, response_port=0):
    flags = (0x04 if change_ip else 0) | (0x02 if change_port else 0)
    attrs = b''
    if change_ip or change_port:
        attrs += struct.pack('!HHI', 0x0003, 4, flags)
    if response_port:
        attrs += struct.pack('!HHH', 0x8032, 2, response_port)
    tid = b'0123456789ab'
    return struct.pack('!HHI', 0x0001, len(attrs), MAGIC) + tid + attrs


def exchange(port, payload, listen_port=0, timeout=2.0):
    """Send from a socket bound to an explicit local port (for RESPONSE-PORT)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((PRIMARY, listen_port))
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (PRIMARY, port))
        data, peer = sock.recvfrom(2048)
        return data, peer, sock.getsockname()
    except socket.timeout:
        return None, None, sock.getsockname()
    finally:
        sock.close()


def attributes(data):
    found = []
    offset = 20
    while offset + 4 <= len(data):
        atype, alen = struct.unpack('!HH', data[offset:offset + 4])
        value = data[offset + 4:offset + 4 + alen]
        found.append((atype, value))
        offset += 4 + ((alen + 3) & ~3)
    return found


def start(port, addresses, verbose=False):
    script = Path(__file__).with_name('stun-responder.py')
    command = [sys.executable, str(script), '--port', str(port)]
    for address in addresses:
        command += ['--address', address]
    if verbose:
        command.append('--verbose')
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.0)
    return process


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=13478)
    args = parser.parse_args()
    port = args.port
    failures = []

    def check(condition, message):
        print(('  ok   ' if condition else '  FAIL ') + message)
        if not condition:
            failures.append(message)

    print('two-address server')
    server = start(port, [PRIMARY, ALTERNATE])
    try:
        data, peer, _ = exchange(port, request())
        check(data is not None, 'plain request is answered')
        if data:
            kinds = [atype for atype, _ in attributes(data)]
            check(kinds == [0x0001, 0x802B, 0x802C, 0x0020],
                  'attributes are MAPPED, RESPONSE-ORIGIN, OTHER-ADDRESS, XOR-MAPPED (got %s)'
                  % [hex(k) for k in kinds])
            other = dict(attributes(data)).get(0x802C)
            if other:
                other_ip = socket.inet_ntoa(other[4:8])
                other_port = struct.unpack('!H', other[2:4])[0]
                check((other_ip, other_port) == (ALTERNATE, port + 1),
                      'OTHER-ADDRESS names the alternate address and port (%s:%d)' % (other_ip, other_port))
            check(peer[0] == PRIMARY and peer[1] == port, 'plain reply comes from the primary socket')

        data, peer, _ = exchange(port, request(change_port=True))
        check(peer is not None and peer[1] == port + 1, 'change-port is answered from port+1')

        data, peer, _ = exchange(port, request(change_ip=True))
        check(peer is not None and peer[0] == ALTERNATE and peer[1] == port,
              'change-ip is answered from the alternate address, same port')

        data, peer, _ = exchange(port, request(change_ip=True, change_port=True))
        check(peer is not None and peer[0] == ALTERNATE and peer[1] == port + 1,
              'change-ip + change-port is answered from the alternate address, port+1')

        # RESPONSE-PORT: the answer must go to the port named in the request, not
        # back to the sender. Two sockets prove it - the sender must stay silent and
        # the named port must receive it.
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.bind((PRIMARY, 0))
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind((PRIMARY, 0))
        target_port = receiver.getsockname()[1]
        try:
            sender.sendto(request(response_port=target_port), (PRIMARY, port))
            receiver.settimeout(2.0)
            data, _ = receiver.recvfrom(2048)
            check(data is not None, 'RESPONSE-PORT delivers the answer to the requested port')
            sender.settimeout(0.5)
            stray = None
            try:
                stray, _ = sender.recvfrom(2048)
            except socket.timeout:
                pass
            check(stray is None, 'RESPONSE-PORT does not also answer the source port')
        except socket.timeout:
            check(False, 'RESPONSE-PORT delivers the answer to the requested port')
        finally:
            sender.close()
            receiver.close()
    finally:
        server.terminate()
        server.wait(timeout=5)

    print('single-address server')
    single = start(port + 10, [PRIMARY])
    try:
        data, peer, _ = exchange(port + 10, request())
        check(data is not None, 'plain request is answered')
        if data:
            kinds = [atype for atype, _ in attributes(data)]
            check(0x802C not in kinds,
                  'OTHER-ADDRESS is suppressed when only one address exists')
        data, peer, _ = exchange(port + 10, request(change_ip=True), timeout=1.0)
        check(data is None, 'change-ip is not answered when no alternate address exists')
    finally:
        single.terminate()
        single.wait(timeout=5)

    print()
    if failures:
        print('FAILED: %d check(s)' % len(failures))
        return 1
    print('all checks passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
