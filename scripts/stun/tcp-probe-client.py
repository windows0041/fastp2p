#!/usr/bin/env python3
"""Measure TCP NAT filtering: ask a probe server to call us back.

The client keeps one local port for both directions: it dials out from it (which
creates the NAT mapping) and listens on it (so an inbound SYN can be accepted).
That is the same simultaneous-open arrangement fastp2p uses for TCP punching.

Verdict:
  both callbacks arrived      -> not filtered by port or address (TCP full cone)
  only the same-IP one        -> address restricted
  neither                     -> port restricted / blocked

Usage: tcp-probe-client.py <server> [port] [other-ip]
"""
import socket
import sys

server = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478

# A free local port, then reuse it for the outbound dial and the listener.
pick = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
pick.bind(('0.0.0.0', 0))
local_port = pick.getsockname()[1]
pick.close()
print('local port: %d' % local_port)

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
listener.bind(('0.0.0.0', local_port))
listener.listen(4)
listener.settimeout(1.0)

dialer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dialer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
dialer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
dialer.bind(('0.0.0.0', local_port))
dialer.settimeout(6)
dialer.connect((server, port))
print('control connection up, local endpoint %s:%d' % dialer.getsockname()[:2])

handle = dialer.makefile('rwb')
report = handle.readline().decode().strip()
print('server reports: %s' % report)
if not report.startswith('mapped'):
    raise SystemExit('unexpected greeting')
_, mapped_ip, mapped_port = report.split()

handle.write(b'probe\n')
handle.flush()

arrivals = []
deadline = 6.0
while deadline > 0:
    try:
        conn, peer = listener.accept()
    except socket.timeout:
        deadline -= 1.0
        continue
    arrivals.append(peer)
    conn.close()
    deadline = 0.5  # keep collecting for a moment

print('callbacks from: %s' % (arrivals or 'none'))
result = handle.readline().decode().strip()
print('server result: %s' % result)

mapped = '%s:%s' % (mapped_ip, mapped_port)
same = 'same-port=1' in result
other = 'other-ip=1' in result
if same and other:
    verdict = 'TCP 全锥（两个方向都放行）'
elif same:
    verdict = 'TCP 地址受限（同 IP 新端口可入）'
else:
    verdict = 'TCP 端口受限/被拦（陌生入站不通）'
print('verdict: %s   [mapped=%s, accepted=%d]' % (verdict, mapped, len(arrivals)))
