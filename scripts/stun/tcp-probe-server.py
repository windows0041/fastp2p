#!/usr/bin/env python3
"""TCP probe server: tells a peer its mapping, then calls it back.

The callback is the TCP analogue of STUN's CHANGE-REQUEST, which does not exist
for TCP: an outbound connection reveals the mapped endpoint, and whether a *new*
inbound SYN to that endpoint is accepted is exactly what the NAT's filter decides.

  same IP, different source port  -> not port-restricted
  the other public IP            -> full cone
  neither                        -> port-restricted

It only reports what happened; the verdict is the client's job.

Usage: tcp-probe-server.py --listen 3478 [--address 1.2.3.4 ...]
"""
import argparse
import socket
import sys
import threading
import time


def accept_loop(listener, addresses, timeout):
    while True:
        try:
            conn, peer = listener.accept()
        except OSError:
            return
        threading.Thread(target=serve, args=(conn, peer, addresses, timeout), daemon=True).start()


def serve(conn, peer, addresses, timeout):
    try:
        conn.settimeout(20)
        conn.sendall(('mapped %s %d\n' % (peer[0], peer[1])).encode())
        line = conn.makefile().readline().strip()
        if not line.startswith('probe'):
            return
        results = []
        # 1. Same address, a fresh source port.
        results.append(('same-port', attempt(peer, addresses[0], 0, timeout)))
        # 2. The other public address, a fresh source port.
        if len(addresses) > 1:
            results.append(('other-ip', attempt(peer, addresses[1], 0, timeout)))
        conn.sendall((' '.join('%s=%d' % (name, ok) for name, ok in results) + '\n').encode())
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def attempt(peer, source_address, source_port, timeout):
    """Try to open a new connection to the peer from a chosen source address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.bind((source_address, source_port))
    except OSError:
        sock.close()
        return 0
    try:
        sock.connect(peer)
        return 1
    except OSError:
        return 0
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--listen', type=int, default=3478)
    parser.add_argument('--address', action='append', default=[])
    parser.add_argument('--timeout', type=float, default=4.0)
    args = parser.parse_args()

    addresses = args.address or ['0.0.0.0']
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((addresses[0] if addresses[0] != '0.0.0.0' else '0.0.0.0', args.listen))
    listener.listen(16)
    print('tcp probe listening on %s:%d, callbacks from %s' % (
        addresses[0], args.listen, ', '.join(addresses)), flush=True)
    try:
        accept_loop(listener, addresses, args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()


if __name__ == '__main__':
    sys.exit(main())
