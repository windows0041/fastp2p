#!/usr/bin/env python3
"""Minimal STUN server that honours RFC 3489 CHANGE-REQUEST and RFC 5780.

Why this exists: public STUN servers mostly ignore CHANGE-REQUEST, so a NAT's
inbound filter cannot be measured through them (a filtered reply and an ignored
attribute look identical). Running this on a host with two public addresses makes
the "answer from a different address" case real, which is what separates a
full-cone NAT (NAT1) from an address-restricted one (NAT2) and a port-restricted
one (NAT3).

The layout follows the reference implementation (jselbie/stunserver): four sockets
in a 2x2 matrix, and every request is answered by one of them:

    primary   address / primary   port   <- plain requests
    primary   address / alternate port   <- CHANGE-REQUEST port
    alternate address / primary   port   <- CHANGE-REQUEST ip
    alternate address / alternate port   <- CHANGE-REQUEST ip + port

Attributes are emitted in the order the reference implementation uses (MAPPED,
RESPONSE-ORIGIN, OTHER-ADDRESS, XOR-MAPPED-ADDRESS) because some clients are
written against that ordering. OTHER-ADDRESS is only advertised when all four
sockets are real: telling a client about an address that cannot answer would make
it report a port-restricted NAT that does not exist.

RESPONSE-PORT (RFC 5780 section 4.5) is honoured: a client may ask for the reply to
be sent to a different port of its own address, which is the other way to probe the
inbound filter.

Usage: stun-responder.py [--port 3478] [--address 1.2.3.4 ...]
"""
import argparse
import json
import selectors
import socket
import struct
import subprocess
import sys

MAGIC = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_MAPPED = 0x0001
ATTR_CHANGE_REQUEST = 0x0003
ATTR_XOR_MAPPED = 0x0020
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C
ATTR_RESPONSE_PORT = 0x8032


def local_addresses():
    """Every global IPv4 the host holds, via iproute2 (always present on the
    distributions this runs on). Falls back to the kernel's source selection."""
    addresses = []
    try:
        # JSON output keeps the broadcast address out of the list; the text form
        # also carries "brd <addr>", which is not a usable source.
        output = subprocess.run(['ip', '-j', '-4', 'addr', 'show', 'scope', 'global'],
                                capture_output=True, text=True, timeout=5).stdout
        for interface in json.loads(output or '[]'):
            for info in interface.get('addr_info', []):
                candidate = info.get('local')
                if info.get('family') == 'inet' and candidate and candidate not in addresses:
                    addresses.append(candidate)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    if not addresses:
        # One address is still enough for the change-port case.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(('1.1.1.1', 53))
            candidate = probe.getsockname()[0]
            if candidate.count('.') == 3 and candidate != '0.0.0.0':
                addresses.append(candidate)
        except OSError:
            pass
        finally:
            probe.close()
    return addresses


def address_attribute(kind, address, port, xored):
    if xored:
        port_value = port ^ (MAGIC >> 16)
        cookie = struct.pack('!I', MAGIC)
        packed = bytes(a ^ b for a, b in zip(socket.inet_aton(address), cookie))
    else:
        port_value = port
        packed = socket.inet_aton(address)
    value = bytes([0, 1]) + struct.pack('!H', port_value) + packed
    return struct.pack('!HH', kind, len(value)) + value


def build_response(transaction, client, origin, other):
    """MAPPED-ADDRESS, RESPONSE-ORIGIN, OTHER-ADDRESS, XOR-MAPPED-ADDRESS.

    `origin` is the endpoint this reply leaves from, `other` the endpoint that would
    answer a combined change-ip/change-port request (None when the host has no
    second address, which suppresses the attribute)."""
    attrs = address_attribute(ATTR_MAPPED, client[0], client[1], False)
    attrs += address_attribute(ATTR_RESPONSE_ORIGIN, origin[0], origin[1], False)
    if other:
        attrs += address_attribute(ATTR_OTHER_ADDRESS, other[0], other[1], False)
    attrs += address_attribute(ATTR_XOR_MAPPED, client[0], client[1], True)
    return struct.pack('!HHI', BINDING_SUCCESS, len(attrs), MAGIC) + transaction + attrs


def parse_attributes(data):
    """Returns (change_ip, change_port, response_port)."""
    change_ip = change_port = False
    response_port = 0
    offset = 20
    while offset + 4 <= len(data):
        atype, alen = struct.unpack('!HH', data[offset:offset + 4])
        value = data[offset + 4:offset + 4 + alen]
        if atype == ATTR_CHANGE_REQUEST and alen == 4:
            flags = struct.unpack('!I', value)[0]
            change_ip = bool(flags & 0x04)
            change_port = bool(flags & 0x02)
        elif atype == ATTR_RESPONSE_PORT and alen == 2:
            response_port = struct.unpack('!H', value)[0]
        offset += 4 + ((alen + 3) & ~3)
    return change_ip, change_port, response_port


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=3478)
    parser.add_argument('--address', action='append', default=[])
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    addresses = args.address or local_addresses()
    if not addresses:
        print('no local IPv4 address found', file=sys.stderr)
        return 1
    primary, alternate_port = args.port, args.port + 1
    print('serving on %s, udp/%d and udp/%d' % (', '.join(addresses), primary, alternate_port))

    selector = selectors.DefaultSelector()
    sockets = {}
    for address in addresses:
        for port in (primary, alternate_port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((address, port))
            selector.register(sock, selectors.EVENT_READ)
            sockets[(address, port)] = sock

    # OTHER-ADDRESS is only advertised when the whole 2x2 matrix exists, matching
    # the reference implementation: a client told about an address that cannot
    # answer would report filtering that is not there.
    complete = len(addresses) > 1

    while True:
        for key, _ in selector.select(timeout=60):
            sock = key.fileobj
            try:
                data, peer = sock.recvfrom(2048)
            except OSError:
                continue
            # Only BINDING requests are answered: no echo, no amplification.
            if len(data) < 20 or struct.unpack('!H', data[:2])[0] != BINDING_REQUEST:
                continue
            if struct.unpack('!I', data[4:8])[0] != MAGIC:
                continue
            transaction = data[8:20]
            change_ip, change_port, response_port = parse_attributes(data)
            local = sock.getsockname()

            target_address = local[0]
            if change_ip:
                others = [a for a in addresses if a != local[0]]
                if not others:
                    if args.verbose:
                        print('change-ip requested but only one address is bound; not answering')
                    continue
                target_address = others[0]
            target_port = alternate_port if change_port else primary
            out = sockets.get((target_address, target_port))
            if out is None:
                continue

            # RESPONSE-PORT lets the client choose the port the answer arrives on;
            # it is the second way to probe the inbound filter (RFC 5780 4.5).
            destination = (peer[0], response_port or peer[1])
            other = None
            if complete:
                other_address = [a for a in addresses if a != target_address]
                if other_address:
                    other = (other_address[0], alternate_port)
            payload = build_response(transaction, peer, (target_address, target_port), other)
            try:
                out.sendto(payload, destination)
            except OSError:
                continue
            if args.verbose:
                print('%s:%d -> %s:%d (change ip=%s port=%s response-port=%s)' % (
                    local[0], local[1], target_address, target_port, change_ip, change_port,
                    response_port or '-'))


if __name__ == '__main__':
    sys.exit(main())
