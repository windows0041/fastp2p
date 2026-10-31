#!/usr/bin/env python3
"""Loopback-only fixtures used to verify the remote OpenP2P data path."""
import socket
import socketserver
import threading

class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        self.request.sendall((socket.gethostname() + '-OPENP2P-ECHO\n').encode())
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        connection.sendto(socket.gethostname().encode() + b'|' + data, self.client_address)

tcp = socketserver.ThreadingTCPServer(('127.0.0.1', 24400), TCP)
udp = socketserver.ThreadingUDPServer(('127.0.0.1', 24401), UDP)
tcp.daemon_threads = udp.daemon_threads = True
threading.Thread(target=tcp.serve_forever, daemon=True).start()
udp.serve_forever()
