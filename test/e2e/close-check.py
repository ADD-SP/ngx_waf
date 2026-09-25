#!/usr/bin/env python3
"""Send one request over a raw socket with `Connection: close` and exit 0 when
the server answered with the expected status *and* closed the connection.

    close-check.py <port> <method> <uri> <expected status> [body]

A request whose reference count leaked is never released: the answer still
arrives, but nginx keeps the connection open (and one of the worker connections
with it), so the read of the socket times out instead of ending at the close of
the server.
"""
import socket
import sys

port = int(sys.argv[1])
method = sys.argv[2]
uri = sys.argv[3]
expected = sys.argv[4]
body = sys.argv[5].encode() if len(sys.argv) > 5 else b""

request = (
    b"%s %s HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Connection: close\r\n"
    b"Content-Length: %d\r\n\r\n" % (method.encode(), uri.encode(), len(body))
) + body

connection = socket.create_connection(("127.0.0.1", port), timeout=5)
connection.sendall(request)
connection.settimeout(5)

data = b""
try:
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data += chunk
except (socket.timeout, ConnectionResetError):
    sys.exit(1)
finally:
    connection.close()

status = data.split(b"\r\n", 1)[0].split(b" ")[1:2]
if not status or status[0].decode(errors="replace") != expected:
    sys.exit(1)
