#!/usr/bin/env python3
"""
local_http_proxy.py

Simple local HTTP proxy that forwards browser -> remote and closes sockets
when a full HTTP response is delivered to client. Useful as a workaround for
upstream proxies that mishandle HTTP/1.1 keep-alive state.

Usage:
  python local_http_proxy.py --listen 127.0.0.1:8080 --remote example.com:80
"""

import argparse
import socket
import threading
import time
from typing import Tuple, Optional
import logging

RECV_BUF = 8192
SOCKET_TIMEOUT = 2.0   # seconds for idle reads
CONNECT_TIMEOUT = 2.0

logging.basicConfig(
    format='[%(asctime)s] %(message)s',
    level=logging.INFO,
    datefmt='%H:%M:%S'
)

def parse_request_line(data: bytes) -> Tuple[str, str]:
    try:
        lines = data.decode('iso-8859-1', errors='replace').split('\r\n')
        method, path, _ = lines[0].split(' ', 2)
        return method, path
    except Exception:
        return 'UNKNOWN', 'UNKNOWN'

def parse_hostport(spec: str) -> Tuple[str,int]:
    host, port = spec.split(':', 1)
    return host, int(port)

def read_until_double_crlf(sock: socket.socket, timeout=SOCKET_TIMEOUT) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        chunk = sock.recv(RECV_BUF)
        if not chunk:
            break
        data.extend(chunk)
        if b'\r\n\r\n' in data:
            break
        # protect against unbounded header reads
        if len(data) > 65536:
            break
    return bytes(data)

def recv_exact(sock: socket.socket, n: int, timeout=SOCKET_TIMEOUT) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(min(RECV_BUF, n - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)

def forward_all(src: socket.socket, dst: socket.socket, timeout=SOCKET_TIMEOUT):
    src.settimeout(timeout)
    try:
        while True:
            chunk = src.recv(RECV_BUF)
            if not chunk:
                break
            dst.sendall(chunk)
    except socket.timeout:
        pass
    except Exception:
        pass

def handle_client(client_sock: socket.socket, remote_host: str, remote_port: int):
    client_addr = client_sock.getpeername()
    client_sock.settimeout(SOCKET_TIMEOUT)
    try:
        # Read request headers from client
        req_headers = read_until_double_crlf(client_sock)
        if not req_headers:
            client_sock.close()
            return
        start_time = time.time()
        method, path = parse_request_line(req_headers)
        client_ip = client_sock.getpeername()[0]
        req_size = len(req_headers)

        
        # Connect to remote
        remote = socket.create_connection((remote_host, remote_port), timeout=CONNECT_TIMEOUT)
        remote.settimeout(SOCKET_TIMEOUT)

        # Send what we've already read (headers + maybe some body bytes) to remote
        # There is a risk: if there is a request body (POST), we must forward it too.
        # Try to detect Content-Length in request headers and read body if present.
        remote.sendall(req_headers)

        # parse request headers for Content-Length
        headers_text = req_headers.decode('iso-8859-1', errors='replace')
        head, _, rest = headers_text.partition('\r\n\r\n')
        content_length = 0
        for line in head.split('\r\n')[1:]:
            if ':' not in line:
                continue
            k, v = line.split(':',1)
            if k.strip().lower() == 'content-length':
                try:
                    content_length = int(v.strip())
                except Exception:
                    content_length = 0
                break

        # If we read extra bytes after header (e.g., read part of body), forward the rest that was already captured
        # (In our read_until_double_crlf we may not have consumed body bytes, but if read() returned more than header,
        # they'd be in req_headers after the header bytes — handled by sending req_headers above.)

        # If request has a body, read remaining bytes and forward
        if content_length > 0:
            # Count how many bytes of body we've already sent (if any)
            hdr_bytes = (head + '\r\n\r\n').encode('iso-8859-1')
            already = len(req_headers) - len(hdr_bytes)
            remaining = max(0, content_length - already)
            if remaining > 0:
                body_rest = recv_exact(client_sock, remaining)
                if body_rest:
                    remote.sendall(body_rest)

        # Now read response headers from remote
        resp_head_bytes = read_until_double_crlf(remote)
        if not resp_head_bytes:
            # remote closed immediately
            client_sock.close()
            remote.close()
            return

        # Forward response headers to client
        client_sock.sendall(resp_head_bytes)

        resp_head_text = resp_head_bytes.decode('iso-8859-1', errors='replace')
        resp_head, _, _ = resp_head_text.partition('\r\n\r\n')
        # Determine response framing
        headers = {}
        for line in resp_head.split('\r\n')[1:]:
            if ':' in line:
                k,v = line.split(':',1)
                headers[k.strip().lower()] = v.strip().lower()

        # If Transfer-Encoding: chunked
        if 'transfer-encoding' in headers and 'chunked' in headers['transfer-encoding']:
            # read chunks until 0\r\n\r\n sequence end of chunked message
            try:
                while True:
                    # read chunk size line
                    line = b''
                    while not line.endswith(b'\r\n'):
                        c = remote.recv(1)
                        if not c:
                            break
                        line += c
                    client_sock.sendall(line)
                    if not line:
                        break
                    size_str = line.strip().split(b';',1)[0]
                    try:
                        size = int(size_str, 16)
                    except Exception:
                        size = 0
                    if size == 0:
                        # read and forward the trailing CRLF and any trailers until double CRLF
                        trailing = read_until_double_crlf(remote)
                        if trailing:
                            client_sock.sendall(trailing)
                        break
                    # read the chunk payload + CRLF
                    chunk = recv_exact(remote, size + 2)
                    if chunk:
                        client_sock.sendall(chunk)
            except Exception:
                pass
            finally:
                # chunked responses usually imply connection can remain open, but to avoid upstream proxy issues,
                # close remote after complete response
                remote.close()
                client_sock.close()
                duration = time.time() - start_time
                resp_size = len(resp_head_bytes) + (len(data) if 'data' in locals() else 0)
                print(f'\t{client_ip} Chunked {method} {path} | Req: {req_size} bytes, Resp: {resp_size} bytes, Time: {duration:.2f}s')
                return

        # If Content-Length present
        elif 'content-length' in headers:
            try:
                total = int(headers['content-length'])
            except Exception:
                total = 0
            # How many body bytes we've already forwarded (might be zero)
            # Already forwarded after headers: len(resp_head_bytes) - len((resp_head + '\r\n\r\n').encode())
            hdr_bytes = (resp_head + '\r\n\r\n').encode('iso-8859-1')
            already = len(resp_head_bytes) - len(hdr_bytes)
            remaining = max(0, total - already)
            if remaining > 0:
                data = recv_exact(remote, remaining)
                if data:
                    client_sock.sendall(data)
            # finished response; close remote to avoid keepalive confusion
            remote.close()
            client_sock.close()
            duration = time.time() - start_time
            resp_size = len(resp_head_bytes) + (len(data) if 'data' in locals() else 0)
            print(f'\t{client_ip} content-length {method} {path} | Req: {req_size} bytes, Resp: {resp_size} bytes, Time: {duration:.2f}s')           
            return

        # No explicit length: server will close to indicate end of body (HTTP/1.0 behavior)
        else:
            # Forward until remote closes or timeout
            try:
                forward_all(remote, client_sock, timeout=SOCKET_TIMEOUT)
            finally:
                remote.close()
                client_sock.close()
                duration = time.time() - start_time
                resp_size = len(resp_head_bytes) + (len(data) if 'data' in locals() else 0)
                print(f'\t{client_ip} HTML1.0 type {method} {path} | Req: {req_size} bytes, Resp: {resp_size} bytes, Time: {duration:.2f}s')
                return

    except Exception as e:
        try:
            client_sock.close()
        except Exception:
            pass

def serve(listen_host: str, listen_port: int, remote_host: str, remote_port: int):
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((listen_host, listen_port))
    ls.listen(100)
    print(f'Listening on {listen_host}:{listen_port}, forwarding to {remote_host}:{remote_port}')
    try:
        while True:
            c, _ = ls.accept()
            t = threading.Thread(target=handle_client, args=(c, remote_host, remote_port), daemon=True)
            t.start()
    finally:
        ls.close()

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--listen', required=True, help='listen address host:port (e.g. 127.0.0.1:8080)')
    p.add_argument('--remote', required=True, help='remote host:port (e.g. origin.example:80)')
    args = p.parse_args()
    lh, lp = parse_hostport(args.listen)
    rh, rp = parse_hostport(args.remote)
    serve(lh, lp, rh, rp)

