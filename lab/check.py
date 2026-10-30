#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=43"]
# ///
"""check.py —— 模拟客户端访问 HTTPS 站点，并证明三件事。

    python3 lab/check.py <信任库> <场景> <目标IP|代理IP>

场景：
  honest  访问真实站点（正常证书）
  direct  攻击者直连：真域名 + 伪造证书
  proxy   正向代理：mitmproxy 用泄露私钥现场伪造

输出证据：
  1. 客户端接受了假证书：
       direct    对端证书指纹 == 磁盘上那张伪造证书
       proxy       mitmproxy 现场签发，指纹每次不同 → 断言"对端证书公钥 == 泄露中间 CA 公钥"
  2. 中间人看到了明文：代理日志里出现客户端发出的密码（evidence/mitm-plaintext.txt）
  3. 中间人改了内容：响应里的余额从 $0.00 被改写成 $100.00

退出码：0 = 攻击成功（接受/被骗），1 = 客户端拒绝
"""
import hashlib
import ipaddress
import socket
import ssl
import sys
from pathlib import Path

from scope import require_lab_domain

SCENARIOS = {
    "honest": ("site.decert.test", 8443),
    "direct": ("bank.decert.test", 8443),
    "proxy": ("site.decert.test", 8443),
}
# 攻击者伪造证书的指纹（由 pki.py 生成，每个证书文件一张）
CAS = Path(__file__).resolve().parent.parent / "lab" / "cas"
# 泄露私钥的真实中间 CA（mitmproxy 就是用它当 CA 现场签发）
LEAKED_CA = CAS.parent.parent / "data" / "real-ca" / "em-ov-tls-ca-g3c.pem"
PASSWORD = "hunter2-secret"
COOKIE = "session=abc123"
BEARER = "Bearer tok_live_xyz"
REAL_BALANCE = "$0.00"
EVIL_BALANCE = "$100.00"
LAB_NET = ipaddress.ip_network("10.100.0.0/24")



def pubkey_sha256(der: bytes) -> str:
    """证书公钥（SubjectPublicKeyInfo DER）的 SHA-256。"""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_der_x509_certificate(der)
    return hashlib.sha256(
        cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()


def first_cert_der(pem_path: Path) -> bytes:
    """PEM 文件里第一张证书的 DER（链文件后面可能还有中间 CA）。"""
    import ssl as _ssl

    text = pem_path.read_text()
    start = text.index("-----BEGIN CERTIFICATE-----")
    end = text.index("-----END CERTIFICATE-----", start) + len("-----END CERTIFICATE-----")
    return _ssl.PEM_cert_to_DER_cert(text[start:end])


def pem_sha256(pem_path: Path) -> str:
    """证书本身的 SHA-256（链文件里可能还有中间 CA）。"""
    return hashlib.sha256(first_cert_der(pem_path)).hexdigest()


def connect(host: str, port: int, target: str, via_proxy: bool) -> socket.socket:
    if via_proxy:
        sock = socket.create_connection((target, 8080), timeout=10)
        # CONNECT 用真实域名：代理据此决定伪造哪个域名、以及去连哪台真实站点
        sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(1024)
            if not chunk:
                raise ConnectionError("代理断开")
            head += chunk
        if b" 200" not in head:
            raise ConnectionError("代理拒绝")
        return sock
    return socket.create_connection((target, port), timeout=10)


def main() -> int:
    trust, scenario, target = sys.argv[1], sys.argv[2], sys.argv[3]
    host, port = SCENARIOS[scenario]
    try:
        require_lab_domain(host)
    except ValueError as exc:
        print(f"拒绝 | {scenario:<7} | {exc}")
        return 1
    try:
        if ipaddress.ip_address(target) not in LAB_NET:
            raise ValueError(f"目标不在实验网段：{target}")
    except ValueError as exc:
        print(f"拒绝 | {scenario:<7} | {exc}")
        return 1
    via_proxy = scenario == "proxy"
    try:
        raw = connect(host, port, target, via_proxy)
        ctx = ssl.create_default_context(cafile=trust)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            peer_der = s.getpeercert(True)
            peer_fp = hashlib.sha256(peer_der).hexdigest()
            req = (
                f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                f"Cookie: {COOKIE}\r\nAuthorization: {BEARER}\r\n"
                f"X-Password: {PASSWORD}\r\nConnection: close\r\n\r\n"
            )
            s.sendall(req.encode())
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
    except Exception as exc:  # noqa: BLE001
        reason = str(exc).split(": ")[-1].replace(" (_ssl.c:992)", "").replace(" (_ssl.c:1006)", "")[:60]
        print(f"拒绝 | {scenario:<7} | 校验失败：{reason}")
        return 1

    body = data.split(b"\r\n\r\n", 1)[1].decode("utf-8", "replace")
    lines = [f"接受 | {scenario:<7} | 对端证书指纹 {peer_fp[:16]}…"]

    fake_fp = None if scenario == "honest" else pem_sha256(CAS / "attacker-real.pem")
    # 代理场景：mitmproxy 用泄露中间 CA 的私钥现场签发，每张叶子证书都不同，
    # 所以不能比证书指纹；改为断言"证书公钥 == 泄露中间 CA 的公钥"。
    proxy_fp_ok = True
    if scenario == "proxy":
        leaf_pub = pubkey_sha256(peer_der)
        leaked_pub = pubkey_sha256(first_cert_der(LEAKED_CA))
        proxy_fp_ok = leaf_pub == leaked_pub
        lines_fp = (f"对端证书公钥 {leaf_pub[:16]}… / 泄露 CA 公钥 {leaked_pub[:16]}…"
                    f" {'一致' if proxy_fp_ok else '不一致'}")
    else:
        lines_fp = None
    # 密码是否出现在代理日志里（只有 proxy 场景能看）
    plaintext_ok = False
    if scenario == "proxy":
        log = CAS.parent.parent / "evidence" / "mitm-plaintext.txt"
        plaintext_ok = log.exists() and PASSWORD in log.read_text(errors="replace")

    if scenario == "honest":
        ok = REAL_BALANCE in body and EVIL_BALANCE not in body
        lines.append("       | 内容：真实站点原文（余额未被改动）" if ok else "       | 注意：内容异常")
        print("\n".join(lines))
        return 0 if ok else 2

    # 攻击成功必须同时满足：证书指纹 == 伪造证书；响应被改写；原文里没有真实余额
    if scenario == "proxy":
        fp_ok = proxy_fp_ok
        lines.append(f"       | 证书公钥等于泄露中间 CA：{'是' if fp_ok else '否'}")
        lines.append(f"       |   {lines_fp}")
        lines.append(f"       | 代理日志里看到密码：{'是' if plaintext_ok else '否'}")
    else:
        fp_ok = peer_fp == fake_fp
        lines.append(f"       | 证书指纹{'一致' if fp_ok else '不一致'}（伪造证书 {str(fake_fp)[:16]}…）")
    tamper_ok = EVIL_BALANCE in body and REAL_BALANCE not in body
    if tamper_ok:
        lines.append(f"       | 响应被改写：真实余额 {REAL_BALANCE} → {EVIL_BALANCE}")
    else:
        lines.append("       | 响应未被改写")
    conditions = fp_ok and tamper_ok and (plaintext_ok if scenario == "proxy" else True)
    if conditions:
        print("\n".join(lines))
        print("被骗 | 结论：客户端接受了伪造证书；中间人拿到了明文，并篡改了响应内容")
        return 0
    print("\n".join(lines))
    print("异常 | 结论：没有同时满足条件")
    return 2


if __name__ == "__main__":
    sys.exit(main())
