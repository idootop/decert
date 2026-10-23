#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=43"]
# ///
"""pki.py —— 生成实验用的全部密钥与证书（纯本地，域名都是 *.decert.test）。

    uv run lab/pki.py            # 生成本地 CA、正常证书、攻击者证书、信任库
    uv run lab/pki.py --show     # 从公开证书还原弱私钥（攻击者的第一步）

产物（lab/cas/）：
    root.pem  weak-ca.pem  site.pem            本地站点链路（私钥 = 4，复刻事故）
    attacker-real.pem                          伪造证书 + 真实 eMudhra 中间 CA
    trust-old.pem  trust-new.pem              两种客户端信任库
"""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "lab" / "cas"
REAL = ROOT / "data" / "real-ca"
NOW = dt.datetime.now(dt.timezone.utc)

D_WEAK = 4   # 事故里最小的私钥；本地复刻用它


def name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EMU-LAB"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def key_der(d: int):
    return ec.derive_private_key(d, ec.SECP384R1())


def pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def pem_cert(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def builder(subject, issuer, pub, days, ca, pathlen=None, issuer_pub=None):
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer).public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW - dt.timedelta(days=1))
         .not_valid_after(NOW + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
         .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False))
    if issuer_pub is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_pub), critical=False)
    return b


def server(b, *domains):
    return b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]), critical=False)


def save(path: Path, *parts: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(p if p.endswith(b"\n") else p + b"\n" for p in parts))
    print(f"  {path.relative_to(ROOT)}")


def recover_d(cert_pem: bytes):
    """攻击者的第一步：只拿公开证书，试 255 个小整数，找到私钥。"""
    pub = x509.load_pem_x509_certificate(cert_pem).public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return None
    target = pub.public_numbers()
    for d in range(1, 256):
        n = key_der(d).public_key().public_numbers()
        if (n.x, n.y) == (target.x, target.y):
            return d
    return None


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    real_ca = x509.load_pem_x509_certificate((REAL / "em-ov-tls-ca-g3c.pem").read_bytes())
    real_chain = (REAL / "g3-intermediates.pem").read_bytes()

    print("[1] 本地 CA")
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = builder(name("EMU-LAB Root CA"), name("EMU-LAB Root CA"), root_key.public_key(), 3650, True, None, root_key.public_key()) \
        .sign(root_key, hashes.SHA384())
    save(OUT / "root.pem", pem_cert(root))

    weak_key = key_der(D_WEAK)                      # 复刻事故：私钥就是 4
    weak = builder(name("EMU-LAB Weak TLS CA"), root.subject, weak_key.public_key(), 3650, True, 0, root_key.public_key()) \
        .sign(root_key, hashes.SHA384())
    save(OUT / "weak-ca.key", pem_key(weak_key))
    save(OUT / "weak-ca.pem", pem_cert(weak))

    print("[2] 真实站点的正常证书")
    site_key = ec.generate_private_key(ec.SECP256R1())
    site = server(builder(name("site.decert.test"), weak.subject, site_key.public_key(), 365, False, None, weak_key.public_key()),
                  "site.decert.test").sign(weak_key, hashes.SHA256())
    save(OUT / "site.key", pem_key(site_key))
    save(OUT / "site.pem", pem_cert(site), pem_cert(weak), pem_cert(root))

    print("[3] 攻击者证书（一）：伪造进真实 eMudhra 链")
    leaked = key_der(D_WEAK)                        # 与真实 EM OV TLS CA - G3C 相同（见 --show）
    fake_key = ec.generate_private_key(ec.SECP256R1())
    fake = server(builder(name("bank.decert.test"), real_ca.subject, fake_key.public_key(), 60, False, None, leaked.public_key()),
                  "bank.decert.test").sign(leaked, hashes.SHA256())
    save(OUT / "attacker-real.key", pem_key(fake_key))
    save(OUT / "attacker-real.pem", pem_cert(fake), real_chain)

    print("[4] 信任库")
    g3_root = (REAL / "g3-root.pem").read_bytes()
    save(OUT / "trust-old.pem", pem_cert(root), g3_root)        # 旧设备：信任 emSign G3
    save(OUT / "trust-new.pem", pem_cert(root))                 # 新设备：没有 emSign G3


def show() -> None:
    print("从公开证书还原私钥（不需要任何漏洞）：")
    for p in sorted(REAL.glob("*.pem")):
        d = recover_d(p.read_bytes())
        if d is None:
            print(f"  {p.name:<26} 密钥正常（不是小整数）")
        else:
            print(f"  {p.name:<26} 私钥 d = {d}")


if __name__ == "__main__":
    show() if "--show" in sys.argv else main()
