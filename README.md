# decert

**Hunt legacy devices with broken trust anchors.**

> [!WARNING]
> **Disclaimer**
>
> This project is provided for authorized security research, education, and defensive
> testing only. All hostnames are under the reserved `*.decert.test` domain, and all
> certificates are generated locally; the project does not connect to any live service.
>
> The software is provided "as is", without warranty of any kind, express or implied,
> including but not limited to the warranties of merchantability, fitness for a
> particular purpose, and non-infringement. In no event shall the authors or copyright
> holders be liable for any claim, damages, or other liability, whether in an action of
> contract, tort, or otherwise, arising from, out of, or in connection with the software
> or its use.
>
> You are solely responsible for ensuring that any use complies with applicable laws
> and regulations and that you have obtained the necessary authorization. Unauthorized
> interception, decryption, or impersonation of communications is illegal in most
> jurisdictions.

2026 年 10 月，印度证书机构 eMudhra 有 8 张中间 CA 证书的私钥过短，最小的仅等于整数 `4`。
这类私钥可直接从公开证书还原，进而为任意域名签发能通过正常校验的证书。

`decert` 在本地复现这条攻击链：还原私钥、签发伪造证书、拦截并篡改 HTTPS 流量，
并输出可核验的证据。

## 1. 快速开始

依赖：Docker 或 Podman、[uv](https://docs.astral.sh/uv/)、`make`。

```bash
make                # 查看所有命令
make run            # 一键跑完整流程（约 1 分钟）
make down           # 清理

./decert.sh --help  # CLI 用法
```

`make run` 依次执行：生成本地证书 → 构建镜像 → 还原私钥 → 启动攻击面 → 运行对照测试。

## 2. 结果

| 客户端 | 正常访问 | 攻击者直连 | 正向代理 |
|---|---|---|---|
| 信任库含 eMudhra 根 | 接受 | **被骗** | **被骗** |
| 已移除该根 | 接受 | 拒绝 | 拒绝 |

"被骗"需同时满足三项证据：

1. **证书**：客户端接受了对端证书。直连比对证书指纹；正向代理每次现场签发，
   因此比对**对端证书公钥**与泄露中间 CA 的公钥。
2. **明文**：客户端发出的 `Cookie`、`Authorization`、`X-Password` 出现在代理记录中
   （`evidence/mitm-plaintext.txt`）。
3. **篡改**：真实站点返回余额 `$0.00`，客户端得到的是 `$100.00`。

结论：移除整条根证书即可挡下全部场景；仅拉黑那 8 张中间 CA 并不充分。

## 3. 攻击是怎么进行的

以银行站点 `bank.decert.test` 为例：

1. **还原私钥**：下载真实中间 CA 的公开证书，逐个尝试 `1` 到 `255`，命中 `4`。
2. **签发假证书**：用这把私钥为 `bank.decert.test` 签发证书。签发者在信任库中，客户端认它合法。
3. **引流**：攻击者控制网络（公共 Wi-Fi、DNS 劫持、ARP 欺骗），让请求先到达攻击者机器。
4. **客户端接受**：签名与域名校验全部通过，正常建立加密连接。
5. **读改流量**：会话密钥由攻击者掌握，密码、Cookie、接口密钥均可被读取和篡改。

## 4. 目录

```
decert/
├── decert.sh              CLI 入口：run / pki / build / attack / test / down
├── Makefile               常用命令（make 查看）
├── data/real-ca/          事件涉及的公开证书（无任何私钥）
├── images/                客户端与攻击者代理的容器镜像
│   ├── client-old/        信任库保留 eMudhra 根
│   ├── client-new/        信任库已移除该根
│   └── proxy/             攻击者正向代理（mitmproxy）
├── lab/
│   ├── pki.py             证书与信任库生成；--show 演示还原私钥
│   ├── check.py           模拟客户端并核对三项证据
│   ├── site/serve.py      最小 HTTPS 服务：真实站点 / 中间人 / 伪造页
│   └── mitm/addon.py      mitmproxy 插件：记录明文并改写响应
├── evidence/              运行结果（已 gitignore）
└── lab/cas/               运行时生成的证书（已 gitignore）
```

## 5. 命令行

```bash
make run      # 完整复现
make pki      # 只生成证书（lab/cas/）
make show     # 演示：从公开证书还原私钥
make build    # 只构建镜像
make attack   # 只启动攻击面
make test     # 只跑对照矩阵（需先 make attack）
make shell    # 进入旧客户端容器
make down     # 停止并清理
make clean    # 连生成物一起删除
```

攻击面启动后的三个入口（容器网络 `decert`，`10.100.0.0/24`）：

| 场景 | 地址 | 说明 |
|---|---|---|
| 正常访问 | `10.100.0.10:8443` | 对照组 |
| 攻击者直连 | `10.100.0.20:8443` | 伪造证书转发真实站点，并篡改响应 |
| 正向代理 | `10.100.0.40:8080` | mitmproxy 用泄露私钥现场签发 |

## 6. 影响范围

判断某台设备是否受影响，只看一件事：**它的信任库里是否仍包含 `emSign ECC Root CA - G3`**。

| 时间 | 事件 |
|---|---|
| 2018-02 | `emSign ECC Root CA - G3` 签发，有效期至 2043 年 |
| 2019-03 | Python `certifi` 开始收录该根 |
| 2025-04-30 | 8 张弱私钥中间 CA 签发，事故根源形成 |
| 2026-10-17 | 研究者上报 Mozilla；Firefox 当天下发 OneCRL 拉黑 |
| 2026-10-18 | `certifi` 移除该根 |
| 2026-10-20 | Mozilla 从 NSS 信任库移除该根 |

**受影响**：macOS、iOS、Android，以及 JDK / Kotlin / Gradle（自带 `cacerts`）——
它们的信任库中仍有该根。旧版 Debian 12、旧版 `certifi`（`2026.10.18` 之前）同样在内。

**不受影响**：Ubuntu、Alpine、Node.js、Rust（rustls）、Firefox，以及已升级的 `certifi`。

**跟随系统**：Go、Dart / Flutter、curl 使用系统信任库，状态取决于所在平台；
Windows 随系统更新下发，需逐机确认。

自查方法：在该平台搜索信任库中是否存在 `emSign ECC Root CA - G3`。

```bash
# Linux
awk '/BEGIN CERT/{n++} {print > ("/tmp/q" n ".pem")}' /etc/ssl/certs/ca-certificates.crt
for f in /tmp/q*.pem; do openssl x509 -in $f -noout -subject | grep -q 'emSign ECC Root CA - G3' && echo 受影响; done

# Python
python3 -c "import certifi,re;b=open(certifi.where()).read();print('受影响' if re.search('emSign ECC Root CA - G3',b) else '不受影响')"

# Java / Kotlin / Gradle
keytool -list -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit | grep -i emsign

# macOS
security find-certificate -a -c emSign /System/Library/Keychains/SystemRootCertificates.keychain

# Windows (PowerShell)
Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -like '*emSign*'
```

处置：移除该根或升级信任库；无法升级的设备使用证书固定（pinning）或 mTLS。

## 7. 参考

- [Mozilla Security Blog：eMudhra intermediate certificates compromise](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/)
- [Mozilla Bugzilla 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla NSS 3.131.1](https://groups.google.com/a/mozilla.org/g/dev-tech-crypto/c/vSxZxnOMMvs)
- [Android 系统信任库（AOSP）](https://android.googlesource.com/platform/system/ca-certificates/)
- [certifi 发布记录](https://pypi.org/project/certifi/#history)
