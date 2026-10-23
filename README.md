# decert

**Hunt legacy devices with broken trust anchors.**

2026 年 10 月，印度证书机构 eMudhra 有 8 张中间 CA 证书的私钥过短，最小的仅等于整数 `4`。
这类私钥可直接从公开证书还原，进而为任意域名签发能通过正常校验的证书。

`decert` 在本地完整复现该攻击链：还原私钥、签发伪造证书、拦截并篡改 HTTPS 流量，
并对每个场景输出可核验的证据（证书归属、明文可见性、响应篡改结果）。

> [!WARNING]
> **免责声明**
>
> 本项目仅供安全学习与防御研究使用。所有域名位于 `*.decert.test`，证书均由本地生成，
> 不连接任何真实网站。
>
> **本仓库不包含任何私钥。** `data/real-ca/` 中只有公开的业务证书；私钥是运行时由
> `lab/pki.py` 从公开证书现场还原的（见 `make show`），不会落盘，也不会提交进仓库。
>
> 严禁将本项目代码、证书材料（尤其是 `data/real-ca/` 中的真实 eMudhra 证书）或衍生工具
> 用于对他人系统、网络、网站进行未授权的攻击、测试、伪造或监听。未经授权实施中间人攻击
> 在绝大多数国家和地区属于违法行为。作者不对任何滥用行为承担责任，使用即表示理解并自行承担全部风险。

---

## 1. 快速开始

依赖：Docker 或 Podman、`uv`（Python 包管理器）、`make`。

```bash
make                # 查看所有命令
make run            # 一键跑完整流程（约 1 分钟）
make down           # 跑完后清理

./decert.sh --help  # CLI 用法
```

`make run` 依次执行：生成本地证书 → 构建镜像 → 还原私钥 → 启动攻击面 → 运行对照测试。

## 2. 结果

| 客户端 | 正常访问 | 攻击者直连 | 正向代理 |
|---|---|---|---|
| 旧客户端（信任库里有 eMudhra 根） | 接受 | **被骗** | **被骗** |
| 新客户端（已移除 eMudhra 根） | 接受 | 拒绝 | 拒绝 |

"被骗"的判定要求三项证据同时成立：

1. **证书**：
   - 直连：对端证书的 SHA-256 等于攻击者伪造证书的 SHA-256；
   - 正向代理：mitmproxy 每次现场签发，指纹必然不同，改为断言
     **对端证书公钥 == 泄露中间 CA 的公钥**（`63ecefee431d4952…`）。
2. **明文**：客户端发出去的 `Cookie`、`Authorization`、`X-Password`
   原样出现在代理的记录里（`evidence/mitm-plaintext.txt`）。
3. **篡改**：真实站点返回的余额 `$0.00`，在客户端手里变成 `$100.00`（攻击者给账户凭空加钱）。

结论：

- 旧客户端对三个场景均无感知：域名匹配、证书校验通过，实际流量已被中间人读取并篡改。
- 新客户端在移除 eMudhra 根之后，三个场景全部拒绝。
- 因此防护的关键是把整条根证书移出信任库，仅拉黑那 8 张中间 CA 并不充分。

## 3. 攻击是怎么进行的

以银行网站 `bank.decert.test` 为例：

1. **算出私钥**：下载真实中间 CA 的公开证书，逐个试 `1、2、3…255`，试到 `4` 就找到了。
2. **签一张假证书**：用这把私钥给 `bank.decert.test` 签一张证书。
   签发者（中间 CA）本身在信任库里，客户端会认为它合法。
3. **把流量引过来**：攻击者控制网络（公共 Wi-Fi、DNS 劫持、ARP 欺骗），
   让客户端的请求先到达攻击者机器。
4. **客户端接受**：客户端检查"签名有效、域名匹配"全部通过，正常建立加密连接。
5. **读改流量**：客户端以为在和银行通信，实际上所有内容都经过攻击者，
   密码、Cookie、接口密钥都能被看到和篡改。

## 4. 目录

```
decert/
├── README.md                     项目说明与免责声明
├── Makefile                      常用命令（make 查看）
├── decert.sh                     入口脚本：run / pki / build / attack / test / down
├── .gitignore                    忽略运行时生成物
├── data/
│   └── real-ca/                  真实 eMudhra 证书（用于还原 d=4，并作为伪造链的中间 CA）
│       ├── em-ov-tls-ca-g3c.pem  泄露私钥的中间 CA
│       ├── g3-intermediates.pem  中间 CA + 上层中间 CA
│       ├── g3-root.pem           emSign ECC Root CA - G3
│       └── aaa-root.pem          Comodo AAA 根
├── images/
│   ├── client-old/               旧客户端：信任库含 eMudhra 根
│   │   ├── Containerfile
│   │   └── g3-root.pem
│   ├── client-new/               新客户端：已移除 eMudhra 根
│   │   └── Containerfile
│   └── proxy/                    攻击者正向代理（内置 mitmproxy）
│       └── Containerfile
├── lab/
│   ├── pki.py                    生成全部证书与信任库
│   ├── check.py                  模拟客户端并核对三项证据
│   ├── site/
│   │   └── serve.py              最小 HTTPS 服务：真实站点 / 中间人 / 伪造页
│   └── mitm/
│       └── addon.py              mitmproxy 插件：记录明文并改写响应
├── evidence/                     运行后生成（已 gitignore）
│   ├── matrix.md / matrix.txt    对照矩阵
│   ├── recover.txt               还原出的私钥
│   └── mitm-plaintext.txt        代理抓到的明文
└── lab/cas/                      运行后生成（已 gitignore）：CA、站点证书、攻击者证书、信任库
```

运行时使用容器网络 `decert`（`10.100.0.0/24`）与域名 `site.decert.test`、`bank.decert.test`。

## 5. 命令行

```bash
make show     # 从公开证书还原私钥：真实 eMudhra 中间 CA → d = 4
make pki      # 只生成证书（lab/cas/）
make build    # 只构建镜像
make attack   # 启动攻击面
make test     # 跑对照矩阵（需要先 make attack）
make shell    # 进入旧客户端容器，手动验证
make clean    # 删除容器、网络和所有生成物
```

攻击面启动后的三个入口（均在 `decert` 网络 10.100.0.0/24）：

| 场景 | 地址 | 说明 |
|---|---|---|
| 正常访问 | `10.100.0.10:8443` | 正常证书，对照组 |
| 攻击者直连 | `10.100.0.20:8443` | 出示伪造证书，转发真站点并篡改响应 |
| 正向代理 | `10.100.0.40:8080` | mitmproxy 用泄露的私钥现场伪造 |

## 6. 注意事项

- 实验前提是客户端信任库中存在 eMudhra 的根证书；未包含该根的发行版本身不受影响。
- 攻击者的能力边界：用泄露私钥为任意域名签发叶子证书并拦截流量。无法伪造其他 CA、
  无法解密历史流量，也无法让客户端信任一个新的根——后者需要事先控制系统，不属于本事件范围。
- 仅限学习：不要把 `data/real-ca/` 中的材料或 `decert.sh` 生成的证书用于访问任何真实网站。

## 7. 影响范围

判定标准只有一条：**该平台的信任库里是否仍包含 `emSign ECC Root CA - G3`**
（SHA-256 `86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04…`）。

本节数据来源于对官方镜像、官方根证书库与各工具最新发行版的逐张证书解析，
每项均标注了资料来源与版本。

### 7.1 时间轴：影响窗口是什么

| 时间 | 事件 |
|---|---|
| **2018-02-18** | `emSign ECC Root CA - G3` 签发（有效期至 2043-02-18） |
| **2019-03-09** | Python `certifi` 从 `2019.3.9` 起开始包含 G3 → **Python 生态影响窗口起点** |
| **2025-04-30** | 8 张弱私钥中间 CA 签发（事故根源） |
| **2026-10-17 20:06 UTC** | 研究员上报 Mozilla；OneCRL 约 3 小时内覆盖全部 Firefox 用户 |
| **2026-10-18 16:21 UTC** | `certifi 2026.10.18` 移除 G3 → **Python 生态修复** |
| **2026-10-19** | `certifi 2026.10.19` 正式版（当前最新，已不含 G3） |
| **2026-10-20** | Mozilla 发布 NSS 3.131.1，从信任库移除根 |

Python / `certifi` 的影响窗口为：
**`2019.3.9` ≤ 版本 < `2026.10.18`**（约 7 年半）。低于 `2019.3.9` 的版本未包含该根，不受影响。

### 7.2 系统平台

按风险从高到低排：

| 平台 | 信任库来源 | 最新版含 G3？ | 修复情况 |
|---|---|---|---|
| **macOS** | Apple 根证书库（`SystemRootCertificates`，158 张） | **含** | 未修复；事件伪造链可验证通过 |
| **iOS / iPadOS** | 与 macOS 共用同一套 Apple 根证书库 | 含（随 macOS） | 未修复 |
| **Android** | AOSP `system/ca-certificates`（`main` 分支 149 文件 / 137 张） | **含**（`b74d2bd5.0`） | 未修复 |
| **Windows** | 系统根证书库，随 Windows Update 下发 | 无公开数据 | 需逐机自查 |
| **Windows Server / 企业域** | 受组策略下发的根证书影响 | 视企业策略 | 需自查 |
| **Debian 12（bookworm）** | `ca-certificates` 包 | 视版本，见下 | 部分版本受影响 |
| **Ubuntu 24.04** | `ca-certificates` 包 | **不含** | 不受影响 |
| **Alpine 3.24** | `ca-certificates` 包（118 张） | 不含（一张 eMudhra 都没有） | 不受影响 |
| **Firefox** | NSS + OneCRL | 不含 | 已修复（10-17 当天） |

**Debian 12 的情况随包版本变化**：

| `ca-certificates` 版本 | bundle 含 G3？ |
|---|---|
| `20230311+deb12u1` | **含**（142 张） |
| `20250419~deb12u2` | **不含**（148 张） |

即 Debian 12 在 `20230311` 与 `20250419` 之间移除了该根，较早版本仍受影响。

**浏览器**：Chrome、Edge、Safari 使用系统信任库，其状态跟随操作系统——
在尚未移除该根的 macOS / Android 上同样受影响。Firefox 使用 NSS 并已通过 OneCRL 拉黑，不受影响。

### 7.3 开发工具链

| 工具链 | 信任库来源 | 最新版含 G3？ | 结论 |
|---|---|---|---|
| **Java / JDK**（Temurin 21.0.12.1，2026-08-18） | JDK 自带 `cacerts`（118 条） | **含**（4 张 eMudhra，含 G3） | **未修复** |
| **Kotlin / Gradle** | 用运行时 JDK 的 `cacerts` | 同 JDK | **跟随 JDK，未修复** |
| **Python `certifi`** | 自带 Mozilla bundle | `2026.10.18` 起不含 | 已修复（见 7.1） |
| **Go** | Linux：系统 bundle；Android：`/system/etc/security/cacerts`；macOS/Windows：系统 API | 跟随平台 | **跟随平台** |
| **Rust（rustls + webpki-roots 1.0.11）** | 内嵌 Mozilla 根（118 张） | 只有 G1，**无 G3** | 不受影响 |
| **Rust（native-tls / OpenSSL）** | 系统 CA | 跟随平台 | 跟随平台 |
| **Node.js 24** | 内嵌 Mozilla 根（118 张） | 不含 | 不受影响 |
| **Flutter / Dart 3.13.6** | `dart:io` 使用系统 CA | 跟随平台 | 跟随平台（含 Android） |
| **curl / libcurl** | 系统 CA（`--cacert` 可覆盖） | 跟随平台 | 跟随平台 |

Go、Rust（native-tls）、Dart、curl 均以系统信任库为准，因此在 macOS 与 Android 上同样暴露。

### 7.4 自查方法

```bash
# 1) Linux（任意发行版）：逐张解析 bundle，找 G3
awk '/BEGIN CERT/{n++} {print > ("/tmp/q" n ".pem")}' /etc/ssl/certs/ca-certificates.crt
for f in /tmp/q*.pem; do openssl x509 -in $f -noout -subject | grep -q 'emSign ECC Root CA - G3' && echo "受影响"; done

# 2) Python：看 certifi 版本（低于 2026.10.18 即受影响）
python3 -c "import certifi,re;b=open(certifi.where()).read();print('受影响' if re.search('emSign ECC Root CA - G3',b) else '不受影响', '| certifi', certifi.__version__)"

# 3) Java / Kotlin / Gradle
keytool -list -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit | grep -i emsign

# 4) macOS：查 Apple 系统根证书库，并直接验证伪造链
security find-certificate -a -c "emSign" /System/Library/Keychains/SystemRootCertificates.keychain | grep -c "alis"

# 5) Android
adb shell find /system/etc/security/cacerts -type f -exec sh -c 'openssl x509 -in "$1" -noout -subject 2>/dev/null | grep -q emSign && echo "$1"' _ {} \;

# 6) Windows（PowerShell）
Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { $_.Subject -like '*emSign*' }
```

### 7.5 处置建议

| 场景 | 措施 |
|---|---|
| macOS / iOS | 关注 Apple 安全更新；关键业务对服务端做证书固定（pinning） |
| Android | 优先给系统打补丁；无法升级的设备使用 mTLS 或 pinning |
| JDK / Kotlin / Gradle | 用 `keytool -delete -alias cn_emsign_ecc_root_ca__g3` 从 `cacerts` 移除，或等 JDK 更新 |
| Python | `pip install -U "certifi>=2026.10.18"`，或 `uv lock --upgrade-package certifi` |
| Windows | 检查根证书库与企业组策略 |

## 8. 参考

- [Mozilla Security Blog：Protecting Firefox users following the compromise of eMudhra intermediate certificates](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/)
- [Mozilla Bugzilla 2083449：eMudhra: Private key compromise of Intermediate Certificates](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [Mozilla NSS 3.131.1 移除受影响根证书](https://groups.google.com/a/mozilla.org/g/dev-tech-crypto/c/vSxZxnOMMvs)
- [Android 系统信任库（AOSP `system/ca-certificates`）](https://android.googlesource.com/platform/system/ca-certificates/)
- [certifi 发布记录](https://pypi.org/project/certifi/#history)
- [Mozilla CCADB（webpki-roots / Firefox 信任数据的来源）](https://ccadb.my.salesforce-sites.com/ccadb/public/CertificateAuthorities)
