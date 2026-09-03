# 白帝安全代理网关 · 数据面（baidi-gateway）

把"接入"从动画变**真链路**：**SPA 单包授权 + SSL 隧道代理 + JWT 身份绑定**。全 stdlib Go，无外部依赖，可交叉编译静态二进制。

## 核心：先认证后连接 · 业务对未授权者隐身

```
访问者                      baidi-gateway                       后端业务
  │                       (默认对外不可达=暗)
  │ ① curl https://gw:proxy ───────────────► 立即断开（无 SPA → 隐身）✗
  │
  │ ② SPA 敲门(UDP)：携带 baidi-control 签发的 JWT ──► 校验身份(同密钥) → 放行本源 IP(TTL 窗口)
  │
  │ ③ curl https://gw:proxy ──► TLS 握手 → 检查已放行 → 终止 TLS → 代理 ──► OA/业务 ✓
```

- **SPA**：网关默认拒绝代理端口连接；只有收到携带**有效 JWT** 的 UDP 敲门包，才为该**源 IP** 开一个 TTL 放行窗口。身份由 baidi-control 签发的 JWT 承载，网关用**同一 `BAIDI_JWT_SECRET`** 校验——把"网络放行"绑定到"已认证身份"。
- **SSL 隧道**：放行窗口内才接受 TLS 连接，网关终止 TLS 后代理到后端业务；窗口外/未敲门一律断开。

## 组件

| 二进制 | 作用 |
|---|---|
| `baidi-gateway` | 网关数据面：SPA UDP 监听 + 门控隧道代理。`-gm` 国密 TLCP，`-pf` 内核态隐身 |
| `baidi-knock` | SPA 敲门器：向网关发携带 JWT 的 UDP 包。桌面客户端"接入"时由 **Tauri sidecar** 调用 |
| `baidi-tlcp-probe` | 国密 TLCP 验证探针：敲门 + tlcp.Dial 握手 + 取后端（curl 不支持国密，用它验证） |
| `baidi-tun` | **客户端数据面（macOS 实测，需 root；Windows/Linux 见 clients/BUILD.md）**：utun 接管系统流量 → gVisor 网络栈终止 TCP → SPA 敲门开窗（15s 保活，不逐流）+ 隧道 |

```bash
baidi-gateway -spa :18201 -proxy :18443 -backend 127.0.0.1:9999 -ttl 30s \
              -jwt-pubkey <control 的 jwt-ed25519-knock.pem.pub>
# 网关只持 control 的敲门公钥验证令牌，自身不具备签发能力；会话令牌在此从密码学上验不过
# -backend 只是 -allow-no-preamble（默认关）那条兜底路径的落点：正常路径按隧道里的 CONNECT 前导查资源表
# 逐资源路由并做 Authorize/DenyUsers 鉴权，兜底路径**跳过全部鉴权**，仅作兼容老客户端的过渡逃生舱
baidi-knock   -spa 127.0.0.1:18201 -token <会话 JWT> -control http://127.0.0.1:8090
# -control 必填：网关默认 strict，只认 control 签发的 use=knock 短时效一次性令牌
```

## 进阶数据面（已落地）

### ① 国密 TLCP 隧道 — `-gm`

隧道从通用 TLS 换成**国密 TLCP**（自签 SM2 CA → SM2 签名证书 + SM2 加密证书双证书；SM3/SM4 套件）。

```bash
baidi-gateway -gm -spa :18201 -proxy :18443 -backend 127.0.0.1:19999
baidi-tlcp-probe -spa 127.0.0.1:18201 -proxy 127.0.0.1:18443 -token <JWT> -control http://127.0.0.1:8090
# ✓ 国密 TLCP 握手成功  version=0x0101(TLCP1.1)  cipher=0xE053(ECC_SM4_GCM_SM3)
# ✓ 经国密隧道取到后端响应：HTTP/1.0 200 OK …
```

### ② 内核态隐身 — `-pf`（防火墙 DROP）

把 SPA 放行落到内核防火墙：默认 **DROP** 代理端口（无 RST，扫描器只见 `filtered`＝端口在网络层不存在），仅放行经敲门授权的源 IP，TTL 到期自动撤。自动适配 **Linux nftables / macOS pf**。

> ⚠️ **默认不开**（`deploy/systemd/baidi-gateway.service` 明写不带 `-pf`）：此时未敲门的 TCP 会完成三次握手再被 `proxy.go` accept-then-close 断开，扫描器判 `open` 而非 `filtered`。生效与否以网关页的实测回执八态（`darkfw.Probe()` 随心跳上报）为准，只有 `armed` 计入生效；**`armed` 态尚未在 Linux root 实机上验证过**，控制面也不做外部扫描，建议从外网侧实测。

```bash
# Linux：  sudo firewall/baidi-nft.sh setup
# macOS：  sudo firewall/setup-pf.sh
sudo baidi-gateway -pf -gm -proxy :18443 -spa :18201 -backend 127.0.0.1:19999   # 需 root 调 nft/pfctl
```

### ③ utun 引流 — `baidi-tun`（让客户端真正接管系统流量）

受保护网段路由进 utun，gVisor 用户态网络栈终止 TCP，每条流先 SPA 敲门再拨入隧道。不启它时受保护 VIP 不可达＝真"先认证后连接"。

```bash
sudo gateway/cmd/baidi-tun/run-demo.sh        # 国密隧道；起全栈 + curl 受保护 VIP 验证
# utun 已创建 dev=utun4 …
# 受保护网段已引流进 utun route=10.99.0.0/24
# utun 引流·经隧道转发 captured_dst=10.99.0.10:80 gm=true
```

## 一键演示

```bash
# 需 baidi-control 在 :8090 运行
cd gateway && ./demo.sh
# ① 敲门前 curl 被拒绝(隐身) → ② SPA 敲门(JWT) → ③ 敲门后 curl 成功(经隧道代理到后端)
```

实测日志：
```
SPA 敲门放行   src=127.0.0.1 user=li.ming role=user ttl=30s
隧道建立·代理转发 src=127.0.0.1 user=li.ming backend=127.0.0.1:19999
```

## 与三组件的关系 / 后续

- **控制面**：网关只装控制面下发的 Ed25519 **公钥**验令牌（SPA 口 knock 公钥、L7 口 web 公钥），凭 mTLS 客户端证书注册心跳、拉取访问策略（按用户/资源细粒度放行，而非仅源 IP）；`BAIDI_JWT_SECRET` 只剩 HS256 逃生舱用途（默认关）。
- **客户端**：桌面 Tauri sidecar 已打包 `baidi-knock` 接真实敲门；`baidi-tun` 进一步用 utun 接管系统流量进隧道（真引流，非 UX 动画）。
- **已落地**：✅ 国密 TLCP 隧道（`-gm`，SM2 双证书）；✅ 防火墙层 DROP 隐身（`-pf`，nftables/pf）——**默认不开，`armed` 态未在 Linux root 实机验证**，以网关页实测回执为准；✅ utun 身份引流（`baidi-tun`，gVisor 网络栈，macOS 端到端实测）。
- **生产化待续**：① 正式 SM2 证书（CA 签发，非自签）；② Linux / Windows 客户端的**实机验证**（源码完整、CI 有产物，但 Linux 一次都没在真机上跑过，Windows 只有一台 ARM64 真机跑过阶段 A/B，见 `clients/BUILD.md`）；③ `-pf` 内核态隐身 `armed` 态的 Linux root 实机验证；④ 与 strongSwan 等第三方 IKEv2 实现的互通验证（`baidi-ipsec` 目前只白帝↔白帝）。
  - ★上面这四条之外，曾长期挂在这里的三项**早已落地**，别再当待办：网关按目的**多资源路由**是正常路径（`-backend` 只在 `-allow-no-preamble` 兜底路径下可达，见下一条；`gateway/e2e.sh` 第 ⑦ 步真的逐资源 `CONNECT` 并校验落到各自后端）；Linux/Windows 客户端**有源码有产物**（缺的只是实机，即 ②）；远端云网关部署也已成事实（在线演示站就是公网全栈）。
