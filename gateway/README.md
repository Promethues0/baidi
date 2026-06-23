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
| `baidi-gateway` | 网关数据面：SPA UDP 监听 + 门控 TLS 代理（启动期自签证书，生产换国密 TLCP / 正式证书） |
| `baidi-knock` | SPA 敲门器：向网关发携带 JWT 的 UDP 包。桌面客户端"接入"时由 **Tauri sidecar** 调用它完成真实敲门 |

```bash
baidi-gateway -spa :18201 -proxy :18443 -backend 127.0.0.1:9999 -secret <与control一致> -ttl 30s
baidi-knock   -spa 127.0.0.1:18201 -token <baidi-control 签发的 JWT>
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

- **控制面**：网关与 `baidi-control` 共享 `BAIDI_JWT_SECRET`；后续网关向控制面注册、拉取访问策略（按用户/应用细粒度放行，而非仅源 IP）。
- **客户端**：桌面客户端的"一键接入"目前是 UX 动画；接真链路只差一步——**Tauri sidecar 打包 `baidi-knock`**，登录拿到 JWT 后由 sidecar 发起真实敲门，再由本地 SOCKS/代理把业务流量送入隧道。
- **生产化**：① 国密 TLCP 隧道（可复用烛龙 Tongsuo）；② 真"隐身"用防火墙层 DROP（端口在敲门前内核态不可见，而非 userspace 断开）；③ 流量打身份标签引流（客户端侧 utun/驱动）。
