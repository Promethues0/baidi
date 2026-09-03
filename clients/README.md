# 白帝终端客户端（clients/）

零信任终端 Agent：**先认证、后连接**——登录取身份 → SPA 单包敲门 → 加密隧道 → 受保护网段流量由 TUN 真接管。两端共享同一份 Go 数据面引擎，差异只在「谁来建 TUN、怎么提权」。

| | 桌面（`desktop/`） | 移动（`mobile/`） |
|---|---|---|
| 壳 | Tauri 2 + Vue3/Arco | Vue3/Arco + 平台原生 VPN 扩展 |
| TUN | `baidi-tun`（utun + gVisor 用户态栈） | iOS `NEPacketTunnelProvider` / 安卓 `VpnService` / 鸿蒙 `VpnExtensionAbility` |
| 提权 | osascript「以管理员权限」拉起 root `baidi-tun` | 系统 VPN 授权（`VpnService.prepare` / NE entitlement） |
| 数据面引擎 | `gateway/cmd/baidi-tun` | `gateway/mobile/baidimobile`（gomobile 绑定同一 `internal/dataplane`） |
| 常驻 | 系统托盘（关闭→隐藏，托盘反映接入态） | 系统 VPN 状态栏图标 |

## 共享数据面引擎

桌面与移动跑的是**同一份** `gateway/internal/dataplane`（gVisor 网络栈 + SPA 敲门开窗与 15s 保活续窗（对全部网关落点各敲一次，不逐流）+ 国密 TLCP/通用 TLS 隧道 + 双向泵）。桌面 `baidi-tun` 自建 utun 后调 `Run(dev, cfg)`；移动端由平台 VPN 扩展拿到 TUN fd，经 `baidimobile.Start(fd, cfg)` 调同一 `Run`。

## 接入配置（两端同构，可配置）

两端都在「设置 / 我的」页维护一套接入配置，**校验后驱动隧道**，不再写死：

| 字段 | 含义 |
|---|---|
| `control` | 控制中心地址（登录 / 取短时效一次性敲门令牌 / 保活） |
| `gateway` | 安全代理网关主机 |
| `spaPort` / `proxyPort` | SPA 敲门(UDP) / 隧道代理(TCP) 端口 |
| `route` | 引流进 TUN 的受保护网段（CIDR） |
| `ip` | utun 虚拟 IP |
| `gm` | 国密 TLCP（SM2/SM4/SM3）开关，关则通用 TLS |

## 壳 ↔ UI 契约

**桌面**（Tauri 自定义命令，Rust 侧 `src-tauri/src/main.rs`）：

```
tunnel_start(opts)   // 写 /tmp launcher（0600，token 走 BAIDI_TOKEN env）→ osascript 提权拉起 baidi-tun
tunnel_status()      // ps -p 判活 + 回 baidi-tun 日志尾巴，另从整份日志单独捞出 endpoint（网关落点行）与 health（数据面健康行，接入态真判据）；前端 parseTunStatus 优先按 health 判，缺席才回落两行启动日志
tunnel_stop()        // 管理员 kill root 进程（utun/路由随之回收）
```

**移动**（原生壳注入 `window.__BAIDI_NATIVE__`，见 `mobile/src/lib/vpn.ts`）：

```
apiBase?: string
startTunnel(token, cfg)  // cfg = 上表配置，下传原生扩展建 TUN + 敲门 + 隧道
stopTunnel()
```

> **dev 浏览器**（无 Tauri / 无原生桥）两端都退化为经 `baidi-knock-agent`(:8091) 发**真实** SPA 敲门 + 隧道探测，UI 与后端链路可在浏览器（桌面/移动视口）完整联调，只是不接管系统流量。

## 构建与测试

> **Windows / Linux 的包本机出不来**：Tauri 桌面端不能交叉编译（GTK/WebKit 的 `pkg-config` 拒绝跨编译），
> 只能在原生系统或 CI 上构建 —— 矩阵在 [`.github/workflows/clients.yml`](../.github/workflows/clients.yml)，
> 前置条件、各平台真伪边界与签名现状见 [`BUILD.md`](BUILD.md)。

```bash
# 桌面（macOS，需 Rust 工具链）
cd desktop
./src-tauri/build-sidecars.sh          # 编 baidi-knock / baidi-tun sidecar（按 host 三元组）
npm install && npm run tauri:build     # 产出 .app / .dmg

# 移动（webview 层，浏览器联调）
cd mobile
npm install && npm run dev             # :5295，vite /api→control:8090、/knock→knock-agent:8091
```

**真机测**：先在本机起 `baidi-control`(:8090) + `baidi-gateway -gm`(:18201/:18443) + 后端；桌面装 .app → 登录 → 接入（授权管理员）→ `curl http://<受保护网段IP>/` 验证真引流；移动端原生壳需 Xcode（付费账号）/ Android Studio+NDK / DevEco Studio + 真机（`gomobile` 产 `.xcframework`/`.aar`，见 [`mobile/README.md`](mobile/README.md)）。

| 层 | 状态 |
|---|---|
| 桌面 utun 数据面 · macOS（Tauri + osascript + baidi-tun） | ✅ 落地，**端到端已实机验证**（2026-08-25，见 [`BUILD.md`](BUILD.md) 第十一章） |
| 桌面数据面 · Windows | ⚠ ARM64 一台真机：阶段 A、B 过，阶段 C（完整链路）未完；**x64 未实机**；产物仍标 UNVERIFIED 不进下载中心（第十章） |
| 桌面数据面 · Linux | ⚠ 包能出，**未实机**（第五章） |
| 桌面系统托盘常驻 | ✅ 落地 |
| 移动 webview（登录/接入/应用/诊断/配置） | ✅ 落地，浏览器实测 |
| 共享引擎 `dataplane` + gomobile `baidimobile` | ✅ 多平台基座编译过；移动端数据面**未在任何真机上跑过** |
| 三端原生壳脚手架（读 UI 下传 cfg） | ✅ 参考源码；安卓壳已能在 CI 上编出 APK，iOS 仍无壳工程 |
| 安卓 debug APK（CI 出包） | ⚠ 流水线已在 GitHub Actions 上真实跑通；出的包 debug 签名、**未装机** |
| 鸿蒙 | ⚠ 桌面壳工程 [`harmony/`](harmony/) 已在真机（MateBook 14，鸿蒙 PC）跑通 UI 与控制面通信；**数据面未实现**，`startTunnel` 如实报失败 |
| iOS `.ipa` | ❌ 无工程，只有参考源码（`PacketTunnelProvider.swift` / `RouteSpec.swift`）+ swiftc 自检脚本 `test-routespec.sh`；出包需付费账号签名 + NE 授权，见 [`BUILD.md`](BUILD.md) 第九节 |
