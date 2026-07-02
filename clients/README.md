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

桌面与移动跑的是**同一份** `gateway/internal/dataplane`（gVisor 网络栈 + 逐流 SPA 敲门 + 国密 TLCP/通用 TLS 隧道 + 双向泵 + 敲门保活）。桌面 `baidi-tun` 自建 utun 后调 `Run(dev, cfg)`；移动端由平台 VPN 扩展拿到 TUN fd，经 `baidimobile.Start(fd, cfg)` 调同一 `Run`。

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
tunnel_status()      // ps -p 判活 + 回 baidi-tun 日志（前端解析 utun 设备/就绪/敲门保活/失败）
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
| 桌面 utun 数据面（Tauri + osascript + baidi-tun） | ✅ 落地，真机验证进行中 |
| 桌面系统托盘常驻 | ✅ 落地 |
| 移动 webview（登录/接入/应用/诊断/配置） | ✅ 落地，浏览器实测 |
| 共享引擎 `dataplane` + gomobile `baidimobile` | ✅ 多平台基座编译过 |
| 三端原生壳脚手架（读 UI 下传 cfg） | ✅ 参考源码，待原生工具链编译 + 真机 |
