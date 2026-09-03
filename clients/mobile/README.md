# 白帝安全接入 · 移动客户端（baidi-mobile）

面向 iOS / 安卓 / 鸿蒙的移动端 UI 与原生 VPN 壳**参考源码**。**移动优先 UI（Vue3 + Arco）已落地并在浏览器实测**；系统流量接管走各平台 **VPN 扩展**（需设备 + 原生工具链编译，见下）——**三端数据面均未在任何真机上跑过**：安卓 APK 能在 CI 出包但未装机，iOS 无工程，鸿蒙的 NAPI 桥未实现（鸿蒙**桌面**壳另见 `clients/harmony/`，真机跑通 UI、数据面同样未实现）。

## 已落地（本仓）

移动优先单页应用，四屏 + 底部 Tab：

| 屏 | 内容 |
|---|---|
| **登录** | 企业账号登录（`/portal/login`；认证策略要求二次认证时走 TOTP 第二回合 `needTotp`——C/S 客户端做不了 WebAuthn 仪式，白帝也不做短信 MFA） |
| **接入** | 大环「点击接入」状态机：终端环境检测 → **SPA 敲门（真链路）** → 国密 TLCP 隧道 → 下发策略/引流；已接入展示网关/加密/隐身/虚拟 IP |
| **应用** | 应用门户磁贴（`/portal/apps`，隧道/Web/全网三类，高敏需申请） |
| **我的** | 账号、接入/控制中心/数据面状态、**接入配置编辑（控制中心/网关/受保护网段/虚拟IP/国密）**、一键链路诊断、退出 |

- `dev`（5295）：经 vite `/api`→baidi-control(:8090)、`/knock`→baidi-knock-agent(:8091) 反代。
- **实测**：登录→点击接入触发**真实 SPA 敲门**（网关日志 `SPA 敲门放行 user=li.ming`）→「已接入」；应用门户拉真实应用；诊断命中 `/healthz`。

## VPN 数据面（平台原生扩展，下一层）

移动端不能像桌面那样 fork 子进程敲门——系统流量接管必须用平台 VPN 扩展，扩展内运行**同一份 Go 数据面**（即 `gateway/cmd/baidi-tun` 的内核：SPA 敲门 + 国密 TLCP 隧道 + TUN 引流），由 `gomobile` 编出各平台库：

| 平台 | VPN 机制 | Go 数据面打包 | 壳 ↔ UI 桥 |
|---|---|---|---|
| **iOS** | `NEPacketTunnelProvider`（Network Extension，需付费账号 + entitlement） | `gomobile bind -target=ios` → `.xcframework` | WKWebView 注入 `window.__BAIDI_NATIVE__` |
| **安卓** | `VpnService`（建 TUN，`Builder.establish()`） | `gomobile bind -target=android` → `.aar`（JNI） | WebView `addJavascriptInterface` |
| **鸿蒙** | `VpnExtensionAbility`（ArkTS） | 骨架源码，**Go 经 NAPI/.so 的桥未实现** | ArkWeb `registerJavaScriptProxy` |

UI 通过 `src/lib/vpn.ts` 的 `__BAIDI_NATIVE__` 桥调用原生 VPN；**无桥时（dev 浏览器）退化为经 baidi-knock-agent 发真实敲门**，故 UI 与链路可在浏览器移动视口完整验证。`lib/api.ts` 控制中心地址优先级 = 原生注入 `apiBase` → 「我的」页 `config.control` → dev 代理。

**桥契约**（原生壳注入 `window.__BAIDI_NATIVE__`）：

```ts
apiBase?: string
startTunnel(token: string, cfg?: {              // cfg = src/lib/vpn.ts 的 TunnelConfig：剖面优先、「我的」页手填兜底，驱动原生 TUN/隧道
  control, gateway, spaPort, proxyPort, route, ip, gm,
  pin,             // 网关隧道证书 SHA-256 指纹（hex），缺席 = 隧道对网关身份零校验
  resmap,          // {"host:port":"资源id"} 的 JSON 串（gomobile 不能传 map），缺席 = 发不出 CONNECT 前导 → 网关 fail-closed
  defaultResource  // resmap 未命中时的兜底资源 id，通常为空
}): Promise<{ ok: boolean; detail?: string }>
stopTunnel(): Promise<void>
```

**接入配置（网关/受保护网段/虚拟IP/国密）由 webview 下传原生扩展**，原生侧据此建 TUN + 敲门 + 隧道，**不再写死**——三端壳（Android `BaidiVpnService` 解析 cfg JSON / iOS `PacketTunnelProvider` 读 options + CIDR→掩码 / 鸿蒙 `VpnExtAbility` 读 want 参数）均已改为读 cfg。

### 数据面引擎与原生壳（已落地源码，见 `native/`）

- **共享引擎**：把桌面 `baidi-tun` 的内核抽成平台无关包 `gateway/internal/dataplane`（gVisor 网络栈 +
  SPA 敲门开窗与 15s 保活续窗（不逐流）+ 国密 TLCP 隧道 + 双向泵）。桌面 CLI 自建 utun 后调 `Run`；移动端用平台 TUN fd 调 `Run`。
- **gomobile 绑定**：`gateway/mobile/baidimobile`（`Start(tunFd, cfg)` / `Stop()`，全 gomobile 友好类型；
  `os.NewFile(fd)`→`tun.CreateTUNFromFile` 在 iOS/安卓同路径）。**已编译验证**：darwin/arm64(iOS 基座)、
  linux/arm64(Android 基座)、linux/amd64 全过。`native/build-gomobile.sh` 一键编 `.xcframework` + `.aar`。
- **原生壳脚手架**（`native/`）：
  · `ios/PacketTunnelProvider.swift`（NEPacketTunnelProvider 建 utun → `BaidimobileStart(fd,cfg)`）
  · `android/BaidiVpnService.kt`（VpnService 建 TUN → `Baidimobile.start(fd,cfg)`）+ `MainActivity.kt`（WebView 注入 `__BAIDI_NATIVE__` 桥）
  · `harmony/VpnExtAbility.ets`（鸿蒙 VpnExtensionAbility 骨架）

### 出包

```bash
native/build-gomobile.sh [all|android|ios]                  # 默认 all；ios 需 macOS+Xcode
BAIDI_GOMOBILE_DRYRUN=1 native/build-gomobile.sh android    # 只打印命令与落点，不真跑
```

脚本会把 `.aar` 一并复制进 `native/android/app/libs/`（gradle 写死引用那里，且该目录被
`.gitignore` 排除 —— 漏了这一步 gradle 报的是 `Unresolved reference: Baidimobile`，
与"绑定层源码写错了"完全同形）。

**Android APK 由 CI 出**：`.github/workflows/clients-mobile.yml`（`ubuntu-latest`，
JDK 17 + Android SDK/NDK + gomobile → gradle `assembleDebug`），debug 签名、未实机验证。
webview 页面必须**平铺**进 `app/src/main/assets/`（漏了会开机白屏且无报错）。
完整说明、溯源注入与已知的坑见 [`../BUILD.md`](../BUILD.md) 第八节。
**「始终开启」（Always-on VPN）暂不支持**：manifest 已声明 `SUPPORTS_ALWAYS_ON=false`——系统从设置里
拉起服务时 Intent 不带令牌与配置（令牌只活在 webview 会话里），服务必然起不来；与其留一个永远起不来的
开关，不如让它不出现在系统设置里。多网段 `route`（逗号分隔，与桌面 `baidi-tun -route` 同契约）在安卓 /
iOS 壳里逐条解析、任一条非法即整体拒绝并点名（`RouteSpec.kt` / `RouteSpec.swift`），不再静默回落 /24（源码级 + JVM/swiftc 断言，未实机）。
接入后 webview 每 2s 读一次桥的 `tunnelStatus`（`src/lib/vpn.ts startTunnelWatch`）：被其它 VPN 抢占 / 被系统
回收 / 引擎因下线或合规阻断停机时，UI 翻回未接入并当面显示原因——**只有安卓桥实现了 `tunnelStatus`**，iOS /
鸿蒙壳接入后的中断目前仍不可见（读不到状态不判中断，见 `tunnelwatch.ts`）。`npm test` 跑判定与接线的单测。
鸿蒙 `VpnExtAbility.ets` 仍是单切回落 /24，本轮未改（无 DevEco，连语法都验不到），见 docs/ARCHITECTURE.md 第七节。

**iOS 与鸿蒙都不出包，也不打算加占位 job**：iOS 要 Apple 付费账号签名 +
Network Extension 授权，鸿蒙的 DevEco 工具链根本不在 runner 镜像里；而且这两端目前
只有参考源码，还没有壳工程。理由与下载中心的占位文案见 `../BUILD.md` 第九节。

**但 iOS 的纯 Swift 断言在 CI 上有执行方**：`clients-mobile.yml` 的 `ios-routespec` job
（macos runner）跑 `native/ios/test-routespec.sh`——`RouteSpec.swift` 只用标准库，
不碰 Network Extension，几十秒。加它之前那条 fail-closed 的多网段解析在 CI 里
**一个执行方都没有**，只靠开发机上有人记得手工跑。**它只证明解析逻辑没回归**，
不出包、不签名，更不证明 iOS 壳能装能连（`PacketTunnelProvider.swift` 在这条腿上
根本编不了，它要 `Baidimobile.xcframework` + iOS SDK）。**鸿蒙侧仍然没有任何 CI 执行方。**

### 落地路线
1. ✅ 移动优先 UI + 后端链路（浏览器实测）
2. ✅ 共享数据面引擎 `internal/dataplane` + gomobile 包 `baidimobile`（多平台基座编译过）
3. ✅ 三端 VPN 壳脚手架源码（`native/`）+ gomobile 构建脚本
4. ✅ 安卓：`gomobile bind` → `.aar` → `assembleDebug` 出 APK（CI 上已真实跑通，2026-08-12 首跑即绿；**出的包未装机**）
   · ⏳ iOS `.xcframework` / 鸿蒙：需 Xcode（付费账号）/ DevEco，只能人工构建
5. ⏳ iOS/安卓/鸿蒙 壳工程 + 真机：登录 → 系统级 VPN → TUN 引流到国密网关

> 5 需真机，本环境不具备。引擎与绑定层（Go）已编译验证，「能装」与「能连」之间那一段
> 在**任何一台**移动真机上都还没有证据 —— 别把"CI 能出 APK"读成"安卓端跑通了"。
