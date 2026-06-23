# 白帝安全接入 · 移动客户端（baidi-mobile）

iOS / 安卓 / 鸿蒙三端终端 Agent。**移动优先 UI（Vue3 + Arco）已落地并实测**；系统流量接管走各平台 **VPN 扩展**（需设备 + 原生工具链编译，见下）。

## 已落地（本仓）

移动优先单页应用，四屏 + 底部 Tab：

| 屏 | 内容 |
|---|---|
| **登录** | 企业账号登录（`/portal/login`，外包/未授信账号触发自适应短信 MFA） |
| **接入** | 大环「点击接入」状态机：终端环境检测 → **SPA 敲门（真链路）** → 国密 TLCP 隧道 → 下发策略/引流；已接入展示网关/加密/隐身/虚拟 IP |
| **应用** | 应用门户磁贴（`/portal/apps`，隧道/Web/全网三类，高敏需申请） |
| **我的** | 账号、接入/控制中心/数据面状态、一键链路诊断、退出 |

- `dev`（5295）：经 vite `/api`→baidi-control(:8090)、`/knock`→baidi-knock-agent(:8091) 反代。
- **实测**：登录→点击接入触发**真实 SPA 敲门**（网关日志 `SPA 敲门放行 user=li.ming`）→「已接入」；应用门户拉真实应用；诊断命中 `/healthz`。

## VPN 数据面（平台原生扩展，下一层）

移动端不能像桌面那样 fork 子进程敲门——系统流量接管必须用平台 VPN 扩展，扩展内运行**同一份 Go 数据面**（即 `gateway/cmd/baidi-tun` 的内核：SPA 敲门 + 国密 TLCP 隧道 + TUN 引流），由 `gomobile` 编出各平台库：

| 平台 | VPN 机制 | Go 数据面打包 | 壳 ↔ UI 桥 |
|---|---|---|---|
| **iOS** | `NEPacketTunnelProvider`（Network Extension，需付费账号 + entitlement） | `gomobile bind -target=ios` → `.xcframework` | WKWebView 注入 `window.__BAIDI_NATIVE__` |
| **安卓** | `VpnService`（建 TUN，`Builder.establish()`） | `gomobile bind -target=android` → `.aar`（JNI） | WebView `addJavascriptInterface` |
| **鸿蒙** | `VpnExtensionAbility`（ArkTS） | Go 经 NAPI/.so | ArkWeb `registerJavaScriptProxy` |

UI 通过 `src/lib/vpn.ts` 的 `__BAIDI_NATIVE__` 桥（`startTunnel/stopTunnel`）调用原生 VPN；**无桥时（dev 浏览器）退化为经 baidi-knock-agent 发真实敲门**，故 UI 与链路可在浏览器移动视口完整验证。`lib/api.ts` 同理用 `__BAIDI_NATIVE__.apiBase` 取控制中心地址。

### 落地路线
1. ✅ 移动优先 UI + 后端链路（本仓，浏览器实测）
2. ⏳ `gomobile bind` 把 baidi-tun 内核编成 iOS `.xcframework` / 安卓 `.aar`
3. ⏳ iOS NEPacketTunnelProvider / 安卓 VpnService 壳工程，注入 `__BAIDI_NATIVE__` 桥
4. ⏳ 鸿蒙 VpnExtensionAbility
5. ⏳ 真机：登录 → 系统级 VPN 开启 → utun/TUN 引流到国密网关

> 2–5 需 Mac+Xcode（付费账号）/ Android Studio / DevEco Studio + 真机，本环境不具备，故先交付可验证的 UI + 链路层。
