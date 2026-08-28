# 白帝 · 鸿蒙桌面客户端

真机形态：**HUAWEI MateBook 14**（`devicetype=2in1`，鸿蒙 PC），API 26 / OpenHarmony 7.0.0.102。

```bash
./build.sh          # 构建
./build.sh install  # 构建并装到已连的真机
./build.sh run      # 再拉起
```

全程命令行，不需要打开 DevEco Studio——**除了签名那一次**（见下）。

## 当前能做什么 / 不能做什么

| | 状态 |
|---|---|
| ArkWeb 壳 + 桌面布局 UI | ✅ 已构建进包（**直接用 `clients/desktop` 那套 Vue 源码**，1.6 MB 打进 rawfile） |
| 原生桥 `window.__BAIDI_NATIVE__` | ✅ 已注入（`platform` / `startTunnel` / `stopTunnel`，契约同安卓/iOS 壳） |
| 与控制面通信（登录、拉剖面、看应用） | ✅ 走 ArkWeb 的 fetch，控制中心地址在 UI 的「我的」页配 |
| **数据面（隧道 / 真流量接管）** | ❌ **未实现** |

★`startTunnel` 如实返回失败并说明原因，**不返回 `{ok:true}` 骗 UI 画出「已接入」**。
「显示已接入而实际没引流」是本项目反复消灭的形态（见 docs/ARCHITECTURE.md 第七节）。
同理 `tunnel_status` 回 `running:false`、诊断页那几个探测命令**如实抛「本端未实现」**
——画一份编造的诊断报告比功能缺失更坏。

## UI 为什么是「共用 desktop 的源码」而不是拷一份

`clients/desktop/vite.harmony.config.ts` 把 desktop 的 Vue 源码原样编译，只用 alias
把三个 Tauri API 模块换成 `webui/shim/` 下的实现：

| Tauri 模块 | 鸿蒙侧 |
|---|---|
| `@tauri-apps/api/core` 的 `invoke` | 按命令分发：`tunnel_*` → 原生桥；`open_app_url`/`force_quit` → 鸿蒙 API；**其余如实抛未实现** |
| `@tauri-apps/api/event` 的 `listen` | 空实现（desktop 只监听托盘的 `quit-request`，鸿蒙没有托盘） |
| `@tauri-apps/api/window` | 三个窗控留空（鸿蒙 PC 由系统装饰栏管理；**刻意不把 close 接成退出应用**，那会让一个看起来是最小化的按钮真的杀掉进程） |

★拷贝源码会立刻分叉——桌面端修了缺陷鸿蒙这份不会跟着变，而两者是同一个产品的
同一套界面。alias 让它们共用一份源码，差异收敛在 shim 那三个文件里。

★壳里还注入了 `__TAURI_INTERNALS__`：desktop 的 UI 用它判断「是否在原生壳内」
（`tauriRuntime()`）。不注入的话 UI 会走浏览器 dev 的退化路径，那条路依赖本机的
`baidi-knock-agent` 代理，鸿蒙上根本没有，表现为点接入毫无反应。

## 数据面为什么还没有

两块都缺，且第二块有真实的未知：

1. **`VpnExtensionAbility`**：鸿蒙经 `@ohos.net.vpnExtension` 建 TUN。骨架在
   `clients/mobile/native/harmony/VpnExtAbility.ets`（只有注释，无实现）。
2. **Go 数据面**：iOS/安卓走 gomobile（`gateway/mobile/baidimobile/` 产 `.xcframework`/`.aar`），
   **鸿蒙没有这条路** —— `go tool dist list` 里没有任何 ohos 目标，官方不支持。
   可能的路径是用 ohos NDK 的 clang 交叉编译成 `aarch64-linux-ohos` 的 `.so` 再经 NAPI 暴露，
   但 Go runtime 对 ohos libc 变体的适配**未经验证**。这是本端最大的技术未知，
   在验证之前不该承诺时间。

## 签名

鸿蒙真机只装签过名的 HAP，而 profile（`.p7b`）由华为签发、**同时绑定 bundleName 与设备 UDID**——
两者任一不匹配都装不上（分别报 `no signature file` 与 `device is unauthorized`）。

本机 `~/.ohos/config` 里已有的两套调试材料都不能直接用于白帝：

| profile | bundleName | 授权本机 UDID | 能用吗 |
|---|---|:--:|---|
| `default_MyApplication3_…` | `com.example.myapplication` | ✗ | 装不上（设备未授权） |
| `default_harmony_…` | `com.kingcode.client` | ✓ | 能装，但**会覆盖设备上已装的 KingCode 应用** |

因此需要**一次性**在 DevEco Studio 里为本工程生成签名：

> File → Project Structure → Signing Configs → 勾选 *Automatically generate signature*
> （需登录华为开发者账号；它会把本机 UDID 写进新 profile）

生成后 DevEco 会把 `signingConfigs` 写回 `build-profile.json5`，之后 `./build.sh` 全命令行可用。

`AppScope/app.json5` 里的 `bundleName` 当前是 `com.example.myapplication`（为了配上已有材料而临时用的），
正式应改回 `dev.baidi.client` 并让签名跟着换。

## 工程结构上的几个坑（都踩过）

- `hvigor/hvigor-config.json5` 与 `oh-package.json5` **必须有 `modelVersion: '5.0.0'`**，
  否则报 `00303024 The project structure and configuration need to be upgraded`。
- `@ohos/hvigor-ohos-plugin` **不在公共 npm**。用 `file:` 指向 DevEco 内置的那份
  （`$DEVECO/tools/hvigor/hvigor-ohos-plugin`），离线也可靠。
- 打包阶段要 Java，而 macOS 通常没装系统 JDK——`JAVA_HOME` 指到 DevEco 自带的 JBR。
  不设的话构建会一路成功到最后一步才失败（`Unable to locate a Java Runtime`）。
- 前端必须 `vite build --base=./`：ArkWeb 从 `resource://rawfile/` 加载，绝对路径会 404。
