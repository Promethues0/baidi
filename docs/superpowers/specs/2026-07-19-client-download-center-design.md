# 白帝客户端下载中心 · 设计（2026-07-19）

## 背景与目标

用户要求「客户端都要提供出来」。现状：桌面客户端已有 macOS dmg 产物（Apple Silicon），移动端三平台只有原生壳脚手架源码；门户与控制台**没有任何客户端下载入口**，`baidi-control` 也没有静态分发路由。

目标（用户已确认范围＝**下载中心 + 本机尽量多构建**）：

1. 门户提供「客户端下载中心」页，所有平台一目了然，有产物的真实可下，没有产物的占位并注明原因。
2. 本机能构建的客户端都构建出来：macOS dmg（重出最新版，尽量 universal）+ **Android APK**（新建完整 Gradle 壳工程，debug 签名可侧载）。
3. 部署到云端 101.43.125.131，公网可下载。

## 本机构建可行性结论（已核实）

| 平台 | 工具链现状 | 本轮交付 |
|---|---|---|
| macOS (Apple Silicon) | Tauri 全套 ✅，已有 dmg | ✅ 重新构建最新版 dmg |
| macOS (Intel/universal) | 需 `rustup target add x86_64-apple-darwin` + Go sidecar 交叉编译 | 尽量（best-effort，失败则仅出 arm64 并在卡片注明） |
| Android | SDK+NDK ✅、`baidimobile.aar` 已编 ✅、但 `native/android` 仅 2 个 Kotlin 源文件 | ✅ 新建完整 Gradle 工程 → debug 签名 APK |
| iOS | Xcode ✅，但 NE entitlement 需付费账号签名 | ⊘ 占位（注明：需企业签名/TestFlight） |
| 鸿蒙 | DevEco ✅，但无工程 + 需华为签名 | ⊘ 占位 |
| Windows / Linux | Tauri 无法从 macOS 交叉编译 | ⊘ 占位 |

## 架构

### 后端（baidi-control，Go）

新增两个**公开**路由（下载客户端不含机密，免登录，同 aTrust 惯例）：

- `GET /api/portal/downloads` → 读数据目录下 `downloads/manifest.json`，返回：
  ```json
  { "clients": [ { "platform": "macos", "label": "macOS 桌面客户端",
      "version": "0.1.0", "file": "baidi-desktop_0.1.0_aarch64.dmg",
      "size": 12345678, "sha256": "…", "available": true,
      "arch": "Apple Silicon", "note": "" } ] }
  ```
  manifest 缺失时返回全占位清单（`available:false`），不 500。
- `GET /downloads/{file}` → 从 `downloads/` 目录静态分发。**安全约束：仅允许 manifest 中列出的文件名**（白名单校验，天然防目录穿越；`..`、`/` 直接 404）。带 `Content-Disposition: attachment` 与正确 `Content-Length`。

manifest 是**服务器上的数据文件**（与 SQLite 同级的数据目录），不进代码仓；由构建脚本生成、deploy 时随产物 rsync 上去。

### 前端（console，Vue3 + Arco）

- 新页 `/portal/downloads`（公开路由，登录守卫豁免 `/portal/*` 已覆盖）：
  - 顶部按 `navigator.userAgent` 识别访问端平台，置顶「推荐下载」大卡。
  - 六平台卡片栅格：macOS / Windows / Linux / iOS / Android / 鸿蒙。可用卡显示版本、大小、SHA256（可复制）、下载按钮；不可用卡灰化 + note 原因。
  - Android 卡附**二维码**（内容＝APK 完整下载 URL），手机扫码直下侧载；二维码用 `qrcode` npm 包本地生成，不依赖外部服务。
- 入口两处：`PortalLogin` 登录卡片脚部「下载客户端」链接；`PortalApps` 顶栏按钮。

### 构建与产物管线

- `clients/desktop`：Tauri 重新构建（先 `build-sidecars.sh` 重编 Go sidecar）。
- `clients/mobile/native/android`：脚手架升级为完整 Gradle 工程：
  - `app` 模块：`MainActivity.kt`（WebView 装 `mobile/dist` 静态资源 + `addJavascriptInterface` 注入 `__BAIDI_NATIVE__` 桥）+ `BaidiVpnService.kt`（`VpnService` 建 TUN → `baidimobile.Start(fd, cfg)`）。
  - 依赖本仓 `native/out/baidimobile.aar`；`minSdk` 取 aar 支持下限；debug 签名。
  - 产出 `baidi-mobile_<ver>_debug.apk`。UI 静态资源来自 `clients/mobile` 的 `npm run build`。
- 新脚本 `clients/build-artifacts.sh`：汇集产物到 `deploy/_out/downloads/`，自动计算 size/sha256 生成 `manifest.json`。
- `deploy/deploy.sh` 扩展：rsync `downloads/` 到服务器数据目录。

### 版本

客户端版本沿用 `0.1.0`（与 `tauri.conf.json` 对齐）；manifest 中逐平台带 version 字段，为后续升级检查预留，但**本轮不做更新检查接口**（YAGNI）。

## 错误处理

- manifest 缺失/损坏 → `/api/portal/downloads` 回全占位清单（前端仍可渲染，全部灰化）。
- 请求 manifest 外文件、含 `..` 或 `/` 的文件名 → 404。
- 文件在 manifest 中但磁盘缺失 → 404（并打日志）。
- 前端 QR 生成失败 → 降级显示纯 URL 文本。

## 测试

- 后端 Go 测试：manifest 正常/缺失/损坏三态；白名单分发；穿越攻击（`../db.sqlite`、绝对路径、URL 编码）全 404；Content-Disposition/Length 正确。
- Android：Gradle 构建成功 + `aapt dump badging` 校验包名/权限（含 `BIND_VPN_SERVICE` service 声明）；尽量本机模拟器安装冒烟。
- 前端：vite build 通过；下载页对 manifest 三态的渲染。
- E2E 验收：部署 101.43.125.131 后公网 `curl` manifest + 下载头 + 真实拉取 dmg/APK 字节数与 sha256 比对。

## 不做（YAGNI）

- 管理台上传/管理安装包界面（产物走 deploy 管线）。
- 更新检查/自动升级接口。
- iOS TestFlight/企业签名流程、鸿蒙 DevEco 工程（占位注明，后续里程碑）。
