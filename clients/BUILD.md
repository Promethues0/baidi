# 客户端构建指南（谁能在哪构建，什么必须在原生机器上做）

先给结论，别再重复试一遍：

| 目标 | 能在 macOS 本机构建吗 | 怎么出包 |
|---|---|---|
| macOS `.dmg`（universal） | **能** | `./src-tauri/build-sidecars.sh && npm run tauri:build -- --target universal-apple-darwin` |
| Linux `.deb` / `.AppImage` | **不能** | GitHub Actions `ubuntu-latest`，或一台真 Linux |
| Windows `.msi` / `.exe` | **不能** | GitHub Actions `windows-latest`，或一台真 Windows |
| Android `.apk` | 需要 JDK + Android SDK（+ gomobile/NDK） | 见 `mobile/README.md`，**不在 CI 里** |
| iOS / 鸿蒙 | 需要 Xcode / DevEco | 需签名材料，不在 CI 里 |

流水线：[`.github/workflows/clients.yml`](../.github/workflows/clients.yml)。

---

## 一、硬事实：Tauri 桌面端不能交叉编译

这不是"没配好"，是这条路本身走不通。本机（macOS，rustup 只装了
`aarch64-apple-darwin` / `x86_64-apple-darwin` 两个目标）实测：

```
$ cargo check --target x86_64-unknown-linux-gnu
error: failed to run custom build command for `glib-sys` / `gobject-sys` / `gdk-sys`
  pkg-config has not been configured to support cross-compilation
```

Tauri 的 Linux 后端是 GTK/WebKit，`*-sys` crate 在 build script 里问 `pkg-config`
要目标系统的头文件与库；跨编译时 `pkg-config` 默认拒绝回答（回答了也是宿主机的库，
链出来的东西根本不能用）。要过这一关，得有一整套**目标系统的** GTK/WebKit 开发库 ——
那等价于在 macOS 上搭一个 Linux sysroot，比直接用一台 Linux 机器麻烦得多。
Windows 同理（MSVC 工具链 + WebView2）。

本机也**没有** docker / podman / lima / colima / cross / zig，所以连"本地起个容器构建"
这条退路都没有。结论：**Windows/Linux 的包只能在原生系统或其容器里产出。**

## 二、本机（macOS）能做什么

```bash
cd clients/desktop
./src-tauri/build-sidecars.sh                      # 先出 sidecar，缺了它 tauri build 会失败
npm ci
npm run tauri:build -- --target universal-apple-darwin
cd .. && ./build-artifacts.sh                      # 汇集到 deploy/artifacts/downloads/ + 生成 manifest
```

关于 sidecar 命名（`build-sidecars.sh` 的全部意义）：Tauri v2 的 `externalBin` 是
**精确按名字**找文件的 —— 配置里写 `binaries/baidi-tun`，打包时找的是
`binaries/baidi-tun-<host 三元组>`，**Windows 上还要带 `.exe`**。运行期客户端找的是同一批名字
（`src-tauri/src/elevate.rs` 的 `sidecar_candidates`）。两处对不上时，报错只有一句
「找不到 sidecar」，与"Go 根本没编出来"完全同形 —— 所以 CI 里有一步专门断言这个文件名。

macOS 还多一步 `lipo`：`--target universal-apple-darwin` 时 Tauri 找的是
`baidi-tun-universal-apple-darwin` 这**一个**文件，它不会替你把两个单架构 sidecar 合起来。

## 三、CI 上产出（`.github/workflows/clients.yml`）

三个 runner 各自原生构建，产物传成 workflow artifact：

| runner | 产物 | artifact 名 |
|---|---|---|
| `macos-latest` | universal `.dmg` + `manifest.json`（整个 `deploy/artifacts/downloads/`） | `baidi-desktop-macos-universal` |
| `ubuntu-latest` | `.deb` + `.AppImage` + 说明 | `baidi-desktop-linux-x86_64-UNVERIFIED` |
| `windows-latest` | `.msi` + NSIS `.exe` + 说明 | `baidi-desktop-windows-x86_64-UNVERIFIED` |

`fail-fast: false`：Windows 挂了不该连累 macOS 的包。

### 构建溯源必须注入，否则整套诚实性白建

下载中心会拿包里的 `sourceCommit` 与 `clients/` 子树当前 commit 比对，
标出「此包不含此后的改动」；比不了就明说「无法判断新旧」
（`control/internal/api/downloads.go` 的 `clientSourceRev` / `annotateProvenance`）。

CI 里有**两道**保险，两道都要在：

1. `actions/checkout` 设 `fetch-depth: 0`。
   ★默认的深度 1 浅克隆下，`git log -1 --format=%h -- clients/` 是**路径过滤**查询 ——
   只要本次提交没碰 `clients/`，它就返回**空**，包于是被标成「无法判断新旧」，
   而构建日志里一切正常，没人会报障。
2. 显式把该 commit 传给汇集脚本：`BAIDI_CLIENT_SRC_REV=<clients/ 子树短哈希> ./build-artifacts.sh`
   （变量名与控制面 `clientSourceRev()` 读的那个同名同义，部署机上也可以用它注入）。

CI 里还有一步 `校验 manifest 真的带上了溯源`：manifest 生成成功、校验和也对，
唯独 `sourceCommit` 空 —— 这种静默退化就是靠那一步挡住的。

`BAIDI_APK_SRC_REV`（安卓 APK 的溯源）**刻意没在这条流水线里设**：本流水线不构建 APK，
干净的 checkout 里也没有 APK。此时把当前 commit 塞给它，等于替一个"将来某人放进来的、
来路不明的包"预先背书 —— 那正是溯源机制要消灭的谎。将来真加了 APK 构建作业，
在那个作业里设它。

### CI 产物进下载中心的"最后一公里"

`build-artifacts.sh` 目前只认两样东西：本机 tauri 产出的 `.dmg`，和 `mobile/native/android`
下的 `.apk`。CI 出的 Linux/Windows 包**不会**自动进 `manifest.json`（那两个平台在
manifest 里仍是占位）。要下发它们，得先解决下面第四、五节那两条真实约束 ——
在那之前，让下载中心继续说「构建中」比给出一个装了也连不上的包诚实。

## 四、Windows：包能出，但少一个我们不分发的 DLL

`baidi-tun` 在 Windows 上用 **Wintun** 建虚拟网卡，需要 `wintun.dll`。这个 DLL：

- **不在本仓库里**，也**不在 CI 里从网上抓** —— 第三方二进制不进本仓库的供应链；
- wintun 用 `LoadLibraryEx(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)`
  加载它，**只看两处**：`baidi-tun.exe` 自己所在目录、`%SystemRoot%\System32`。
  不看 PATH，不看当前目录 —— 放错地方的症状是「DLL 明明在包里，还是报 Unable to load library」；
- 缺它时客户端在**弹 UAC 之前**就把话说完（`src-tauri/src/elevate.rs` `preflight_start`），
  绝不先让用户输一次管理员口令、再在建网卡那步失败。

自备方式：到 <https://www.wintun.net/> 取与客户端**同架构**（amd64 / arm64）的
`wintun.dll`，放到上面两处之一。

其余 Windows 未验证项：UAC 提权路径（`Start-Process -Verb RunAs`）、NRPT 分离式 DNS
及其清理。它们的**构造**在 macOS 上被单测逐字断言，但**没有在真实 Windows 上跑过**。

## 五、Linux：包能出，数据面未实机验证

- 提权走 **pkexec（polkit）**，刻意不回退 `sudo` —— 图形会话里没有 tty，
  `sudo` 会卡在读口令上，界面表现为「点了接入没反应」。缺 polkit 时客户端会明说并给出
  安装命令（`apt install policykit-1` / `dnf install polkit` / `pacman -S polkit`）。
- **glibc 决定可运行范围**：在 `ubuntu-latest` 上构建的 deb/AppImage 到更老的发行版上
  可能直接起不来（`GLIBC_x.xx not found`）。要覆盖老发行版，就在那个发行版上构建。
- AppImage 是这套里最脆的一环（linuxdeploy + FUSE + strip），所以 CI 里 deb 与 AppImage
  分成两步 —— 合成一步的话，AppImage 挂了会让日志看起来像"Linux 根本编不过"。
- 系统依赖用的是 Tauri v2 官方那张表（`libwebkit2gtk-4.1-dev` 等），另加 `patchelf`（AppImage 要）。

## 六、签名

macOS 的 dmg **未签名未公证**，首次打开需右键「打开」或 `xattr -dr com.apple.quarantine`；
Windows 包**未签名**，会触发 SmartScreen。CI 里没有配置任何签名密钥，也没有留放密钥的口子 ——
要做签名分发，先想清楚密钥托管在哪，别顺手往仓库 Secrets 里塞。

## 七、这份流水线的验证状态

`.github/workflows/clients.yml` **没有在 GitHub Actions 上真实运行过**（本机无法运行 Actions）。
已做的验证到此为止：

- `actionlint`（含 `shellcheck` 集成）对该 workflow 零告警；
- `build-sidecars.sh` 的四条分支在本机用假 `rustc`（伪造 host 三元组）**真跑过**：
  `x86_64-pc-windows-msvc` → PE32+ x86-64、`aarch64-pc-windows-msvc` → PE32+ Aarch64、
  `x86_64-unknown-linux-gnu` → ELF、未适配三元组 → 如实报错退出；
- `build-artifacts.sh` 的溯源分支（注入 / 不注入 / 工作区脏 / 目标不是 git 仓）逐条跑过。

也就是说：**构建脚本是验过的，runner 上的步骤编排没有。** 第一次真实运行大概率还要修，
红了先看步骤名。
