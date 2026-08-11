# 客户端构建指南（谁能在哪构建，什么必须在原生机器上做）

先给结论，别再重复试一遍：

| 目标 | 能在 macOS 本机构建吗 | 怎么出包 |
|---|---|---|
| macOS `.dmg`（universal） | **能** | `./src-tauri/build-sidecars.sh && npm run tauri:build -- --target universal-apple-darwin` |
| Linux `.deb` / `.AppImage` | **不能** | GitHub Actions `ubuntu-latest`，或一台真 Linux |
| Windows `.msi` / `.exe` | **不能** | GitHub Actions `windows-latest`，或一台真 Windows |
| Android `.apk` | **不能**（本机无 Java 运行时、未设 `ANDROID_HOME`、gomobile 跑不起来） | GitHub Actions `ubuntu-latest`，见第八节 |
| iOS `.ipa` | **不能** | **只能人工构建**，公共 CI 上做不到，见第九节 |
| 鸿蒙 `.hap` | **不能** | **只能人工构建**，公共 CI 上做不到，见第九节 |

流水线两条，工具链毫无交集所以分开：

- 桌面：[`.github/workflows/clients.yml`](../.github/workflows/clients.yml)（Tauri/Rust，三平台矩阵）
- 移动：[`.github/workflows/clients-mobile.yml`](../.github/workflows/clients-mobile.yml)（JDK + Android SDK/NDK + gomobile，**只有 Android**）

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
| `ubuntu-latest` | `.deb` + `.AppImage` + 说明 + `build-provenance.env` | `baidi-desktop-linux-x86_64-UNVERIFIED` |
| `windows-latest` | `.msi` + NSIS `.exe` + 说明 + `build-provenance.env` | `baidi-desktop-windows-x86_64-UNVERIFIED` |

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

**Linux / Windows 的 UNVERIFIED 产物同样要带溯源**，虽然它们不进 `manifest.json`。
`取 clients/ 子树 commit` 那一步在三个 runner 上都跑，但它的输出此前只有 macOS 分支消费 ——
两份 UNVERIFIED 包里只有安装包和一份 README，下载的人无从知道它出自哪个 commit、
什么时候构建。将来有人手工把它铺进 `downloads/` 时只能靠 `git log` 事后猜一个，
而**猜错的方向恰好是「看起来是新的」**（给安卓建 `apk-provenance.env` 时写的就是这句，
这条纪律现在回填到了桌面这条流水线）。
产物里因此各带一份 `build-provenance.env`（`BAIDI_CLIENT_SRC_REV` / `BAIDI_CLIENT_BUILT_AT` /
`BAIDI_CLIENT_PLATFORM` / `BAIDI_CLIENT_VERIFIED=no`，变量名与汇集脚本、控制面
`clientSourceRev()` 同名同义，铺包的人可以直接 `source` 它），同样内容也追加进 README。

`BAIDI_APK_SRC_REV`（安卓 APK 的溯源）**刻意没在这条流水线里设**：本流水线不构建 APK，
干净的 checkout 里也没有 APK。此时把当前 commit 塞给它，等于替一个"将来某人放进来的、
来路不明的包"预先背书 —— 那正是溯源机制要消灭的谎。将来真加了 APK 构建作业，
在那个作业里设它。

### CI 产物进下载中心的"最后一公里"

`build-artifacts.sh` 目前只认两样东西：本机 tauri 产出的 `.dmg`，和 `mobile/native/android`
下的 `.apk`。CI 出的 Linux/Windows 包**不会**自动进 `manifest.json`（那两个平台在
manifest 里仍是占位）。要下发它们，得先解决下面第四、五节那两条真实约束。

在那之前，占位文案要照实说**为什么**。这两个平台**都不写「构建中，敬请期待」**：
包不是"还在构建"，是构建出来了、按现有决策不下发。

- **Linux**：「pkexec 提权与数据面均未实机验证；CI 产物标 UNVERIFIED、刻意不进下载中心，
  请联系管理员」；
- **Windows**：「包内已含建虚拟网卡所需的 wintun.dll（构建期官方取件 + 哈希校验），
  但 UAC 提权与数据面均未实机验证；CI 产物标 UNVERIFIED、刻意不进下载中心，请联系管理员」。
  ★这句的**理由**换过一次：`wintun.dll` 从"我们不分发、请用户自备"改成了随包分发（见第四节），
  组件因此齐了，**剩下的差距只是实机验证** —— UAC 提权、建卡、NRPT 分离式 DNS 一次都没在
  真实 Windows 上跑过。占位文案说的必须是**此刻**的缺口，不是历史上的那个。

共同的判据是：用户看到的不是「包能不能出」，是「能不能用」—— 说「敬请期待」等于让他一直等一个
按现有决策不会下发的包，而正确的下一步（找管理员要 UNVERIFIED 包）明明存在，却被那句话挡住了。

## 四、Windows：wintun.dll 随包分发（构建期取件 + 强校验）

`baidi-tun` 在 Windows 上用 **Wintun** 建虚拟网卡，需要 `wintun.dll`。

### 从哪来：构建期取件，不入库

`src-tauri/fetch-wintun.sh` 从官方 <https://www.wintun.net/> 下载 zip 并做 **SHA-256 强校验**
（哈希的来历见下文「哈希从哪儿来」），按架构解出 DLL 与 `LICENSE.txt` 到
`src-tauri/binaries/wintun/`。`build-sidecars.sh` 在 `GOOS=windows` 时自动调它。
二进制**不进 git**：本仓库被 `gateway/baidi-tun` 那两个 13MB 历史产物坑过一次，
入库之后没人再核对来源，clone 的人也无从判断它是不是官方那一份。

### 凭什么能随包分发：许可第 3(d) 条的例外

Wintun 的「Prebuilt Binaries License」（zip 里的 `wintun/LICENSE.txt`）默认**禁止**再分发 ——
第 3 条 d 项禁止未经 WireGuard LLC 书面同意就 resell / redistribute / lease / rent /
transfer / sublicense。但同一项留了一条例外，原文（英文）是：

> …except insofar as the Software is distributed alongside other software that uses the
> Software only via the Permitted API

`baidi-tun` 的 Go 绑定只调用 `wintun.h` 导出的函数（即 Permitted API），DLL 也只随白帝客户端
一同分发、不单独提供 —— 落在这条例外里，**分发是合法的，不需要另外去要书面许可**。

附带义务两条，每条都有执行方（不是写在文档里就算数）：

| 义务 | 出处 | 执行方 |
|---|---|---|
| 不得改动 DLL、不得从中剥掉版权注记 | 第 3 条 a 项（禁 modify）、b 项（禁衍生作品，只放行"仅用 `wintun.h` 的 API 接口"）、c 项（禁 remove any proprietary notices **from the Software**） | `fetch-wintun.sh` 从官方 zip **原样解出**：不改名、不加壳、不重签 |
| 不得借 WireGuard / Wintun 的名号背书本产品 | 第 3 条 e 项 | 文案只做事实陈述（「Windows 用 Wintun 建虚拟网卡」「到 wintun.net 取 DLL」），不写成合作 / 认证 / 推荐 |

★**「随包附上 `LICENSE.txt`」是我们自愿的做法，许可原文并未要求**。这一栏此前把它援引到
第 3 条 c 项，是错的：§1 把 "Software" 定义为 `wintun.dll` 的精确内容，3(c) 管的是
「不得从那个二进制里移除版权注记」，通篇没有「必须附带许可文件」这一条。
仍然要附，理由是收到包的人应当能读到约束这份 DLL 的条款；但**不许把它写成许可的硬性要求** ——
那是替第三方许可作一个原文没有的事实陈述，而这句话会随 UNVERIFIED 包发到用户手里
（`README-windows.txt`）。既然对外说了要附，就得有执行方：`verify-wintun-stage.sh` 在打包前
查它在不在，CI 打包后查它进没进安装包。

### 哈希从哪儿来

`WINTUN_SHA256` **不是**"把下载下来的文件算一遍填进去" —— 那等于给任何一次被投毒的下载
盖章，校验永远通过、永远没有意义。它是**官网公布值**：<https://www.wintun.net/> 的下载页
逐版本列出 zip 的 SHA-256，本地取件后**人工逐字符比对**一致才写进脚本
（`wintun-0.14.1.zip` = `07c2561…4ef51`，750540 字节；核实日期记在脚本顶部注释里）。

三条取件路径 —— `BAIDI_WINTUN_ZIP` 指定的本地文件 / 缓存命中 / 现下 —— **都**过同一道校验，
一条都不豁免：内网构建机上那份 zip 的来路，与网上下载的那份一样不可自证。缓存的判据是
「文件在**且**哈希对」，只看在不在等于把一份被改过的缓存永久信下去。校验不过就退出，
不重试也不降级：这个 DLL 会被以**管理员权限**加载进数据面进程。

★下载地址只有 `https://www.wintun.net/builds/wintun-<版本>.zip` 这一条。
旧文档里常见的 `git.zx2c4.com/wintun/builds/…` 现在是 **404**，别照抄。

### 离线 / 内网构建：`BAIDI_WINTUN_ZIP`

构建机不通外网时，在别处下好同一份 zip，用环境变量指过去（照样强校验，不是"跳过校验"的开关）：

```bash
cd clients/desktop
BAIDI_WINTUN_ZIP=/data/pkgs/wintun-0.14.1.zip ./src-tauri/fetch-wintun.sh --arch amd64
# 环境变量会被子进程继承，所以整条构建线也可以直接：
BAIDI_WINTUN_ZIP=/data/pkgs/wintun-0.14.1.zip ./src-tauri/build-sidecars.sh
```

其余用法：`--arch amd64|arm64` 取单一架构（**打包必须指定单一架构**，脚本只在这种情况下产出
打包配置引用的固定路径 `binaries/wintun/wintun.dll`）；`--arch all` 取全部，用于离线预取或检视，
此时脚本会**主动删掉**固定路径上那份旧 DLL —— 留一份架构对不上的在那儿，包照样打得出、
装得上，只在用户点「接入」那一刻报一句看不懂的加载失败。

### 升级 wintun 版本时要同时改什么

版本号在全仓**只有 `fetch-wintun.sh` 这一处**（其余地方都是示例文字），所以升级动作很小，
但下面几步一步都不能省：

1. 到 <https://www.wintun.net/> 取新版 zip，**人工比对官网公布的 SHA-256**；
2. 改脚本顶部**挨在一起**的三个常量 `WINTUN_VERSION` / `WINTUN_URL` / `WINTUN_SHA256`
   （刻意挨着写，「改了版本忘了改哈希」在视觉上无处可藏；真忘了也不会静默 ——
   校验会当场拒绝，而不是把一个未知二进制放进安装包），外加只用于报错提示的 `WINTUN_ZIP_BYTES`，
   并更新那句「核实日期」；
3. **复核 zip 内部布局没变**：脚本按 `wintun/LICENSE.txt`、`wintun/bin/<amd64|arm64>/wintun.dll`
   这两条固定成员路径取件。上游改了目录结构时，解包器可能回 0 却什么都没写 ——
   脚本对空文件当失败处理，就是为这个；
4. **重读一遍新版 `LICENSE.txt`**：本项目随包分发的合法性完全押在第 3(d) 条那句例外上，
   上游改许可就是改结论。条款变了要先改这一节的说法，不是先升版本；
5. 不需要动 `tauri.windows.conf.json`、CI 或 `.gitignore` —— 它们引用的都是与版本无关的路径。

### 放哪去：必须与 `baidi-tun.exe` **同目录**

wintun 用 `LoadLibraryEx(..., LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)`
加载它，**只看两处**：**发起加载的那个进程**自身 exe 所在目录、`%SystemRoot%\System32`。
不看 PATH，不看当前目录。发起方是 sidecar `baidi-tun.exe`，所以 DLL 要落在**它**旁边。

打包配置在 `src-tauri/tauri.windows.conf.json`（平台专属配置，只在 Windows 目标上合并进
`tauri.conf.json`；放主配置里会让 macOS/Linux 构建因找不到这两个文件而失败）：

```json
"resources": { "binaries/wintun/wintun.dll": "", "binaries/wintun/LICENSE.txt": "wintun-LICENSE.txt" }
```

**必须是这种「映射形 + 目的地空串」的写法**，理由是失败形态：写成列表形
`["binaries/wintun/wintun.dll"]` 时，Tauri 按 `resource_relpath` **保留目录结构**，
DLL 会装到 `<安装目录>\binaries\wintun\wintun.dll` —— 包照样打得出、装得上、文件也确实在，
只有用户点「接入」那一刻加载失败。空串是 Tauri 里「放到资源根目录、保留原文件名」的
唯一写法（`tauri-utils/src/resources.rs`），而 Windows 上资源根目录就是安装目录本身。

externalBin 与 resources 在 Windows 上落到同一处，这一点是查过打包器源码的：
NSIS 模板在 `Section Install` 里先 `SetOutPath $INSTDIR`，随后 resources 与 binaries 都用
`File /a "/oname=<目标名>"`；MSI 的 `main.wxs` 把两者都放进 `<DirectoryRef Id="INSTALLDIR">`，
且外部二进制会被剥掉 `-<三元组>` 后缀（`tauri-bundler` 的 `nsis/mod.rs` 与 `msi/mod.rs`）。
CI 不满足于"查过源码"：Windows 作业在打包后**真的**校验一遍 —— 解析生成出来的
`installer.nsi`，并用 `msiexec /a` 把 MSI 摊开，断言 `wintun.dll` 与 `baidi-tun.exe`
的父目录是同一个（见 `.github/workflows/clients.yml`）。

### 装到哪去：必须是需要管理员的目录（`installMode = perMachine`）

同一份配置里还有一行不能少：

```json
"windows": { "nsis": { "installMode": "perMachine" } }
```

Tauri 的 NSIS 缺省是 **`currentUser`**（`tauri-utils` 里 `NSISInstallerMode` 的 `#[default]`，
文档原文就是「装进一个不需要管理员权限的目录」），落点是 `%LOCALAPPDATA%\<产品名>`。
对别的应用这只是个偏好，对白帝是**提权链上的一个洞**：

> 装完之后 `<安装目录>\wintun.dll` 与 `<安装目录>\baidi-tun.exe` 都是**当前用户可写**的，
> 而这两个文件随后会被 UAC 提权、以管理员身份加载和执行。任何一个中完整性级别的进程
> —— 用户自己跑的脚本、一个普通权限的恶意程序 —— 只要把 DLL 换成同架构的恶意 PE，
> 就能在用户下次点「接入」时拿到**管理员代码执行**。`preflight_start` 只查存在性与
> PE machine 码，这两项它都过；`fetch-wintun.sh` 的 SHA-256 钉扎是**构建期**的，
> 只管构建机上那个 zip，管不到用户机上装好的那一份。

`perMachine` 让 NSIS 生成 `RequestExecutionLevel admin` + 默认落点 `$PROGRAMFILES64\<产品名>`
（模板 `installer.nsi` 的 `!if "${INSTALLMODE}" == "perMachine"` 两处分支），把「改写这个目录」
抬回到与「以管理员运行」同一道门槛之上 —— 也与 MSI 对齐（WiX 那侧本来就是 perMachine，
两个安装器此前是两种安全姿态）。代价是安装本身需要管理员，这对一个必须以管理员跑数据面的
客户端是合理的。

守卫两道：`elevate.rs` 的单测钉住配置里写了 `perMachine`；CI 断言**生成出来的**
`installer.nsi` 里有 `!define INSTALLMODE "perMachine"`（配置里写没写与真生成出什么是两回事）。

**别把它读成完整性校验**：产物没有代码签名（见第六节），NSIS 也允许用户在安装向导里
把目录改到一个可写位置 —— 这一步只保证**默认路径**不再是用户可写目录。

### 暂存区架构复核：`verify-wintun-stage.sh`

`fetch-wintun.sh --arch <a>` 在把 DLL 复制到固定位 `binaries/wintun/wintun.dll` 时，
会把「它是哪个架构」写进旁边的 `wintun.dll.triple`。那个文件一度**只写不读** —— 全仓没有
消费方，于是这条信息没有执行方，等于没记。它兜的失败形态是：

> 有人在打包机上手工跑过 `./fetch-wintun.sh`（排障时先 `--arch all`、又单跑了一次别的架构），
> 而不是经 `build-sidecars.sh` 按 GOARCH 调用。此时两个架构目录都在，固定位躺的却是另一份。
> 接下来 tauri build 不报错、包打得出、装得上、DLL 也确实在 `baidi-tun.exe` 旁边 ——
> 只有用户点「接入」那一刻才炸。

现在它有两个消费方：`build-sidecars.sh` 取完件立刻复核一次，`tauri.conf.json` 的
`beforeBundleCommand` 在打包前再复核一次（后者覆盖「build-sidecars 跑完之后又有人手工取件」
这个缺口）。复核内容：DLL / 许可 / `.triple` 三者齐全、`.triple` 的架构与本次目标一致、
固定位那份与按架构分放的那份**逐字节相同**（`.triple` 是脚本自报的，拿原样解出的那份交叉印证）。
目标不是 Windows 时安静跳过。

脚本刻意参数化成 `--triple` / `--stage`，好让 mac 上的 `cargo test` 真跑它、构造出只会在
Windows 打包机上出现的错配场景（六条用例，见 `elevate.rs`）。这条守卫与 CI 那道
（自己重解 PE 头比对 rustc 三元组）判据来源不同，两者对不上就说明暂存区被手工动过。

> `beforeBundleCommand` 是 `bash src-tauri/verify-wintun-stage.sh` —— 打包机上要有 bash
> （Windows 上即 Git Bash；`build-sidecars.sh` 本来就要它）。没有的话打包会直接失败，
> 这是刻意的 fail-closed 方向：宁可打不出包，不要打出一个架构对不上的包。

### 万一还是没放对：客户端要能自证

`src-tauri/src/elevate.rs` 的 `preflight_start` 在**弹 UAC 之前**就把话说完，绝不先让用户
输一次管理员口令再在建网卡那步失败。它查两件事：

1. DLL 在不在（判据与加载器一字不差：sidecar 自身目录 + System32），找不到时把**实际找过的
   绝对路径逐条列出** —— 落位真改错了，用户报障时那两行就是第一手证据；
2. 找到的那份**架构对不对**（读 PE 头的 machine 码）。zip 里有 amd64/arm64/x86/arm 四份，
   选错一份的症状与"根本没装"在界面上完全同形。三态：对→放行、错→当场拒并说清是架构问题、
   **读不出或认不出→放行**（不可判定不当作不合规，与 posture 采集同一条纪律）。

其余 Windows 未验证项：UAC 提权路径（`Start-Process -Verb RunAs`）、建卡与路由接管、
NRPT 分离式 DNS 及其清理。它们的**构造**在 macOS 上被单测逐字断言，但**没有在真实
Windows 上跑过** —— 包里组件齐了不等于跑得通，产物照旧标 UNVERIFIED。

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

Windows 这边要把后果说全：`tauri.conf.json` 里既没有 `certificateThumbprint` 也没有
`signCommand`（没证书，不是忘了配），于是**装完之后没有任何一道完整性校验**能替用户
判断 `wintun.dll` / `baidi-tun.exe` 还是不是我们发出去的那一份 —— 而它们会被以管理员身份
加载执行。`installMode=perMachine`（第四节）把安装目录抬到管理员门槛之上，是目前唯一
真正起作用的缓解；签名是那道缺失的兜底。别在下载页或 README 里用"经过校验"之类的说法
把构建期的哈希钉扎说成运行期的保护，两者覆盖的根本不是同一段路。

## 七、这份流水线的验证状态

`.github/workflows/clients.yml` **没有在 GitHub Actions 上真实运行过**（本机无法运行 Actions）。
已做的验证到此为止：

- `actionlint`（含 `shellcheck` 集成）对该 workflow 零告警；
- `build-sidecars.sh` 的四条分支在本机用假 `rustc`（伪造 host 三元组）**真跑过**：
  `x86_64-pc-windows-msvc` → PE32+ x86-64、`aarch64-pc-windows-msvc` → PE32+ Aarch64、
  `x86_64-unknown-linux-gnu` → ELF、未适配三元组 → 如实报错退出；
- `build-artifacts.sh` 的溯源分支（注入 / 不注入 / 工作区脏 / 目标不是 git 仓）逐条跑过；
  其中「工作区脏」与「占位文案与 `placeholderManifest()` 逐字一致」两条现在由
  `control/internal/api/downloads_script_test.go` **真的执行这个脚本**来守
  —— 它在临时 git 仓里构造「已 `git add` 未提交」「未跟踪新增」两种形态，
  那正是旧判据 `git diff --quiet -- clients/` 判成干净、包因此冒充一个干净 commit 的场景；
- 该用例还断言 `clients.yml` 的两份 UNVERIFIED 产物里确实带上了 `build-provenance.env`。

也就是说：**构建脚本是验过的，runner 上的步骤编排没有。** 第一次真实运行大概率还要修，
红了先看步骤名。

## 八、Android：在 CI 上出 debug APK（`.github/workflows/clients-mobile.yml`）

本机构建不了（无 Java 运行时、未设 `ANDROID_HOME`、gomobile 也跑不起来），所以走
`ubuntu-latest`。整条链是四段，缺一段的失败形态都不长得像"缺了那一段"：

```
clients/mobile          npm ci && npm run build            → dist/
  ↓ 平铺进 app assets（不是 assets/dist/）
gateway/mobile/baidimobile  gomobile bind -target=android  → out/baidimobile.aar
  ↓ 复制进 android/app/libs/
clients/mobile/native/android  ./gradlew assembleDebug     → app-debug.apk
```

### 三个"漏了也不报错"的接缝（CI 里各有一步专门断言）

1. **dist → `app/src/main/assets/`**：`MainActivity` 用 `WebViewAssetLoader` 把
   `https://appassets.local/` 映射到 assets 根并加载 `/index.html`，所以 dist 必须**平铺**。
   漏了这一步 APK 照样打得出来、照样能装，**一开就白屏**，logcat 里只有一条 404。
   `assets/` 被 `.gitignore` 排除，干净 checkout 上必然是空的。
2. **`.aar` → `app/libs/baidimobile.aar`**：gradle 写死 `implementation(files("libs/baidimobile.aar"))`，
   该目录同样被 `.gitignore` 排除。缺文件时 gradle 报的是 Kotlin 侧
   `Unresolved reference: Baidimobile` —— 与"绑定层源码写错了"完全同形。
   现在这一步由 `native/build-gomobile.sh` 自己做（以前是无人记录的手工动作）。
3. **`gomobile` 不在 PATH 上**：`go install` 装到 `$(go env GOPATH)/bin`，那目录不一定在 PATH。
   只认 PATH 的话，明明刚装好却报"缺 gomobile"，人会以为是 `go install` 失败了。
   两道保险：workflow 里 `echo "$(go env GOPATH)/bin" >> $GITHUB_PATH`，
   脚本里 `resolve_gomobile()` 再兜一次底。

`local.properties`（里面是构建者本机的 `sdk.dir` 绝对路径）被 `.gitignore` 排除，CI 上不存在
—— AGP 于是回落到 `ANDROID_HOME`/`ANDROID_SDK_ROOT`，`setup-android` 已设好。
**别在 CI 里生成 `local.properties`**：那等于把两个真相来源都留着。

### `build-gomobile.sh` 的 target 参数与 dry-run

```bash
native/build-gomobile.sh [all|android|ios]        # 默认 all
BAIDI_GOMOBILE_DRYRUN=1 native/build-gomobile.sh android   # 只打印命令与落点，不真跑
```

原先它无条件先编 iOS 再编 Android。iOS 那一条只可能在装了 Xcode 的 macOS 上成功，
于是在 Linux CI 上第一步就 `set -e` 退出 —— "安卓到底能不能编出来"这个问题永远得不到回答。

dry-run 存在的理由与 `posture.rs` / `sysstat` 那条纪律同源：**只在别的机器上才走到的分支
是验不到的**。所以脚本切成「纯构造」+ 一层薄薄的 `run()` 执行，构造部分在本机（macOS，
无 Android SDK/NDK）也能逐条走一遍。已在本机真跑过的分支：三个 target + 非法 target 退出码 2 +
NDK 探测四条（`ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT` / `$ANDROID_HOME/ndk-bundle` /
`$ANDROID_HOME/ndk/<版本>` 取 `sort -V` 最大者）+ 用假 `gomobile` 真跑一遍非 dry-run 路径。

### APK 的溯源必须与包同行

CI 产出 `baidi-mobile-android-debug-UNVERIFIED`，里面三样东西：
`app-debug.apk` + `apk-provenance.env` + `README-android.txt`。

`apk-provenance.env` 是两行：

```
BAIDI_APK_SRC_REV=<clients/ 子树短哈希>
BAIDI_APK_BUILT_AT=<构建时刻 RFC3339>
```

★**两个值都必须显式带走，不能事后补**：

- `SRC_REV` 取的是 **`clients/`** 子树而不是 `clients/mobile/` —— 控制面
  （`downloads.go` 的 `clientSourceRev`）拿**一个** `clients/` 版本去比对 manifest 里**每个**
  平台的 `sourceCommit`。只取 mobile 子树的话，别人改一次 `clients/desktop`，
  刚出炉的 APK 就被标成「已过期」；这条提示一旦开始误报，管理员两天后就不看了。
- `BUILT_AT` 不能靠文件 mtime。APK 经 `upload/download-artifact` 转一手之后，
  mtime 就是**解压那一刻** —— 一个上个月的包会在页面上写着「刚刚构建」。
  `build-artifacts.sh` 为此加了 `BAIDI_APK_BUILT_AT` 注入口（与 `BAIDI_APK_SRC_REV` 成对）。

CI 里有一步「自检：溯源真的能注进 manifest」，它真的跑一遍 `build-artifacts.sh` 并断言安卓条目的
`sourceCommit`/`builtAt` 与注入值逐字相等 —— 但**刻意不上传**那份 manifest：
那台机器上没有 dmg，生成的清单会把 macOS/Windows/Linux 全写成占位，铺到部署机等于
让 macOS 从页面上凭空消失，而两边日志都显示成功。

### 合进下载中心（在有 dmg 的那台机器上，只跑一次 `build-artifacts.sh`）

```bash
cp app-debug.apk clients/mobile/native/android/app/build/outputs/apk/debug/app-debug.apk
set -a; . ./apk-provenance.env; set +a
BAIDI_CLIENT_SRC_REV=$(git log -1 --format=%h -- clients/) bash clients/build-artifacts.sh
```

### 已知的坑（还没修，先记着）

- APK 文件名与 manifest 里的 `version` 取的是 **`clients/desktop/package.json`** 的版本号，
  而 APK 自己的 `versionName` 写在 `app/build.gradle.kts` 里。两处现在都是 `0.1.0`，
  桌面先升版的那天它们就会不一致 —— 包名说 0.2.0、装到机器上是 0.1.0。
- 没做 ABI 拆包：`.aar` 带 armeabi-v7a / arm64-v8a / x86 / x86_64 四套，APK 因此 60MB 起。
- **debug 签名**，不能上架、不能覆盖安装正式签名版。仓库里没有配置任何发布签名密钥，
  也没有留放密钥的口子（与桌面同一条：要做签名分发，先想清楚密钥托管在哪）。
- 数据面（`VpnService` 建 TUN → `Baidimobile.start(fd,cfg)` → SPA 敲门 + 国密 TLCP 隧道）
  **没有在任何一台真实安卓设备上跑通过**。「能装」与「能连」之间那一段还没有证据。
- 这条流水线同样**没有在 GitHub Actions 上真实运行过**。本机验证到 `build-gomobile.sh`
  为止（见上），`actionlint`（含 shellcheck）对该 workflow 零告警。

## 九、iOS 与鸿蒙：为什么 CI 上一个 job 都没有

这两个平台在 `clients-mobile.yml` 里**一个 job 都没写**，这不是遗漏。

**iOS.** 白帝的 iOS 数据面是 `NEPacketTunnelProvider`（Network Extension）。要出一个能装的包，
必须同时有：Apple **付费**开发者账号的签名证书与 provisioning profile、
`com.apple.developer.networking.networkextension` **授权**（这个 entitlement 需向 Apple 申请，
不是勾一下就有）、以及一台装了完整 Xcode 的 macOS。公共 runner 上有 Xcode，但**没有**、
也不该有前两样 —— 往仓库 Secrets 里塞签名私钥是另一个量级的决定，不能顺手做。
此外 `native/ios/` 目前只有 `PacketTunnelProvider.swift` 这一份参考源码，
**还没有 Xcode 工程**：即便签名齐了，也不是"跑个命令"就能出包。

**鸿蒙.** 工具链（DevEco Studio / HarmonyOS SDK）不在 GitHub Actions 的 runner 镜像里，
也没有官方 action，更没有可直接 `apt install` 的 CLI。`native/harmony/` 目前也只有
`VpnExtAbility.ets` 这一份骨架源码，同样没有工程。

**为什么不挂两个 skip 掉的 job 占位**：那会把"我们没有这个能力"伪装成"这次没跑"。
Actions 页面上一片绿、每次都跳过，看起来像是配置问题，实际是能力缺口 —— 与本项目
「采不到就说不可判定，绝不补 0」是同一条纪律。所以：不写 job，把原因写在这里，
并让下载中心的占位文案照实说。

占位文案因此改成了（`clients/build-artifacts.sh` 与 `control/internal/api/downloads.go`
的 `placeholderManifest()` **两处逐字一致**，改要一起改）：

| 平台 | 改前 | 改后 |
|---|---|---|
| iOS | 需企业签名 / TestFlight 分发，请联系管理员 | 需 Xcode + 付费账号签名与 Network Extension 授权，公共 CI 无法构建；请联系管理员 |
| 鸿蒙 | **构建中，敬请期待** | 需 DevEco Studio 人工构建（工具链不在 CI 上）；请联系管理员 |
| Windows | **构建中，敬请期待** | 包内已含建虚拟网卡所需的 wintun.dll（构建期官方取件 + 哈希校验），但 UAC 提权与数据面均未实机验证；CI 产物标 UNVERIFIED、刻意不进下载中心，请联系管理员 |
| Linux | **构建中，敬请期待** | pkexec 提权与数据面均未实机验证；CI 产物标 UNVERIFIED、刻意不进下载中心，请联系管理员 |
| macOS（缺 dmg 时） | *（空着，什么都不说）* | 构建中，敬请期待（与 `placeholderManifest()` 同） |

鸿蒙那句「构建中，敬请期待」是不对的：它暗示有一个正在进行的构建、等等就有 —— 而实际上
没有任何流水线在构建它，也不会有。「敬请期待」只能用在**真的会被构建出来、且装了能用**的
平台上。

Windows 起初被豁免过一次，理由是「包能出，所以算数」—— 那是拿错了判据：
**用户看到的不是「包能不能出」，是「能不能用」。** CI 产物刻意不进下载中心，
那个包按现有决策不会下发；而它的正确下一步（找管理员要 UNVERIFIED 包）恰恰是存在的，
只是被那句占位文案挡住了。（这句话的**理由**后来变了一次：`wintun.dll` 从"我们不分发、
请用户自备"改成了随包分发，见第四节；剩下的差距是实机验证。结论没变，措辞跟着改了——
占位文案说的必须是**此刻**的真实缺口，不是历史上的那个。）

**Linux 后来也跟着改了**（起初被判成"不同"：包能出、数据面代码也在，缺的只是一次实机验证，
所以"仍写敬请期待"）。那个判断是错的：Linux 与 Windows 是同一处境 —— CI 出得来 .deb/.AppImage、
标 UNVERIFIED、刻意不下发，差的是实机验证而不是"还在构建"。**「敬请期待」许诺的是一个
不会自己到来的版本**，而两个平台的正确下一步都是同一句「找管理员要 UNVERIFIED 包」。

macOS 那一行是同一条纪律的另一半：脚本在**缺 dmg** 时曾写 `note=""`，而 manifest 整体
缺失时页面回落到 `placeholderManifest()` 的「构建中，敬请期待」—— 同一个平台在两条路径上
说两种话（一句解释 vs 什么都不说）。两处文案的一致性现在由 Go 用例真跑一遍脚本来守
（`control/internal/api/downloads_script_test.go`）。
