#!/usr/bin/env bash
# 汇集客户端安装包 → deploy/artifacts/downloads/ 并生成 manifest.json（size/sha256 自动计算）。
# 前置：桌面 dmg 已构建（Task 4）、安卓 APK 已构建（Task 5）；缺哪个就在 manifest 里占位。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/deploy/artifacts/downloads"

# 版本从 package.json 读，不写死：写死的话改了版本号忘了改这里，
# manifest 会把新包标成旧版本号，而校验和是对的——最难自证的一种不一致。
VER="$(python3 -c "import json;print(json.load(open('$HERE/desktop/package.json'))['version'])")"

# ── 构建溯源 ──
# ★安装包与源码之间此前没有任何可核对的关联：manifest 有 version+size+sha256，
# 看起来很权威，却不说这包是从哪份源码构建的。真实发生过的形态是包停在三周前、
# 源码改了 11 次，而页面上一切正常。版本号帮不上忙（源码改了 package.json 没动）。
# 记 clients/ **子树**的 commit：只改控制面就把所有包标成过期会让提示变噪音。
#
# 允许流水线用 BAIDI_CLIENT_SRC_REV 显式注入（与 control 侧 clientSourceRev() 同名同义）。
# ★为什么必须有这个入口：CI 上 actions/checkout 默认是**深度 1 的浅克隆**，
# 而 `git log -1 -- clients/` 是路径过滤的——本次提交没碰 clients/ 时它返回**空**，
# 于是刚出炉的包被标成「无法判断新旧」，而构建日志里一切正常。
# 对策二选一：checkout 时 fetch-depth: 0，或在这里注入。两条路 .github/workflows/clients.yml 都走了。
if [ -n "${BAIDI_CLIENT_SRC_REV:-}" ]; then
  SRC_REV="$BAIDI_CLIENT_SRC_REV"
  echo "→ 溯源由 BAIDI_CLIENT_SRC_REV 注入：$SRC_REV"
else
  SRC_REV="$(git -C "$ROOT" log -1 --format=%h -- clients/ 2>/dev/null || echo "")"
  [ -n "$SRC_REV" ] || echo "⚠ 取不到 clients/ 的 git 版本，manifest 将缺溯源信息（页面会报「无法判断新旧」）"
fi
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# 源码有未提交改动时，构建出的包与任何 commit 都不对应——如实标成 dirty，
# 让页面把它判成过期，而不是冒充某个干净版本。注入进来的值同样过这一关：
# 注入的是「哪个 commit」，不是「工作区是干净的」这个保证。
# ★先确认这里真是个 git 仓库：不是的话 git 命令以非零退出，会把"没有 .git"读成"有改动"，
# 于是部署机（通常没有 .git）上注入的干净版本会被凭空标成 dirty。
#
# ★判据是 `git status --porcelain -- clients/` 而**不是** `git diff --quiet -- clients/`：
# 后者只比工作树与索引，**已 `git add` 但未提交的改动、以及新增的未跟踪文件全被判成干净**。
# 而"改完先 add、构建验证一轮再提交"正是最常见的节奏——那一轮出的包会写上
# sourceCommit=<上一个 commit> 且不带 -dirty，控制面 annotateProvenance 于是判定
# 「与当前源码一致」，页面一片正常。方向恰好是"看起来是新的"，正是这套机制要消灭的谎。
# porcelain 覆盖三种：已暂存（M /A ）、未暂存（ M）、未跟踪（??）；被 .gitignore 排除的
# 构建产物（target/、node_modules/）本来就不出现在里面。
clients_dirty() {
  git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1 || return 1
  [ -n "$(git -C "$ROOT" status --porcelain -- clients/ 2>/dev/null)" ]
}
if [ -n "$SRC_REV" ] && [ "${SRC_REV%-dirty}" = "$SRC_REV" ] && clients_dirty; then
  SRC_REV="${SRC_REV}-dirty"
  echo "⚠ clients/ 有未提交改动（含已 add 未提交与未跟踪文件），溯源标记为 $SRC_REV"
fi

rm -rf "$OUT"; mkdir -p "$OUT"

# ── 桌面 dmg：universal 优先，aarch64 兜底 ──
DMG_UNI="$HERE/desktop/src-tauri/target/universal-apple-darwin/release/bundle/dmg/白帝安全接入客户端_${VER}_universal.dmg"
DMG_ARM="$HERE/desktop/src-tauri/target/release/bundle/dmg/白帝安全接入客户端_${VER}_aarch64.dmg"
MAC_FILE="" MAC_ARCH="" MAC_REV="" MAC_BUILT=""
if [ -f "$DMG_UNI" ]; then
  MAC_FILE="baidi-desktop_${VER}_universal.dmg"; MAC_ARCH="Universal（Intel + Apple Silicon）"
  cp "$DMG_UNI" "$OUT/$MAC_FILE"; MAC_REV="$SRC_REV"; MAC_BUILT="$BUILT_AT"
elif [ -f "$DMG_ARM" ]; then
  MAC_FILE="baidi-desktop_${VER}_aarch64.dmg"; MAC_ARCH="Apple Silicon"
  cp "$DMG_ARM" "$OUT/$MAC_FILE"; MAC_REV="$SRC_REV"; MAC_BUILT="$BUILT_AT"
else
  echo "⚠ 未找到桌面 dmg，macOS 将占位"
fi

# ── Android APK ──
# ★溯源按**产物自己的**构建时间算，不套用本次运行的 SRC_REV：安卓要 JDK + Android SDK，
# 常常不在跑本脚本这台机器上构建。套用的话，一个几周前的 APK 会被标成「刚从当前源码构建」——
# 那正是这套溯源机制要消灭的谎，反而由它自己制造出来。
# 用 BAIDI_APK_SRC_REV 显式声明该 APK 出自哪个 commit；没声明就留空 = 页面报「无法判断新旧」。
#
# ★BAIDI_APK_BUILT_AT 同理必须能被显式声明，不能只靠文件 mtime：
# APK 现在由 .github/workflows/clients-mobile.yml 在另一台机器上构建，取回来时是
# actions/download-artifact 解出来的——mtime 是**解压那一刻**。只信 mtime 的话，
# 一个上个月构建的 APK 会在页面上写着「刚刚构建」，而 sourceCommit 明明对不上。
# 两个字段一起说谎才最难发现，所以两个字段一起支持注入（CI 把它们成对写进
# apk-provenance.env，与 APK 同行同源）。
APK="$HERE/mobile/native/android/app/build/outputs/apk/debug/app-debug.apk"
AND_FILE="" AND_REV="" AND_BUILT=""
if [ -f "$APK" ]; then
  AND_FILE="baidi-mobile_${VER}_debug.apk"
  cp "$APK" "$OUT/$AND_FILE"
  AND_REV="${BAIDI_APK_SRC_REV:-}"
  AND_BUILT="${BAIDI_APK_BUILT_AT:-}"
  if [ -n "$AND_BUILT" ]; then
    echo "→ APK 构建时刻由 BAIDI_APK_BUILT_AT 注入：$AND_BUILT"
  else
    AND_BUILT="$(date -u -r "$APK" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")"
  fi
  [ -n "$AND_REV" ] || echo "⚠ APK 未声明来源 commit（BAIDI_APK_SRC_REV），页面将报「无法判断新旧」"
else
  echo "⚠ 未找到 Android APK，android 将占位"
fi

# ── 生成 manifest.json ──
MAC_FILE="$MAC_FILE" MAC_ARCH="$MAC_ARCH" AND_FILE="$AND_FILE" VER="$VER" OUT="$OUT" \
SRC_REV="$SRC_REV" BUILT_AT="$BUILT_AT" MAC_REV="$MAC_REV" AND_REV="$AND_REV" \
MAC_BUILT="$MAC_BUILT" AND_BUILT="$AND_BUILT" python3 - <<'PY'
import hashlib, json, os

out = os.environ["OUT"]; ver = os.environ["VER"]

def entry(platform, label, file, arch="", note="", rev="", built=""):
    e = {"platform": platform, "label": label, "available": bool(file), "note": note}
    if file:
        p = os.path.join(out, file)
        e.update(version=ver, file=file, size=os.path.getsize(p),
                 sha256=hashlib.sha256(open(p, "rb").read()).hexdigest(), arch=arch)
        # 溯源逐包记：不同平台可能在不同机器、不同时间构建（安卓要 JDK+SDK，
        # iOS 要 Xcode），统一写一个全局值会把「这台机器刚构建的」冒充成全部。
        if rev:
            e["sourceCommit"] = rev
        if built:
            e["builtAt"] = built
    return e

# ★占位文案要与 control/internal/api/downloads.go 的 placeholderManifest() **逐字一致**
# （manifest 缺失时页面回落到那一份，两处不一致会让同一个平台在两种情况下说两种话）。
# 有 Go 用例真的跑这个脚本、把生成的 manifest 与 placeholderManifest() 逐条比对，
# 见 control/internal/api/downloads_script_test.go。
# ★「构建中，敬请期待」只能用在**真的会被构建出来、且装了能用**的平台上。
#   - iOS 与鸿蒙缺的不是一次构建，而是公共 CI 上根本不存在的东西（Apple 付费账号签名 +
#     Network Extension 授权 / DevEco Studio 工具链）；
#   - Windows 缺的是 wintun.dll（第三方二进制，本仓库不分发、也不在 CI 里从网上抓），
#     加上 UAC 提权路径未实机验证——CI 出的包因此标 UNVERIFIED 且刻意不进下载中心。
#     对用户来说重点不是"包能不能出"，是"能不能用"：写「敬请期待」等于让他一直等一个
#     按现有决策不会下发的包，而正确的下一步（自备 DLL / 找管理员要 UNVERIFIED 包）
#     恰恰是存在的，却被那句占位文案挡住了。
# 写「敬请期待」等于给一个不会到来的版本许诺。理由见 clients/BUILD.md 第九节。
clients = [
    # ★缺 dmg 时的 note 不能留空：空着的话页面上 macOS 那一行什么都不说，而 manifest
    # 整体缺失时同一行会显示「构建中，敬请期待」——同一个平台在两条路径上说两种话。
    entry("macos", "macOS 桌面客户端", os.environ["MAC_FILE"], os.environ["MAC_ARCH"],
          note="" if os.environ["MAC_FILE"] else "构建中，敬请期待",
          rev=os.environ.get("MAC_REV", ""), built=os.environ.get("MAC_BUILT", "")),
    entry("windows", "Windows 桌面客户端", "",
          note="需自备 wintun.dll（第三方组件，本仓库不分发）才能建虚拟网卡，且 UAC 提权路径未实机验证；"
               "CI 产物标 UNVERIFIED、刻意不进下载中心，请联系管理员"),
    entry("linux", "Linux 桌面客户端", "", note="pkexec 提权与数据面均未实机验证；CI 产物标 UNVERIFIED、刻意不进下载中心，请联系管理员"),
    entry("ios", "iOS 客户端", "",
          note="需 Xcode + 付费账号签名与 Network Extension 授权，公共 CI 无法构建；请联系管理员"),
    entry("android", "Android 客户端", os.environ["AND_FILE"],
          "armeabi-v7a / arm64-v8a / x86 / x86_64",
          "调试签名版，安装时需允许「未知来源应用」" if os.environ["AND_FILE"] else "构建中，敬请期待",
          rev=os.environ.get("AND_REV", ""), built=os.environ.get("AND_BUILT", "")),
    entry("harmony", "鸿蒙客户端", "",
          note="需 DevEco Studio 人工构建（工具链不在 CI 上）；请联系管理员"),
]
with open(os.path.join(out, "manifest.json"), "w") as f:
    json.dump({"clients": clients}, f, ensure_ascii=False, indent=2)
print("✓ manifest.json 已生成")
PY

echo "✓ 产物就绪 → $OUT"; ls -la "$OUT"
