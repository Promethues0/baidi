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
SRC_REV="$(git -C "$ROOT" log -1 --format=%h -- clients/ 2>/dev/null || echo "")"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ -n "$SRC_REV" ] || echo "⚠ 取不到 clients/ 的 git 版本，manifest 将缺溯源信息（页面会报「无法判断新旧」）"
# 源码有未提交改动时，构建出的包与任何 commit 都不对应——如实标成 dirty，
# 让页面把它判成过期，而不是冒充某个干净版本。
if [ -n "$SRC_REV" ] && ! git -C "$ROOT" diff --quiet -- clients/; then
  SRC_REV="${SRC_REV}-dirty"
  echo "⚠ clients/ 有未提交改动，溯源标记为 $SRC_REV"
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
# ── Android APK ──
# ★溯源按**产物自己的**构建时间算，不套用本次运行的 SRC_REV：安卓要 JDK + Android SDK，
# 常常不在跑本脚本这台机器上构建。套用的话，一个几周前的 APK 会被标成「刚从当前源码构建」——
# 那正是这套溯源机制要消灭的谎，反而由它自己制造出来。
# 用 BAIDI_APK_SRC_REV 显式声明该 APK 出自哪个 commit；没声明就留空 = 页面报「无法判断新旧」。
APK="$HERE/mobile/native/android/app/build/outputs/apk/debug/app-debug.apk"
AND_FILE="" AND_REV="" AND_BUILT=""
if [ -f "$APK" ]; then
  AND_FILE="baidi-mobile_${VER}_debug.apk"
  cp "$APK" "$OUT/$AND_FILE"
  AND_REV="${BAIDI_APK_SRC_REV:-}"
  AND_BUILT="$(date -u -r "$APK" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")"
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

clients = [
    entry("macos", "macOS 桌面客户端", os.environ["MAC_FILE"], os.environ["MAC_ARCH"],
          rev=os.environ.get("MAC_REV", ""), built=os.environ.get("MAC_BUILT", "")),
    entry("windows", "Windows 桌面客户端", "", note="构建中，敬请期待"),
    entry("linux", "Linux 桌面客户端", "", note="构建中，敬请期待"),
    entry("ios", "iOS 客户端", "", note="需企业签名 / TestFlight 分发，请联系管理员"),
    entry("android", "Android 客户端", os.environ["AND_FILE"],
          "armeabi-v7a / arm64-v8a / x86 / x86_64",
          "调试签名版，安装时需允许「未知来源应用」" if os.environ["AND_FILE"] else "构建中，敬请期待",
          rev=os.environ.get("AND_REV", ""), built=os.environ.get("AND_BUILT", "")),
    entry("harmony", "鸿蒙客户端", "", note="构建中，敬请期待"),
]
with open(os.path.join(out, "manifest.json"), "w") as f:
    json.dump({"clients": clients}, f, ensure_ascii=False, indent=2)
print("✓ manifest.json 已生成")
PY

echo "✓ 产物就绪 → $OUT"; ls -la "$OUT"
