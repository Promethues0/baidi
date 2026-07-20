#!/usr/bin/env bash
# 汇集客户端安装包 → deploy/artifacts/downloads/ 并生成 manifest.json（size/sha256 自动计算）。
# 前置：桌面 dmg 已构建（Task 4）、安卓 APK 已构建（Task 5）；缺哪个就在 manifest 里占位。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$ROOT/deploy/artifacts/downloads"
VER="0.1.0"
rm -rf "$OUT"; mkdir -p "$OUT"

# ── 桌面 dmg：universal 优先，aarch64 兜底 ──
DMG_UNI="$HERE/desktop/src-tauri/target/universal-apple-darwin/release/bundle/dmg/白帝安全接入客户端_${VER}_universal.dmg"
DMG_ARM="$HERE/desktop/src-tauri/target/release/bundle/dmg/白帝安全接入客户端_${VER}_aarch64.dmg"
MAC_FILE="" MAC_ARCH=""
if [ -f "$DMG_UNI" ]; then
  MAC_FILE="baidi-desktop_${VER}_universal.dmg"; MAC_ARCH="Universal（Intel + Apple Silicon）"
  cp "$DMG_UNI" "$OUT/$MAC_FILE"
elif [ -f "$DMG_ARM" ]; then
  MAC_FILE="baidi-desktop_${VER}_aarch64.dmg"; MAC_ARCH="Apple Silicon"
  cp "$DMG_ARM" "$OUT/$MAC_FILE"
else
  echo "⚠ 未找到桌面 dmg，macOS 将占位"
fi

# ── Android APK ──
APK="$HERE/mobile/native/android/app/build/outputs/apk/debug/app-debug.apk"
AND_FILE=""
if [ -f "$APK" ]; then
  AND_FILE="baidi-mobile_${VER}_debug.apk"
  cp "$APK" "$OUT/$AND_FILE"
else
  echo "⚠ 未找到 Android APK，android 将占位"
fi

# ── 生成 manifest.json ──
MAC_FILE="$MAC_FILE" MAC_ARCH="$MAC_ARCH" AND_FILE="$AND_FILE" VER="$VER" OUT="$OUT" python3 - <<'PY'
import hashlib, json, os

out = os.environ["OUT"]; ver = os.environ["VER"]

def entry(platform, label, file, arch="", note=""):
    e = {"platform": platform, "label": label, "available": bool(file), "note": note}
    if file:
        p = os.path.join(out, file)
        e.update(version=ver, file=file, size=os.path.getsize(p),
                 sha256=hashlib.sha256(open(p, "rb").read()).hexdigest(), arch=arch)
    return e

clients = [
    entry("macos", "macOS 桌面客户端", os.environ["MAC_FILE"], os.environ["MAC_ARCH"]),
    entry("windows", "Windows 桌面客户端", "", note="构建中，敬请期待"),
    entry("linux", "Linux 桌面客户端", "", note="构建中，敬请期待"),
    entry("ios", "iOS 客户端", "", note="需企业签名 / TestFlight 分发，请联系管理员"),
    entry("android", "Android 客户端", os.environ["AND_FILE"],
          "armeabi-v7a / arm64-v8a / x86 / x86_64",
          "调试签名版，安装时需允许「未知来源应用」" if os.environ["AND_FILE"] else "构建中，敬请期待"),
    entry("harmony", "鸿蒙客户端", "", note="构建中，敬请期待"),
]
with open(os.path.join(out, "manifest.json"), "w") as f:
    json.dump({"clients": clients}, f, ensure_ascii=False, indent=2)
print("✓ manifest.json 已生成")
PY

echo "✓ 产物就绪 → $OUT"; ls -la "$OUT"
