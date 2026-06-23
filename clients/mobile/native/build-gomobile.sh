#!/usr/bin/env bash
# 把白帝移动数据面引擎(baidimobile)编成 iOS .xcframework + 安卓 .aar。
# 需：Go + gomobile；iOS 需 Xcode；Android 需 Android SDK + NDK。
#   go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GW="$(cd "$HERE/../../../gateway" && pwd)"
OUT="$HERE/out"; mkdir -p "$OUT"
PKG="baidi.dev/gateway/mobile/baidimobile"

command -v gomobile >/dev/null || { echo "缺 gomobile：go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init"; exit 1; }
cd "$GW"

echo "==> iOS .xcframework（拖进 Xcode 的 Network Extension target）"
gomobile bind -target=ios -o "$OUT/Baidimobile.xcframework" "$PKG"

echo "==> Android .aar（放安卓 app/libs，VpnService 工程引用）"
gomobile bind -target=android -androidapi 21 -o "$OUT/baidimobile.aar" "$PKG"

echo "✓ 产物 → $OUT"
ls -la "$OUT"
