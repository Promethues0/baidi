#!/usr/bin/env bash
# 白帝 · 鸿蒙桌面客户端构建。
#
# 全程命令行，不需要打开 DevEco Studio——但**签名材料**必须先由 DevEco 生成一次
# （见 README「签名」一节），因为 profile(.p7b) 由华为签发且绑定 bundleName + 设备 UDID。
#
# 用法：
#   ./build.sh              构建（debug）
#   ./build.sh install      构建并装到已连接的真机
#   ./build.sh run          构建、安装并拉起
set -euo pipefail
cd "$(dirname "$0")"

DEVECO="${DEVECO_HOME:-/Applications/DevEco-Studio.app/Contents}"
[ -d "$DEVECO" ] || { echo "找不到 DevEco Studio：$DEVECO（可用 DEVECO_HOME 指定）" >&2; exit 1; }

# ★JAVA_HOME 必须指到 DevEco 自带的 JBR：打包阶段（PackageHap）要 Java，
# 而 macOS 上通常没装系统 JDK——不设的话构建会走到最后一步才失败。
export JAVA_HOME="$DEVECO/jbr/Contents/Home"
export DEVECO_SDK_HOME="$DEVECO/sdk"
export PATH="$JAVA_HOME/bin:$DEVECO/tools/node/bin:$DEVECO/tools/ohpm/bin:$DEVECO/tools/hvigor/bin:$DEVECO/sdk/default/openharmony/toolchains:$PATH"

MODE="${2:-debug}"
CMD="${1:-build}"

# ── 签名材料合并 ──
# 凭据不入库（同 certs/ 的纪律），本机那份在 signing-local.json5。
# 有它就临时合并进 build-profile.json5，构建完还原——版本库里那份始终干净。
if [ -f signing-local.json5 ]; then
  cp build-profile.json5 .build-profile.orig
  trap 'mv -f .build-profile.orig build-profile.json5 2>/dev/null || true' EXIT
  python3 merge-signing.py
fi

# ── 前端：clients/mobile 那套 Vue 构建进 rawfile ──
# base=./ 是必需的：ArkWeb 从 resource://rawfile/ 加载，绝对路径会 404。
echo "▸ 构建前端 UI"
( cd ../mobile && npx vite build --base=./ >/dev/null )
RAW=entry/src/main/resources/rawfile
rm -rf "${RAW:?}"/* 2>/dev/null || true
mkdir -p "$RAW"
cp -R ../mobile/dist/* "$RAW/"
echo "  UI 已就位：$(find "$RAW" -type f | wc -l | tr -d ' ') 个文件，$(du -sh "$RAW" | cut -f1)"

echo "▸ 构建 HAP（$MODE）"
hvigorw assembleHap -p product=default -p "buildMode=$MODE" --no-daemon

HAP=$(find entry/build -name "*-signed.hap" | head -1)
if [ -z "$HAP" ]; then
  echo "✗ 只产出了未签名的 HAP —— 装不到真机上。见 README「签名」" >&2
  find entry/build -name "*.hap" >&2
  exit 1
fi
echo "✓ $HAP"

case "$CMD" in
  install|run)
    DEV="${BAIDI_HDC_TARGET:-$(hdc list targets | head -1 | tr -d '\r')}"
    [ -n "$DEV" ] && [ "$DEV" != "[Empty]" ] || { echo "没有已连接的设备（hdc list targets 为空）" >&2; exit 1; }
    echo "▸ 安装到 $DEV"
    hdc -t "$DEV" install -r "$HAP"
    if [ "$CMD" = run ]; then
      BUNDLE=$(python3 -c "import json,re,sys;s=open('AppScope/app.json5',encoding='utf-8').read();print(re.search(r\"bundleName:\s*'([^']+)'\",s).group(1))")
      echo "▸ 拉起 $BUNDLE"
      hdc -t "$DEV" shell aa start -a EntryAbility -b "$BUNDLE"
    fi
    ;;
esac
