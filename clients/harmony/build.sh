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
# base=./ 在 vite.harmony.config.ts 里设了：ArkWeb 从 resource://rawfile/ 加载，
# 绝对路径会 404。
echo "▸ 构建前端 UI（clients/desktop 那套 Vue，桌面布局；Tauri API 经 webui/shim 替换）"
( cd ../desktop && npx vite build -c vite.harmony.config.ts >/dev/null )
# ★内联成单文件：ArkWeb 的 resource://rawfile/ 不在它自己的 CORS 白名单里，
# 子资源（JS/CSS）会被拦掉，表现为纯白屏且不报加载失败。详见 inline-webui.py。
python3 inline-webui.py webui/dist
RAW=entry/src/main/resources/rawfile
rm -rf "${RAW:?}"/* 2>/dev/null || true
mkdir -p "$RAW"
cp webui/dist/index.html "$RAW/"
echo "  UI 已就位：$(find "$RAW" -type f | wc -l | tr -d ' ') 个文件，$(du -sh "$RAW" | cut -f1)"

echo "▸ 构建 HAP（$MODE）"
# ★不让 set -e 直接吞掉：签名失败是最常见的一种失败，而它的补救动作很具体
# （去 DevEco 点一次自动签名），值得单独给提示而不是丢一堆 hvigor 栈。
BUILD_RC=0
hvigorw assembleHap -p product=default -p "buildMode=$MODE" --no-daemon || BUILD_RC=$?

HAP=$(find entry/build -name "*-signed.hap" 2>/dev/null | head -1)
UNSIGNED=$(find entry/build -name "*-unsigned.hap" 2>/dev/null | head -1)
if [ "$BUILD_RC" -ne 0 ] && [ -z "$UNSIGNED" ]; then
  echo "✗ 构建失败（非签名问题），见上方 hvigor 输出" >&2
  exit "$BUILD_RC"
fi
if [ -z "$HAP" ]; then
  echo "" >&2
  echo "✗ 只产出了未签名的 HAP —— 装不到真机上。" >&2
  BN=$(python3 -c "import re;s=open('AppScope/app.json5',encoding='utf-8').read();print(re.search(r\"bundleName:\s*'([^']+)'\",s).group(1))" 2>/dev/null || echo "?")
  echo "  当前 bundleName：$BN" >&2
  echo "  鸿蒙真机只装签过名的 HAP，而 profile 由华为签发、同时绑 bundleName 与设备 UDID。" >&2
  echo "  在 DevEco Studio 里为本工程点一次自动签名即可（一次性，之后全命令行）：" >&2
  echo "    File → Project Structure → Signing Configs → 勾 Automatically generate signature" >&2
  echo "  生成后把 signingConfigs 段落存进 signing-local.json5（不入库），详见 README。" >&2
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
