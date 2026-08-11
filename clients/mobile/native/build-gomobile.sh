#!/usr/bin/env bash
# 把白帝移动数据面引擎(baidimobile)编成 iOS .xcframework / 安卓 .aar。
#
#   用法：build-gomobile.sh [all|android|ios]      默认 all
#   需：Go + gomobile；iOS 需 macOS + Xcode；Android 需 Android SDK + NDK。
#       go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
#
# ★为什么加 target 参数：原先无条件先编 iOS 再编 Android。iOS 那一条只可能在装了
#   Xcode 的 macOS 上成功，于是在 Linux CI 上第一步就 `set -e` 退出——"安卓到底能不能
#   编出来"这个问题永远得不到回答，日志看起来还像是"这脚本在 CI 上根本不能用"。
#
# ★为什么脚本要把 .aar 复制进 android/app/libs：gradle 工程写死
#   `implementation(files("libs/baidimobile.aar"))`，而该目录被 .gitignore 排除。
#   此前"从 out/ 拷进 libs/"是一步无人记录的手工动作：漏了它 gradle 报的是
#   Kotlin 侧 `Unresolved reference: Baidimobile`，与"绑定层源码写错了"完全同形。
#
# ★BAIDI_GOMOBILE_DRYRUN=1：只打印将要执行的命令与落点，不真跑。
#   本机（macOS，无 Android SDK/NDK、gomobile 也跑不起来）产不出真产物，但命令构造
#   与落点路径必须能在本机逐字断言——与 posture.rs / sysstat 那条
#   「只活在某个平台分支里的代码是验不到的」是同一条纪律：把"构造"与"执行"分开，
#   构造部分任何主机都能走一遍。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW="$(cd "$HERE/../../../gateway" && pwd)"
OUT="$HERE/out"
LIBS="$HERE/android/app/libs"
PKG="baidi.dev/gateway/mobile/baidimobile"

TARGET="${1:-all}"
DRYRUN="${BAIDI_GOMOBILE_DRYRUN:-0}"

case "$TARGET" in
  all|android|ios) ;;
  *) echo "✗ 未知目标：$TARGET（可选 all|android|ios）" >&2; exit 2 ;;
esac

# ── 薄薄一层"真正执行"：dry-run 时只打印。上面的一切都是纯构造。 ──
run() {
  echo "+ $*"
  if [ "$DRYRUN" = "1" ]; then return 0; fi
  "$@"
}

# gomobile 可执行文件的定位。
# ★不能只 `command -v gomobile`：`go install` 把它装在 $(go env GOPATH)/bin，
#   那个目录不一定在 PATH 上（GitHub Actions 的 setup-go 之后就常常不在）。
#   只认 PATH 的话，明明刚装好却报"缺 gomobile"，人会以为是 go install 失败了。
resolve_gomobile() {
  if command -v gomobile >/dev/null 2>&1; then
    command -v gomobile
    return 0
  fi
  local gopath
  gopath="$(go env GOPATH 2>/dev/null || true)"
  if [ -n "$gopath" ] && [ -x "$gopath/bin/gomobile" ]; then
    echo "$gopath/bin/gomobile"
    return 0
  fi
  return 1
}

# NDK 定位：找到就 export 给 gomobile 用，找不到只告警不拦。
# ★刻意不 fail-closed：这个探测只覆盖几种常见布局，一个探测不到但其实可用的环境
#   被它拦下来，比让 gomobile 自己报那句很清楚的 "no Android NDK found" 更糟。
ensure_ndk() {
  if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "${ANDROID_NDK_HOME}" ]; then
    echo "→ NDK：$ANDROID_NDK_HOME（ANDROID_NDK_HOME）"
    return 0
  fi
  if [ -n "${ANDROID_NDK_ROOT:-}" ] && [ -d "${ANDROID_NDK_ROOT}" ]; then
    export ANDROID_NDK_HOME="$ANDROID_NDK_ROOT"
    echo "→ NDK：$ANDROID_NDK_HOME（ANDROID_NDK_ROOT）"
    return 0
  fi
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [ -n "$sdk" ]; then
    if [ -d "$sdk/ndk-bundle" ]; then
      export ANDROID_NDK_HOME="$sdk/ndk-bundle"
      echo "→ NDK：$ANDROID_NDK_HOME（\$ANDROID_HOME/ndk-bundle）"
      return 0
    fi
    # $ANDROID_HOME/ndk/<版本>：装了多个版本时取**版本序**最大的那个。
    # 必须 sort -V 不能靠字典序/glob 顺序：27.2.x 与 9.0.x 的字典序是反的，
    # 装过两个大版本的机器上会稳定挑到旧的那个，而一切看起来都正常。
    local latest
    latest="$(find "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; 2>/dev/null | sort -V | tail -n 1 || true)"
    if [ -n "$latest" ] && [ -d "$sdk/ndk/$latest" ]; then
      export ANDROID_NDK_HOME="$sdk/ndk/$latest"
      echo "→ NDK：$ANDROID_NDK_HOME（\$ANDROID_HOME/ndk/$latest）"
      return 0
    fi
  fi
  echo "⚠ 没探到 Android NDK（查过 ANDROID_NDK_HOME / ANDROID_NDK_ROOT / \$ANDROID_HOME/ndk-bundle / \$ANDROID_HOME/ndk/*）；"
  echo "  继续往下跑，让 gomobile 自己报——它那句 'no Android NDK found' 比这里瞎猜更准。"
}

build_android() {
  ensure_ndk
  echo "==> Android .aar（放安卓 app/libs，VpnService 工程引用）"
  run "$GOMOBILE" bind -target=android -androidapi 21 -o "$OUT/baidimobile.aar" "$PKG"
  # 落到 gradle 真正引用的位置——这一步以前是手工的，见文件头说明。
  run mkdir -p "$LIBS"
  run cp "$OUT/baidimobile.aar" "$LIBS/baidimobile.aar"
  echo "→ gradle 引用点：$LIBS/baidimobile.aar"
}

build_ios() {
  # 这一条 fail-closed 是安全的：Linux 上 gomobile bind -target=ios 不存在"其实能跑"的情形。
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "✗ iOS 只能在 macOS 上编（当前 $(uname -s)）。CI 上请显式指定 android。" >&2
    exit 1
  fi
  if [ "$DRYRUN" != "1" ] && ! command -v xcodebuild >/dev/null 2>&1; then
    echo "✗ 缺 Xcode（xcodebuild 不在 PATH）：gomobile bind -target=ios 需要完整 Xcode，命令行工具不够。" >&2
    exit 1
  fi
  echo "==> iOS .xcframework（拖进 Xcode 的 Network Extension target）"
  run "$GOMOBILE" bind -target=ios -o "$OUT/Baidimobile.xcframework" "$PKG"
}

GOMOBILE="$(resolve_gomobile || true)"
if [ -z "$GOMOBILE" ]; then
  if [ "$DRYRUN" = "1" ]; then
    GOMOBILE="gomobile" # dry-run 只验命令构造，不要求工具链在场
  else
    echo "✗ 缺 gomobile：go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init" >&2
    echo "  （装完若仍报此错，把 \$(go env GOPATH)/bin 加进 PATH）" >&2
    exit 1
  fi
fi
echo "→ gomobile：$GOMOBILE"
if [ "$DRYRUN" = "1" ]; then
  echo "→ 目标：$TARGET（DRY-RUN，不真跑）"
else
  echo "→ 目标：$TARGET"
fi

run mkdir -p "$OUT"
cd "$GW"

case "$TARGET" in
  android) build_android ;;
  ios)     build_ios ;;
  all)     build_ios; build_android ;;
esac

if [ "$DRYRUN" = "1" ]; then
  echo "✓ DRY-RUN 结束（未产出任何文件）"
  exit 0
fi
echo "✓ 产物 → $OUT"
ls -la "$OUT"
