#!/usr/bin/env bash
# 打包前复核 wintun 暂存区：固定位那份 wintun.dll 到底是哪个架构，与本次要打的包对不对得上。
#
# 用法：
#   ./verify-wintun-stage.sh                              # 目标自动判定：TAURI_ENV_* > rustc host
#   ./verify-wintun-stage.sh --triple x86_64-pc-windows-msvc
#   ./verify-wintun-stage.sh --triple … --stage /path/binaries/wintun   # 供单测构造场景
# 退出码：0 = 通过，或目标不是 Windows（不适用，直接跳过）；1 = 不通过。
#
# ── 为什么需要这一步 ───────────────────────────────────────────────────────
# `fetch-wintun.sh --arch <a>` 会把选定架构的 DLL 复制到打包配置引用的固定路径
# `binaries/wintun/wintun.dll`，并把"它是哪个架构"写进旁边的 `wintun.dll.triple`。
# 但那个文件此前**只写不读**——全仓没有任何消费方，于是「固定位那份是哪个架构」
# 这条信息没有执行方，等于没记。
#
# 它兜的是这个失败形态：有人在打包机上手工跑过 `./fetch-wintun.sh`（比如排障时跑了
# 一次 `--arch all` 之后又单跑了一次别的架构），而不是经 build-sidecars.sh 按 GOARCH 调用。
# 此时暂存区里两个架构目录都在，固定位躺着的却是另一个架构那份。接下来：
#   tauri build 不报错 → 安装包打得出 → 装得上 → DLL 确实躺在 baidi-tun.exe 旁边
#   → 只有用户点「接入」那一刻，才由 elevate.rs 的架构复核报出一句「架构不匹配」。
# 这正是本项目最忌讳的静默失效：构建日志、安装过程、文件清单里全都看不出来。
#
# CI 里还有一道同类断言（.github/workflows/clients.yml 自己重解 PE 头比对 rustc 三元组），
# 但**本地构建完全没有守卫**，而本地打出来的包一样会发给人。两道判据来源不同（那边读
# DLL 的 PE machine 码，这边读取件脚本自报的三元组），对不上时说明暂存区被手工动过。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TRIPLE=""
STAGE="$HERE/binaries/wintun"
while [ $# -gt 0 ]; do
  case "$1" in
    --triple) TRIPLE="${2:-}"; shift 2 ;;
    --triple=*) TRIPLE="${1#--triple=}"; shift ;;
    --stage) STAGE="${2:-}"; shift 2 ;;
    --stage=*) STAGE="${1#--stage=}"; shift ;;
    -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "✗ 未知参数：$1（用 --help 看用法）" >&2; exit 1 ;;
  esac
done

# ── 目标三元组：显式参数 > Tauri 注入的目标环境 > rustc host ────────────────
# ★优先 TAURI_ENV_*（beforeBundleCommand 里 Tauri 会设）而不是 rustc host：交叉打包时
#   host 是构建机、不是产物架构，按 host 判会把一次真实的错配放过去。
#
# ★平台后缀必须按平台真的映射，不能套一个模板。原先写的是
#   TRIPLE="${TAURI_ENV_ARCH}-pc-${TAURI_ENV_PLATFORM}-msvc"
# 于是 Linux 构建日志里赫然出现 `x86_64-pc-linux-msvc` 这个**不存在的三元组**。
# 结论碰巧是对的（不含 windows → 跳过），但判据是编出来的：Tauri 哪天把平台值
# 从 `windows` 改成别的写法，这里就会在**真正的 Windows 构建**上安静地跳过检查，
# 而日志看起来与今天一模一样。所以「是不是 Windows」直接问 TAURI_ENV_PLATFORM，
# 不再从拼出来的字符串里回捞。
if [ -z "$TRIPLE" ]; then
  if [ -n "${TAURI_ENV_PLATFORM:-}" ] && [ -n "${TAURI_ENV_ARCH:-}" ]; then
    case "$TAURI_ENV_PLATFORM" in
      windows)      TRIPLE="${TAURI_ENV_ARCH}-pc-windows-msvc" ;;
      darwin|macos) TRIPLE="${TAURI_ENV_ARCH}-apple-darwin" ;;
      linux)        TRIPLE="${TAURI_ENV_ARCH}-unknown-linux-gnu" ;;
      android)      TRIPLE="${TAURI_ENV_ARCH}-linux-android" ;;
      ios)          TRIPLE="${TAURI_ENV_ARCH}-apple-ios" ;;
      # 认不出的平台**不许静悄悄当成非 Windows**——那正是这道检查失去执行方的方式。
      *) echo "✗ 认不出 TAURI_ENV_PLATFORM=${TAURI_ENV_PLATFORM}。不敢替它判断是否 Windows：" >&2
         echo "  猜错的方向是「跳过检查」，而那会让一次真实的架构错配直接进包。" >&2
         echo "  请在本脚本的平台映射里补上它，或显式传 --triple。" >&2
         exit 1 ;;
    esac
  elif command -v rustc >/dev/null 2>&1; then
    TRIPLE="$(rustc -vV | sed -n 's/host: //p' | tr -d '\r')"
  else
    echo "✗ 判不出目标三元组（没有 --triple、没有 TAURI_ENV_*、也没有 rustc）。" >&2
    exit 1
  fi
fi

# 只比「操作系统 + 架构」两项，不做整串字符串比对：取件脚本一律写 msvc 后缀，
# 而 host 三元组可能是 `x86_64-pc-windows-gnu`——按整串比会把一次正确的取件报成错配。
triple_arch() { printf '%s' "${1%%-*}"; }
is_windows()  { case "$1" in *windows*) return 0 ;; *) return 1 ;; esac; }

if ! is_windows "$TRIPLE"; then
  echo "==> 目标 $TRIPLE 不是 Windows，wintun 暂存区检查不适用，跳过。"
  exit 0
fi

echo "==> 复核 wintun 暂存区：${STAGE}（目标 ${TRIPLE}）"

fail() { echo "✗ $*" >&2; exit 1; }

# ── 该在的文件 ─────────────────────────────────────────────────────────────
[ -s "$STAGE/wintun.dll" ] || fail "缺 $STAGE/wintun.dll。
  可能是没跑取件，也可能是跑了 './fetch-wintun.sh --arch all'——多架构时它**主动删掉**固定位，
  就是为了不留一份架构对不上的在那儿。打包请指定单一架构：./fetch-wintun.sh --arch amd64"

# 许可原文缺席不是小事：README-windows.txt 与 BUILD.md 都对外说了「许可原文随包附上」，
# 少了它，发出去的包与我们自己的说明不符。（这是我们自愿的承诺，不是许可条款的要求。）
[ -s "$STAGE/wintun-LICENSE.txt" ] || fail "缺 $STAGE/wintun-LICENSE.txt —— 我们承诺许可原文随包附上，它必须与 DLL 同时在场。"

[ -s "$STAGE/wintun.dll.triple" ] || fail "缺 $STAGE/wintun.dll.triple。
  取件脚本在产出固定位 wintun.dll 时会一并写下它是哪个架构；只有 DLL 没有这条记录，
  说明固定位那份是手工放进去的——而「手工放的那份是哪个架构」恰恰没人能替你回答。"

GOT="$(tr -d ' \t\r\n' < "$STAGE/wintun.dll.triple")"

# ── 架构必须对得上 ─────────────────────────────────────────────────────────
if ! is_windows "$GOT" || [ "$(triple_arch "$GOT")" != "$(triple_arch "$TRIPLE")" ]; then
  fail "wintun.dll 架构错配 —— 暂存区里那份不是本次要打的架构。
    固定位 $STAGE/wintun.dll 记录的是：$GOT
    本次打包的目标三元组是      ：$TRIPLE
  这个错配不会让构建失败：包照样打得出、装得上、DLL 也确实在 baidi-tun.exe 旁边，
  只有用户点「接入」那一刻才会拿到一句加载失败。
  修法：$HERE/fetch-wintun.sh --arch $(triple_arch "$TRIPLE")"
fi

# ── 固定位与按架构分放的那份必须逐字节相同 ─────────────────────────────────
# .triple 是取件脚本自报的，只信它等于只信一句话。分架构目录那份是从官方 zip 原样解出的，
# 拿它做交叉印证：两者对不上，说明固定位的 DLL 在取件之后被人动过（或换过）。
BY_ARCH="$STAGE/$GOT/wintun.dll"
if [ -f "$BY_ARCH" ]; then
  if ! cmp -s "$BY_ARCH" "$STAGE/wintun.dll"; then
    fail "固定位 $STAGE/wintun.dll 与 $BY_ARCH 内容不一致。
  .triple 说它是 ${GOT}，但它与该架构原样解出的那份对不上 —— 取件之后被改过或被覆盖过。
  别猜，重跑一次取件：$HERE/fetch-wintun.sh --arch $(triple_arch "$TRIPLE")"
  fi
  echo "    ✓ 与 $GOT/wintun.dll 逐字节一致"
fi

echo "✓ wintun 暂存区就绪：${GOT}，许可原文在场"
