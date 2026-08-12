#!/usr/bin/env bash
# 取 Wintun 预编译 DLL —— Windows 数据面（baidi-tun.exe 建虚拟网卡）的唯一外部二进制依赖。
#
# 用法：
#   ./fetch-wintun.sh                 # 默认：Windows 主机取本机架构；非 Windows 主机取全部架构
#   ./fetch-wintun.sh --arch amd64    # 只取一个架构（amd64|x86_64 / arm64|aarch64）
#   ./fetch-wintun.sh --arch all      # 取全部（离线预取 / 检视用）
#   BAIDI_WINTUN_ZIP=/path/wintun-0.14.1.zip ./fetch-wintun.sh   # 离线 / 内网：用本地 zip
#
# 为什么单独一个脚本（而不是并进 build-sidecars.sh）：
#   下载 + 校验是**供应链**这一环，排障时要能脱离 Go 工具链单独跑（内网构建机常常只有网络问题，
#   或者反过来只有 zip 没有网络）。build-sidecars.sh 在 GOOS=windows 时会调它，两种用法都成立。
#
# ── 为什么不把 DLL 提交进仓库 ───────────────────────────────────────────────
# 本仓库被 13MB 预编译二进制坑过一次（见 CLAUDE.md「坑」：gateway/baidi-tun 至今还躺在 git 历史里）。
# 二进制入库之后没人再核对它的来源，clone 的人也无从判断它是不是官方那一份。
# 改成「构建期下载 + 强校验哈希」：来源、版本、指纹三者都在这个文件里写死，可审阅、可复现。
#
# ── 许可（必须遵守，不是形式）─────────────────────────────────────────────
# Wintun 的「Prebuilt Binaries License」默认禁止再分发，但第 3(d) 条留了一条例外：
# 随「只经 Permitted API 使用本软件的其他软件」一同分发是允许的。baidi-tun 的 Go 绑定
# 只调用 wintun.h 导出的函数，落在这条例外里，**随白帝客户端分发是合法的**。附带义务两条：
#   (a) 不得改动 DLL、不得从中剥掉版权注记 —— 出处是第 3 条 a/b/c 三项（a 禁 modify，
#       b 禁衍生作品且只放行"仅使用 wintun.h 的 API 接口"，c 禁 remove any proprietary
#       notices *from the Software*）。执行方是同一件事：本脚本从官方 zip **原样解出**，
#       不改名、不加壳、不重签。
#   (b) 不得用 WireGuard / Wintun 的名号为本产品背书 —— 第 3 条 e 项。UI/文案里只做事实陈述
#       （「Windows 用 Wintun 建虚拟网卡」「到 wintun.net 取 DLL」），不得写成合作/认证/推荐。
#
# ★LICENSE.txt 随包附上是**我们自愿**的做法，许可原文并未要求：§1 把 "Software" 定义为
#   wintun.dll 的精确内容，3(c) 管的是"不得从那个二进制里移除版权注记"，通篇没有
#   "必须附带许可文件"这一条。仍然要附，是因为收到包的人应当能读到约束这份 DLL 的条款。
#   但**不许把它写成许可的硬性要求**——那等于替第三方许可作一个原文没有的事实陈述，
#   而这句话会随安装包发到用户手里（README-windows.txt）。
#
# ── 产物落位（本脚本只负责取件与暂存）───────────────────────────────────────
#   binaries/wintun/LICENSE.txt                          ← 许可原文，随包分发
#   binaries/wintun/<rust 三元组>/wintun.dll             ← 按架构分放，互不覆盖
#   binaries/wintun/wintun.dll                           ← 只在选定**单一**架构时产出：
#   binaries/wintun/wintun.dll.triple                    ←   打包配置引用的固定路径 + 它是哪个架构
#
# 运行期约束（读 wintun 绑定源码 dll.go:86 得到，与 src/elevate.rs::wintun_search_paths 同口径）：
#   wintun 用 LoadLibraryEx(name, 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32)
#   加载 DLL —— **只**看「进程自身 exe 所在目录」与 System32，不看 PATH、不看当前目录。
#   我们的进程是 sidecar baidi-tun.exe，所以最终必须是 <安装目录>\wintun.dll —— Tauri 把
#   externalBin sidecar 与 bundle.resources 都装进安装根目录（NSIS 的 $INSTDIR / MSI 的
#   INSTALLDIR），两者同目录。**把暂存区的文件真正装进安装包**是打包配置那一步的事
#   （tauri.windows.conf.json 的 bundle.resources，**必须是映射形 + 目的地空串**，
#   写成列表形会保留 binaries/wintun/ 这层目录 → 装进子目录 → wintun 永远找不到），
#   本脚本不做——它只保证"取到的这份是官方那一份"。
set -euo pipefail

# ── 上游常量：版本 / URL / SHA-256 三者必须一起改 ───────────────────────────
# 来源：https://www.wintun.net/ 官网下载页与其公布的 SHA-256。
# 核实日期：2026-08-11，人工逐字符比对官网公布值，一致。
# ★三个常量刻意挨在一起：这样「改了版本忘了改哈希」在视觉上无处可藏。真忘了也不会静默——
#   下面那道校验会当场拒绝一个哈希对不上的包，而不是把一个未知二进制放进安装包。
# 注：git.zx2c4.com/wintun/builds/… 那条路径现在是 404，不要用。
readonly WINTUN_VERSION="0.14.1"
readonly WINTUN_URL="https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"
readonly WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
# 仅用于报错时多给一句人话（"你拿到的是不是一个 HTML 错误页 / 半截文件"）。安全性由哈希承担。
readonly WINTUN_ZIP_BYTES=750540

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CACHE_DIR="$HERE/.wintun-cache"
readonly STAGE_DIR="$HERE/binaries/wintun"

TMP=""
cleanup() {
  if [ -n "$TMP" ] && [ -f "$TMP" ]; then rm -f "$TMP"; fi
}
trap cleanup EXIT

# ── 小工具 ─────────────────────────────────────────────────────────────────

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "✗ 找不到 sha256sum / shasum：没有校验手段就不取件（宁可构建失败，不要放进一个来路不明的 DLL）。" >&2
    exit 1
  fi
}

file_bytes() { wc -c < "$1" | tr -d ' '; }

# amd64|arm64 → Rust 三元组。Wintun zip 里用 amd64/arm64，Rust/Tauri 用 x86_64/aarch64，
# 两套词汇必须在这一处映射完，别在调用点各写各的。
arch_triple() {
  case "$1" in
    amd64) echo "x86_64-pc-windows-msvc" ;;
    arm64) echo "aarch64-pc-windows-msvc" ;;
    *) echo "✗ 未知架构 $1" >&2; return 1 ;;
  esac
}

normalize_arch() {
  case "$1" in
    amd64|x86_64|x64|AMD64) echo "amd64" ;;
    arm64|aarch64|ARM64) echo "arm64" ;;
    *) return 1 ;;
  esac
}

# ── 哈希强校验（fail-closed）────────────────────────────────────────────────
# 只判定与打印，**不删文件**：删不删取决于来源（我们下载的可以删，用户自己的 zip 不能碰），
# 由调用方决定。
verify_zip() {
  local f="$1" src="$2" got
  got="$(sha256_of "$f")"
  [ "$got" = "$WINTUN_SHA256" ] && return 0
  cat >&2 <<EOF
✗ wintun-${WINTUN_VERSION}.zip 哈希不匹配（来源：${src}）
    期望 SHA-256：${WINTUN_SHA256}
    实际 SHA-256：${got}
    实际大小：$(file_bytes "$f") 字节（期望 ${WINTUN_ZIP_BYTES}）
  这不是「重试一下就好」的错误。按危险程度排序，可能的原因是：
    1) 传输被劫持 / 镜像被投毒 —— 这个 DLL 会被以**管理员权限**加载进数据面进程；
    2) 上游原地替换了同名发布包（供应链上游改包，同样必须人工核对后才能改常量）；
    3) 下载被截断，或代理返回了一个 HTML 错误页（看一眼上面的实际大小就能分辨）。
  ★不要绕过这道校验，也不要「先注释掉跑通再说」。正确做法：人工到 https://www.wintun.net/
    核对官网公布的 SHA-256，确认无误后同时更新本脚本顶部的
    WINTUN_VERSION / WINTUN_URL / WINTUN_SHA256 三个常量。
EOF
  return 1
}

# ── 解包：unzip / bsdtar / 7z 三选一 ────────────────────────────────────────
# Windows CI 的 Git Bash 不一定有 unzip，但 Windows 10+ 自带的 tar 是 bsdtar（能读 zip）。
# GNU tar 读不了 zip，所以用一次 `tar -tf` 探测而不是看有没有 tar 这个命令。
extract_member() {
  local zip="$1" member="$2" dest="$3"
  mkdir -p "$(dirname "$dest")"
  if command -v unzip >/dev/null 2>&1; then
    if ! unzip -p "$zip" "$member" > "$dest"; then
      echo "✗ 解包失败（unzip）：$member" >&2; rm -f "$dest"; return 1
    fi
  elif tar -tf "$zip" >/dev/null 2>&1; then
    if ! tar -xOf "$zip" "$member" > "$dest"; then
      echo "✗ 解包失败（bsdtar）：$member" >&2; rm -f "$dest"; return 1
    fi
  elif command -v 7z >/dev/null 2>&1; then
    if ! 7z x -so "$zip" "$member" > "$dest" 2>/dev/null; then
      echo "✗ 解包失败（7z）：$member" >&2; rm -f "$dest"; return 1
    fi
  else
    echo "✗ 没有可用的解包工具（unzip / bsdtar / 7z），无法从 zip 取件。" >&2
    return 1
  fi
  # 空文件必须当失败：某些解包器对「成员不存在」也回 0，只是什么都没写。
  # 静默产出一个 0 字节的 wintun.dll，症状会推迟到用户机器上才出现。
  if [ ! -s "$dest" ]; then
    echo "✗ 解出的 $member 是空文件 —— zip 内部结构与预期不符（上游改了目录布局？）" >&2
    rm -f "$dest"; return 1
  fi
}

# ── 参数 ───────────────────────────────────────────────────────────────────

ARCH_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) ARCH_ARG="${2:-}"; shift 2 ;;
    --arch=*) ARCH_ARG="${1#--arch=}"; shift ;;
    -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "✗ 未知参数：$1（用 --help 看用法）" >&2; exit 1 ;;
  esac
done

if [ -z "$ARCH_ARG" ]; then
  # 默认值：Windows 主机上取本机架构（就是要打包的那个），其他主机取全部。
  # ★非 Windows 主机刻意不猜一个"默认架构"：mac/Linux 上根本打不出 Windows 包，
  #   猜一个只会让暂存区留下一份看着像能用、实际没人验证过的东西。
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) ARCH_ARG="$(normalize_arch "$(uname -m)" || echo amd64)" ;;
    *) ARCH_ARG="all" ;;
  esac
fi

ARCHES=()
if [ "$ARCH_ARG" = "all" ]; then
  ARCHES=(amd64 arm64)
else
  a="$(normalize_arch "$ARCH_ARG")" || {
    echo "✗ --arch 只接受 amd64|x86_64 / arm64|aarch64 / all，收到：$ARCH_ARG" >&2; exit 1; }
  ARCHES=("$a")
fi

echo "==> Wintun ${WINTUN_VERSION}，目标架构：${ARCHES[*]}"

# ── 取 zip：本地指定 > 缓存命中 > 下载。三条路径**都**过同一道哈希校验 ────────

ZIP=""
if [ -n "${BAIDI_WINTUN_ZIP:-}" ]; then
  if [ ! -f "$BAIDI_WINTUN_ZIP" ]; then
    echo "✗ BAIDI_WINTUN_ZIP 指向的文件不存在：$BAIDI_WINTUN_ZIP" >&2; exit 1
  fi
  echo "==> 用本地 zip（BAIDI_WINTUN_ZIP）：$BAIDI_WINTUN_ZIP"
  # ★本地路径同样强校验：「给了本地文件就跳过校验」的话这道闸等于没有——
  #   内网构建机上那份 zip 的来路，与网上下载的那份一样不可自证。
  if ! verify_zip "$BAIDI_WINTUN_ZIP" "BAIDI_WINTUN_ZIP 本地文件"; then
    echo "  （刻意没有删除你自己的文件；请自行核对它的来源。）" >&2
    exit 1
  fi
  ZIP="$BAIDI_WINTUN_ZIP"
else
  ZIP="$CACHE_DIR/wintun-${WINTUN_VERSION}.zip"
  mkdir -p "$CACHE_DIR"
  # 幂等：缓存在且哈希正确就不再下载（CI 缓存友好，本地反复构建不重复拉）。
  # 注意「在且哈希正确」是一个判据，不是两个：只看文件在不在，等于把一份被改过的缓存永久信下去。
  if [ -f "$ZIP" ] && verify_zip "$ZIP" "本地缓存" 2>/dev/null; then
    echo "==> 缓存命中且哈希正确，跳过下载：$ZIP"
  else
    if [ -f "$ZIP" ]; then
      echo "⚠ 缓存文件哈希不对，删掉重下：$ZIP"
      rm -f "$ZIP"
    fi
    echo "==> 下载 $WINTUN_URL"
    TMP="$(mktemp "${TMPDIR:-/tmp}/wintun-dl.XXXXXX")"
    if command -v curl >/dev/null 2>&1; then
      # ★两个 --proto* 缺一不可：`--proto '=https'` 只约束**首个** URL。少了
      #   `--proto-redir '=https'`，一个 30x 跳到 http:// 的响应会被 -L 老老实实跟过去，
      #   整包明文取回。哈希校验兜得住投毒（结果是构建失败），但这道纵深是零成本的，
      #   而且少了它，文档里「下载地址只有 https 这一条」与实际可达的协议就不相等了。
      curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 -o "$TMP" "$WINTUN_URL"
    elif command -v wget >/dev/null 2>&1; then
      # ★wget 没有 --proto-redir 这种东西，而 `--https-only` 按 man 页**只在递归模式生效**——
      #   非递归下它管不住重定向，写了只是看着安心。所以这条路径改成**直接禁止重定向**：
      #   实测（2026-08-12）该 URL 是 200、零跳转，禁掉不影响正常取件；哪天上游真改成
      #   跳转，会当场报错而不是安静地降级成明文 http。
      if ! wget -q --https-only --max-redirect=0 -O "$TMP" "$WINTUN_URL"; then
        cat >&2 <<'EOF'
✗ wget 取件失败。若是因为上游改成了 30x 跳转：wget 无法约束跳转之后的协议
  （--https-only 只在递归模式生效），所以这里刻意不允许它跟随重定向。
  处理办法：改用 curl（它有 --proto-redir '=https'），或在别处下好后用 BAIDI_WINTUN_ZIP 指过来。
EOF
        exit 1
      fi
    else
      echo "✗ 既没有 curl 也没有 wget，无法下载。可先在别处下好，再用 BAIDI_WINTUN_ZIP 指过来。" >&2
      exit 1
    fi
    # 校验不过立刻删：不给「下次跑的时候它已经在缓存里了」留任何机会。
    if ! verify_zip "$TMP" "刚下载的文件"; then
      rm -f "$TMP"; TMP=""
      exit 1
    fi
    mv "$TMP" "$ZIP"; TMP=""
    echo "    ✓ SHA-256 校验通过（$(file_bytes "$ZIP") 字节）"
  fi
fi

# ── 解件 ───────────────────────────────────────────────────────────────────

mkdir -p "$STAGE_DIR"

# 许可原文：我们自愿随包附上（不是许可条款的要求，出处见顶部注释）。它和 DLL 一起解，
# 就不会出现「DLL 更新了、许可还是旧版本」或者「打包时漏了它」。
extract_member "$ZIP" "wintun/LICENSE.txt" "$STAGE_DIR/LICENSE.txt"
echo "==> 许可：$STAGE_DIR/LICENSE.txt（$(file_bytes "$STAGE_DIR/LICENSE.txt") 字节，随安装包一起附上）"

echo "==> DLL（从官方 zip 原样解出，不做任何加工）"
for a in "${ARCHES[@]}"; do
  triple="$(arch_triple "$a")"
  dest="$STAGE_DIR/$triple/wintun.dll"
  extract_member "$ZIP" "wintun/bin/$a/wintun.dll" "$dest"
  printf '    %-26s %8s 字节  sha256=%s\n' "$triple" "$(file_bytes "$dest")" "$(sha256_of "$dest")"
done

# ── 打包暂存位 ─────────────────────────────────────────────────────────────
# 打包配置只能引用一条固定路径，所以「哪个架构」必须在取件这一步定死。
if [ "${#ARCHES[@]}" -eq 1 ]; then
  triple="$(arch_triple "${ARCHES[0]}")"
  cp "$STAGE_DIR/$triple/wintun.dll" "$STAGE_DIR/wintun.dll"
  printf '%s\n' "$triple" > "$STAGE_DIR/wintun.dll.triple"
  echo "==> 打包暂存位：$STAGE_DIR/wintun.dll（${triple}）"
else
  # ★多架构时**主动删掉**固定位，而不是留着上一次那份。
  #   留一份架构对不上的 DLL 在那里，打包不会报错、安装包也装得上，
  #   只有用户点「接入」那一刻才会拿到一句看不懂的加载失败——这正是本项目最忌讳的失败形态。
  rm -f "$STAGE_DIR/wintun.dll" "$STAGE_DIR/wintun.dll.triple"
  echo "==> 取了多个架构，未产出固定位 $STAGE_DIR/wintun.dll（已清除旧的，避免架构错配）"
  echo "    要打包请指定单一架构：./fetch-wintun.sh --arch amd64"
fi

echo "✓ 完成"
