#!/usr/bin/env bash
# promote-standby.sh —— 把一台温备节点提升为主控制面（PRD 15.5 / FR-ARCH-03）。
#
# 白帝的控制面是**温备（warm standby）不是双活**：SQLite 单写者，两个实例同时写同一个库
# 会在写冲突时静默丢配置。所以切换是这样一条**人工触发**的流水线，而不是自动选主
# （两节点没有仲裁第三方，自动选主必然脑裂，而脑裂意味着两个控制面同时签发令牌）。
#
#   ① 前置检查（备份在不在、口令有没有、二进制能不能跑）
#   ② 校验备份完整性（解密 + 必须含 baidi.db）—— 不通过就此打住，不碰现网任何文件
#   ③ 解到暂存目录
#   ④ --dry-run 到此为止：打印将要覆盖的清单后退出 0
#   ⑤ 停服务 → 把现有材料整体挪到 pre-promote 快照 → 覆盖 → 起服务
#   ⑥ 自检 /healthz
#
# ★RPO = 备机的同步间隔：最后一次成功同步之后的配置改动，切换后不存在。
#   跑之前先看一眼 `baidi-standby -status -dir DIR` 里的 syncedAt。
# ★老主机必须确认已经停机。两台都在跑 = 两个控制面同时签发令牌、下发相反的策略，
#   网关照着后到的那份执行，而现场没有任何一处会显示这件事。本脚本无法替你确认这件事。
#
# 用法：
#   sudo BAIDI_STANDBY_PASSPHRASE=… ./promote-standby.sh --dry-run
#   sudo BAIDI_STANDBY_PASSPHRASE=… ./promote-standby.sh
set -eo pipefail

PREFIX="${BD_PREFIX:-/opt/baidi}"
DIR="${STANDBY_DIR:-/var/lib/baidi-standby}"
BIN="${STANDBY_BIN:-}"      # 留空 = 参数解析完之后按最终的 PREFIX 推导（见下方）
SERVICE="${SERVICE:-baidi-control}"
PORT="${CONTROL_PORT:-8090}"
USER_NAME="${BD_USER:-baidi}"
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --dir) DIR="$2"; shift ;;
    --prefix) PREFIX="$2"; shift ;;
    --bin) BIN="$2"; shift ;;
    --service) SERVICE="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --user) USER_NAME="$2"; shift ;;
    -h|--help)
      sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "未知参数：$1（-h 看用法）" >&2; exit 2 ;;
  esac
  shift
done

# ★BIN 的默认值在这里推导、而不是在参数解析里：写在 --prefix 分支里的话，
# `--bin X --prefix Y` 与 `--prefix Y --bin X` 会给出不同结果（前者被 --prefix 覆盖回默认值），
# 而这种「参数顺序敏感」在一条只在灾难当天才跑的脚本里是最不该有的惊喜。
BIN="${BIN:-$PREFIX/bin/baidi-standby}"
BAK="$DIR/latest.bak"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/baidi-promote.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

say() { echo "==> $*"; }
die() { echo "promote-standby: $*" >&2; exit 1; }

# ── ① 前置检查 ──
say "前置检查"
[ -n "${BAIDI_STANDBY_PASSPHRASE:-}" ] || die "缺少 BAIDI_STANDBY_PASSPHRASE（备份是加密的，没有口令连校验都做不了）"
[ -f "$BAK" ] || die "找不到备份 ${BAK}：这台备机从未成功同步过，提升它只会得到一套空系统"
[ -x "$BIN" ] || die "找不到可执行的 baidi-standby（${BIN}）；用 --bin 指定"

if "$BIN" -status -dir "$DIR" > "$STAGE/status.json" 2>"$STAGE/status.err"; then
  echo "    本地同步状态："
  sed 's/^/      /' "$STAGE/status.json"
else
  # 状态文件读不出来不阻断（权威判据是备份自身，下一步就会校验），但必须显眼地说出来
  echo "    ⚠ 读本地同步状态失败：$(cat "$STAGE/status.err")" >&2
fi

# ── ② 校验完整性 ──
say "校验备份完整性（解密 + 必须含 baidi.db）"
"$BIN" -verify -file "$BAK" || die "备份校验不通过：**没有动现网任何文件**。先查清这份备份为什么坏，别硬上"

# ── ③ 解到暂存目录 ──
say "解开到暂存目录 $STAGE/payload"
mkdir -p "$STAGE/payload"
"$BIN" -extract -file "$BAK" -out "$STAGE/payload" >/dev/null || die "解开失败"

# 归档内相对名 → 目标路径（与 deploy/systemd/baidi-control.service 里的环境变量一致）
#   baidi.db / audit-hmac.key → $PREFIX/data/
#   pki/**                    → $PREFIX/etc/pki/
#   *.pem / *.pem.pub         → $PREFIX/etc/keys/
dest_for() {
  case "$1" in
    pki/*)                echo "$PREFIX/etc/${1}" ;;
    *.pem|*.pem.pub)      echo "$PREFIX/etc/keys/$(basename "$1")" ;;
    baidi.db|audit-hmac.key) echo "$PREFIX/data/$1" ;;
    *)                    echo "" ;;   # 认不出的名字一律不落地（见下）
  esac
}

PLAN=""
UNKNOWN=""
while IFS= read -r rel; do
  d="$(dest_for "$rel")"
  if [ -z "$d" ]; then UNKNOWN="$UNKNOWN $rel"; continue; fi
  PLAN="$PLAN$rel|$d"$'\n'
done < <(cd "$STAGE/payload" && find . -type f | sed 's|^\./||' | sort)

say "将要覆盖的文件"
printf '%s' "$PLAN" | while IFS='|' read -r rel d; do
  [ -n "$rel" ] && echo "    $rel  →  $d"
done
if [ -n "$UNKNOWN" ]; then
  # ★认不出就不落地，而不是猜一个位置：猜错的结果是恢复"成功"但那份材料没在起作用，
  #   而系统照常运行。宁可让人当场看见这行，手工放置。
  echo "    ⚠ 以下材料不在已知映射内，脚本不会放置，请手工处理：$UNKNOWN" >&2
fi

# ── ④ 版本与终端侧接管的校验清单 ──
#
# ★这一段**没有任何自动接管**，也刻意不做（wave11 行动 18-④）。
#   自动接管需要一个"终端能主动发现新主机"的服务——DNS SRV、锚点服务、
#   或一个终端信得过的引导端点。白帝一个都没有：桌面端控制中心地址是本机
#   localStorage 里一个手填的值，移动端是**编译进 APK** 的 BuildConfig 常量，
#   信任锚也一样。做一个假的"自动切换"只会在切换当天多一层要排查的东西。
#   所以这里给的是**校验 + 清单**：把这台机器上查得到的事实查出来，
#   查不到的当面说清"必须人工做什么"。
say "版本与终端侧接管检查"

# 4-a 版本身份：切换后启动的是**这台机器上的 baidi-control**，不是备机同步进程。
#     两者版本对不上时，最好的结局是进程起不来（切换失败但数据还在），
#     最坏是它起来了并把库按旧结构半迁回去。
CTL_BIN="${CONTROL_BIN:-$PREFIX/bin/baidi-control}"
if [ -x "$CTL_BIN" ]; then
  ctl_ver="$("$CTL_BIN" -version 2>/dev/null || echo "")"
  if [ -n "$ctl_ver" ]; then
    echo "    本机 baidi-control：$ctl_ver"
  else
    echo "    ⚠ $CTL_BIN 不认识 -version（版本低于 wave11）：切换后跑的是哪一版**无法在本机确认**" >&2
  fi
else
  # 这不是"少条信息"：提升流程最后一步就是 systemctl start baidi-control。
  echo "    ✗ 找不到可执行的 $CTL_BIN —— 提升的最后一步会失败（服务起不来）。" >&2
  echo "      先把白帝交付包装到这台机器上（deploy/install-remote.sh），再来提升。" >&2
fi
if [ -f "$PREFIX/VERSION" ]; then
  echo "    本机交付包版本戳：$(tr '\n' ' ' < "$PREFIX/VERSION")"
fi
# 备份头里记着**做这份备份的那台主机**是哪一版。它与上面那个不一致，
# 就是一次跨版本恢复——`baidi-standby -verify` 已经把它打出来了（见步骤 ②）。
echo "    ↑ 与上面 -verify 打出的「备份校验通过：版本 X」比对：不一致即跨版本恢复，先对齐版本再切。"

# 4-b 地址是否会变。这是终端侧要不要动的**唯一判据**，而它在本机是查得到的：
#     latest.json 里的 primary 就是旧主机的地址。
OLD_PRIMARY="$(sed -n 's/.*"primary"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DIR/latest.json" 2>/dev/null | head -1)"
OLD_HOST="$(printf '%s' "$OLD_PRIMARY" | sed -e 's|^[a-zA-Z][a-zA-Z0-9+.-]*://||' -e 's|[:/].*$||')"
SAME_ADDR=0
if [ -n "$OLD_HOST" ]; then
  echo "    终端此前指向的主机：$OLD_HOST（取自 $DIR/latest.json 的 primary）"
  # 本机是否就持有那个地址（VIP 漂移 / 同地址接管）——是的话终端侧一动不用动。
  # ★用 `ip -o addr` / `ifconfig` 两条路，别假设发行版：这台机器可能是最小化安装。
  # ★两条都没有时 SAME_ADDR 保持 0 → 打出"必须人工改终端"那一屏。
  #   方向是**故意**的：判不出来时按"要改"提示，最坏是多做一次无谓的核对；
  #   反过来（判不出来就说"无需改动"）会让人在切换当天什么都不做，
  #   然后全部终端安静地连着一台已经停机的主机。
  if { ip -o addr show 2>/dev/null || ifconfig 2>/dev/null; } | grep -qw "$OLD_HOST"; then
    SAME_ADDR=1
  fi
else
  echo "    ⚠ 读不出旧主机地址（$DIR/latest.json 缺 primary）：终端侧要不要改**无法在本机判定**，请人工核对" >&2
fi

if [ "$SAME_ADDR" = "1" ]; then
  echo "    ✓ 本机已持有 $OLD_HOST（VIP 漂移 / 同地址接管）：终端侧配置**无需改动**。"
  echo "      但 HTTPS 证书仍要看下一条——地址没变不等于证书没变。"
else
  cat >&2 <<'TERMEOF'
    ⚠ 本机没有旧主机那个地址 → **全部终端仍指着旧主机**，切换完成那一刻它们不会自己找过来。
      白帝没有让终端发现新主机的服务（无 DNS SRV / 无引导端点），这一步**只能人工做**：

      1) 网关（每台）：改 -control / BAIDI_GW_CONTROL 指向新主机，重启。
         mTLS 证书随库一起恢复了，白名单仍有效，不必重签。
      2) 桌面客户端（每台）：控制中心地址是本机 localStorage 里**手填的单值**
         （baidi_cfg_control），没有故障转移列表——必须每台在「设置」里改。
      3) 移动端（安卓/iOS/鸿蒙）：控制中心地址与控制面信任锚都是**编译进安装包**的
         （-PbaidiApiBase / res/raw/baidi_control_ca.pem）→ **必须重新出包并让用户重装**。
      4) 门户/管理台的浏览器用户：改书签，或把前置 DNS/负载均衡指向新主机。
TERMEOF
fi

# 4-c HTTPS 证书：**它不在备份材料清单里**（backupSources 只含库 + PKI + 四把签名密钥 +
#     审计链密钥），install-remote.sh 是**每台机器各自**生成自签证书的。
#     于是切换后这台机器出示的是另一张叶子证书——而桌面端的 ~/.baidi/control-ca.pem
#     与安卓包里编译进去的锚，钉的都是**旧主机那张**。
if [ -f "$PREFIX/etc/tls/server.crt" ]; then
  echo "    本机 HTTPS 证书指纹：$(openssl x509 -in "$PREFIX/etc/tls/server.crt" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//' || echo '（取不到，本机没有 openssl？）')"
fi
cat >&2 <<'CERTEOF'
    ⚠ HTTPS 证书**不在备份里**（backupSources 只含数据库 + 内部 CA + 四把签名密钥 + 审计链密钥），
      每台机器的自签证书是 install-remote.sh 各自生成的 → 切换后这台出示的是**另一张证书**。
      受影响的终端侧信任材料，同样只能人工换：
        · 桌面端：把新主机的证书导进本机系统信任库；数据面那半换 ~/.baidi/control-ca.pem。
        · 安卓/iOS/鸿蒙：锚是编译进包的，**必须重新出包**（与上面第 3 条同一次动作）。
        · 若旧主机用的是 Let's Encrypt 的 IP 地址证书（WITH_ACME_IP_CERT=1），
          新主机要用新 IP 重新签一次，且那条路只在裸 IPv4 + 443 独占机上成立。
      要让切换不牵动终端，唯一的正路是**两台机器共用一个对外入口**
      （同一个 VIP / 同一个域名 + 同一张证书），而不是在切换当天补救。
CERTEOF

if [ "$DRY" = "1" ]; then
  say "--dry-run：到此为止，未停服务、未覆盖任何文件"
  echo "✓ 干跑通过：这份备份能解开、内容完整，上面就是正式执行时会覆盖的清单"
  echo "  终端侧接管清单见上方「版本与终端侧接管检查」——那部分**没有任何自动化**，"
  echo "  正式执行也不会替你做，务必先安排好再切。"
  exit 0
fi

# ── ⑤ 停服务 → 快照 → 覆盖 → 起服务 ──
command -v systemctl >/dev/null 2>&1 || die "本机没有 systemctl：正式提升只支持 systemd 部署（用 --dry-run 可在任何机器上验脚本逻辑）"

say "停 $SERVICE"
systemctl stop "$SERVICE" || true

SNAP="$PREFIX/var/pre-promote-$(date +%Y%m%d-%H%M%S)"
say "把现有材料快照到 ${SNAP}（切换失败时能原样退回去）"
mkdir -p "$SNAP"
for p in "$PREFIX/data" "$PREFIX/etc/pki" "$PREFIX/etc/keys"; do
  [ -e "$p" ] && cp -a "$p" "$SNAP/" || true
done

say "覆盖"
printf '%s' "$PLAN" | while IFS='|' read -r rel d; do
  [ -n "$rel" ] || continue
  mkdir -p "$(dirname "$d")"
  cp -p "$STAGE/payload/$rel" "$d"
done
# WAL/SHM 必须删掉：新库文件配着旧库的 -wal，SQLite 打开时的行为取决于两者是否匹配，
# 最好的情况是报错，最坏的情况是读到半新半旧的内容。
rm -f "$PREFIX/data/baidi.db-wal" "$PREFIX/data/baidi.db-shm"
chown -R "$USER_NAME" "$PREFIX/data" "$PREFIX/etc/pki" "$PREFIX/etc/keys" 2>/dev/null || true

say "起 $SERVICE"
systemctl start "$SERVICE"

# ── ⑥ 自检 ──
say "自检 http://127.0.0.1:$PORT/healthz"
ok=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || die "服务起来了但 /healthz 不通。快照在 ${SNAP}，可原样拷回后 systemctl start $SERVICE 退回去"

cat <<EOF
✓ 提升完成。接下来必须人工做的事（脚本替不了，且**没有任何自动接管**）：
  1) 老主机确已停机——两台同时跑 = 两个控制面同时签发令牌、下发相反的策略；
  2) 终端侧接管：见上方「版本与终端侧接管检查」那一段列出的逐项动作。
     地址变了的话，网关的 -control 要改（证书随库恢复，白名单仍有效）、
     桌面端每台手工改控制中心地址、**移动端必须重新出包**（地址与信任锚都编译在包里）；
  3) HTTPS 证书不在备份里，这台出示的是另一张——桌面端要重新导信任库，
     移动端同样落在第 2 条那次重新出包上；
  4) 到管理台跑一次「运维诊断 /diag」与「审计链校验」——后者能证明审计链密钥恢复正确，
     顺带看一眼「服务端版本身份」那一格是不是「未注入」（未注入 = 这台装的不是交付包）。
  切换前快照：$SNAP
EOF
