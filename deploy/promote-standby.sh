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

if [ "$DRY" = "1" ]; then
  say "--dry-run：到此为止，未停服务、未覆盖任何文件"
  echo "✓ 干跑通过：这份备份能解开、内容完整，上面就是正式执行时会覆盖的清单"
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
✓ 提升完成。接下来必须人工确认的三件事（脚本替不了）：
  1) 老主机确已停机——两台同时跑 = 两个控制面同时签发令牌、下发相反的策略；
  2) 各网关的 -control 指向这台机器，且 mTLS 证书仍在白名单里（证书随库一起恢复了）；
  3) 到管理台跑一次「运维诊断 /diag」与「审计链校验」——后者能证明审计链密钥恢复正确。
  切换前快照：$SNAP
EOF
