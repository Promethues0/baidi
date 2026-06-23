#!/usr/bin/env bash
# 加载白帝网关 pf 隐身规则到 anchor（需 sudo）。
# 用法： sudo ./setup-pf.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ANCHOR="baidi-gw"

if [[ "$(id -u)" != "0" ]]; then echo "需 root： sudo $0"; exit 1; fi

# 启用 pf（若未启用）
pfctl -e 2>/dev/null || true

# 把规则装进命名 anchor，并在主规则集挂载该 anchor
echo "anchor \"$ANCHOR\"" | pfctl -f -
pfctl -a "$ANCHOR" -f "$DIR/baidi-pf.conf"

echo "✓ 已加载 anchor $ANCHOR：默认 DROP 18443，仅放行 <baidi_allowed>"
echo "  查看规则：   sudo pfctl -a $ANCHOR -sr"
echo "  查看放行表： sudo pfctl -a $ANCHOR -t baidi_allowed -T show"
echo "  现在以 root 启动网关： sudo baidi-gateway -pf -gm -proxy :18443 -spa :18201 -backend 127.0.0.1:19999"
