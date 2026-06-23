#!/usr/bin/env bash
# 卸载白帝网关 pf 隐身规则（需 sudo）。
set -euo pipefail
ANCHOR="baidi-gw"
if [[ "$(id -u)" != "0" ]]; then echo "需 root： sudo $0"; exit 1; fi
pfctl -a "$ANCHOR" -F all 2>/dev/null || true
echo "✓ 已清空 anchor $ANCHOR 规则与放行表（pf 本身保持启用，如需关闭： sudo pfctl -d）"
