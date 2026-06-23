#!/usr/bin/env bash
# 白帝网关 · 内核态隐身 nftables 规则（Linux，需 root）。
# 默认 DROP 代理端口；仅放行集合 baidi_allowed 内、经 SPA 敲门授权的源 IP。
# 用法： sudo ./baidi-nft.sh setup   |   sudo ./baidi-nft.sh teardown
set -euo pipefail
PROXY_PORT="${PROXY_PORT:-18443}"
SPA_PORT="${SPA_PORT:-18201}"
[[ "$(id -u)" == "0" ]] || { echo "需 root： sudo $0 $*"; exit 1; }

case "${1:-setup}" in
setup)
  nft add table inet baidi 2>/dev/null || true
  nft add set inet baidi baidi_allowed '{ type ipv4_addr; flags interval; }' 2>/dev/null || true
  nft add chain inet baidi input '{ type filter hook input priority -10; policy accept; }' 2>/dev/null || true
  nft flush chain inet baidi input
  nft add rule inet baidi input udp dport "$SPA_PORT" accept                                  # SPA 敲门口可达
  nft add rule inet baidi input tcp dport "$PROXY_PORT" ip saddr @baidi_allowed accept        # 已授权 → 放行
  nft add rule inet baidi input tcp dport "$PROXY_PORT" drop                                   # 其余 → 默认 DROP(无 RST)
  echo "✓ nftables 隐身已加载：默认 DROP $PROXY_PORT，仅放行 @baidi_allowed"
  echo "  查看： nft list table inet baidi"
  echo "  以 root 启动网关： baidi-gateway -pf -gm -proxy :$PROXY_PORT -spa :$SPA_PORT -backend 127.0.0.1:19999"
  ;;
teardown)
  nft delete table inet baidi 2>/dev/null || true
  echo "✓ 已删除 nftables table inet baidi"
  ;;
*) echo "用法： sudo $0 setup|teardown"; exit 1 ;;
esac
