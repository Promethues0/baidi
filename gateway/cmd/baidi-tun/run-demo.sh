#!/usr/bin/env bash
# 白帝 utun 引流真机演示（macOS，需 sudo）。
#
# 验证：应用访问受保护网段里的 VIP（默认 10.99.0.10）时，流量被 utun 接管 →
# gVisor 网络栈终止 TCP → SPA 敲门 + 国密/通用隧道 → 网关 → 后端业务。
# 不启本数据面时该 VIP 不可达（路由不存在）→ 证明“先认证后连接 + 真引流”。
#
# 用法： sudo ./run-demo.sh          # 国密 TLCP 隧道
#        sudo GM=0 ./run-demo.sh     # 通用 TLS 隧道
set -euo pipefail
[[ "$(id -u)" == "0" ]] || { echo "需 root： sudo $0"; exit 1; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"        # gateway/
REPO="$(cd "$ROOT/.." && pwd)"                       # baidi/
GM="${GM:-1}"; VIP="${VIP:-10.99.0.10}"
SPA=127.0.0.1:18201; PROXY=127.0.0.1:18443; BACKEND=127.0.0.1:19999

echo "▶ 编译 gateway / baidi-tun …"
( cd "$ROOT" && go build -o /tmp/baidi-gateway ./cmd/baidi-gateway && go build -o /tmp/baidi-tun ./cmd/baidi-tun )

echo "▶ 起后端业务(:19999) + 控制面(:8090) + 网关 …"
pgrep -f 'http.server 19999' >/dev/null || ( cd /tmp && nohup python3 -m http.server 19999 --bind 127.0.0.1 >/tmp/baidi-backend.log 2>&1 & )
pgrep -f '/tmp/baidi-control' >/dev/null || ( cd "$REPO/control" && nohup env BAIDI_DB="$REPO/control/baidi.db" /tmp/baidi-control >/tmp/baidi-control.log 2>&1 & )
GWFLAG=""; [[ "$GM" == "1" ]] && GWFLAG="-gm"
pkill -f '/tmp/baidi-gateway' 2>/dev/null || true; sleep 0.5
nohup /tmp/baidi-gateway $GWFLAG -spa "$SPA" -proxy "$PROXY" -backend "$BACKEND" -ttl 60s >/tmp/baidi-gw.log 2>&1 &
sleep 1

echo "▶ 取 JWT …"
TOK=$(curl -s -X POST localhost:8090/api/v1/portal/login -H 'Content-Type: application/json' \
  -d '{"username":"li.ming","password":"baidi@123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

echo "▶ 起数据面 baidi-tun（接管 10.99.0.0/24 进隧道）…"
GMFLAG=""; [[ "$GM" == "1" ]] && GMFLAG="-gm"
nohup /tmp/baidi-tun $GMFLAG -spa "$SPA" -proxy "$PROXY" -token "$TOK" -route 10.99.0.0/24 -ip 10.99.0.2 >/tmp/baidi-tun.log 2>&1 &
TUNPID=$!; sleep 2
echo "  数据面日志："; grep -E 'utun|数据面|引流' /tmp/baidi-tun.log | head

echo "▶ 验证：curl 受保护 VIP http://$VIP/ （应经 utun→隧道→后端返回 200）"
curl -s -m 8 "http://$VIP/" -o /tmp/baidi-tun-resp.html -w "HTTP %{http_code}  从 %{remote_ip}:%{remote_port}\n" || echo "curl 失败"
echo "  返回前几行："; head -3 /tmp/baidi-tun-resp.html 2>/dev/null
echo "  隧道转发日志："; grep -E '引流|隧道' /tmp/baidi-tun.log | head
echo "  网关放行日志："; grep -E 'SPA 敲门放行|隧道建立' /tmp/baidi-gw.log | head

echo "▶ 清理： kill baidi-tun + 删路由"
kill "$TUNPID" 2>/dev/null || true
echo "完成。"
