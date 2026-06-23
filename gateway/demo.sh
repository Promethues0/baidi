#!/usr/bin/env bash
# 白帝数据面真链路演示：暗 → SPA 敲门(携带 baidi-control 签发的 JWT) → SSL 隧道代理到后端业务。
# 前置：baidi-control 在 :8090 运行（用默认 JWT 密钥；网关 -secret 须与之一致）。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW=/tmp/baidi-gateway; KNOCK=/tmp/baidi-knock
SPA=127.0.0.1:18201; PROXY=127.0.0.1:18443; BACKEND=127.0.0.1:19999

echo "==> 构建 baidi-gateway / baidi-knock"
( cd "$HERE" && go build -o "$GW" ./cmd/baidi-gateway && go build -o "$KNOCK" ./cmd/baidi-knock ) || exit 1

echo "==> 启动后端业务（演示 OA :19999）"
pkill -f 'http.server 19999' 2>/dev/null; pkill -f "$GW" 2>/dev/null; sleep 0.3
( cd /tmp && nohup python3 -m http.server 19999 --bind 127.0.0.1 >/tmp/baidi-backend.log 2>&1 & )

echo "==> 启动网关（暗；proxy=$PROXY spa=$SPA → $BACKEND）"
nohup "$GW" -spa "$SPA" -proxy "$PROXY" -backend "$BACKEND" -ttl 30s >/tmp/baidi-gateway.log 2>&1 &
sleep 1

echo ""; echo "① 敲门前：curl 隧道端口（期望失败=对未授权者隐身）"
if curl -k -s --max-time 3 -o /dev/null "https://$PROXY/"; then echo "   ✗ 异常：竟然连上了"; else echo "   ✓ 被拒绝（隐身）"; fi

echo "② 取 baidi-control 签发的 JWT 并 SPA 敲门"
TOK=$(curl -s -X POST localhost:8090/api/v1/portal/login -H 'Content-Type: application/json' -d '{"username":"li.ming","password":"baidi@123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
[ -z "$TOK" ] && { echo "   ✗ 取不到 token，请确认 baidi-control 在 :8090 运行"; exit 1; }
"$KNOCK" -spa "$SPA" -token "$TOK"; sleep 0.6

echo "③ 敲门后：curl 隧道端口（期望成功，经 TLS 隧道代理到后端 OA）"
OUT=$(curl -k -s --max-time 4 "https://$PROXY/" | head -2)
[ -n "$OUT" ] && echo "   ✓ 成功，后端响应：" && echo "$OUT" | sed 's/^/     /' || echo "   ✗ 失败"

echo ""; echo "==> 网关日志："; tail -4 /tmp/baidi-gateway.log
echo "==> 清理：pkill -f $GW ; pkill -f 'http.server 19999'"
