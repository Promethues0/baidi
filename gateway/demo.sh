#!/usr/bin/env bash
# 白帝数据面真链路演示：暗 → SPA 敲门(携带 baidi-control 签发的 JWT) → SSL 隧道代理到后端业务。
# 前置：baidi-control 在 :8090 运行（网关只需它的敲门公钥 jwt-ed25519-knock.pem.pub，不再共享密钥）。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW=/tmp/baidi-gateway; KNOCK=/tmp/baidi-knock
SPA=127.0.0.1:18201; PROXY=127.0.0.1:18443; BACKEND=127.0.0.1:19999

echo "==> 构建 baidi-gateway / baidi-knock"
( cd "$HERE" && go build -o "$GW" ./cmd/baidi-gateway && go build -o "$KNOCK" ./cmd/baidi-knock ) || exit 1

echo "==> 启动后端业务（演示 OA :19999）"
pkill -f 'http.server 19999' 2>/dev/null; pkill -f "$GW" 2>/dev/null; sleep 0.3
( cd /tmp && nohup python3 -m http.server 19999 --bind 127.0.0.1 >/tmp/baidi-backend.log 2>&1 & )

echo "==> 启动网关（暗；proxy=$PROXY spa=$SPA → ${BACKEND}）"
# 网关只持 control 的**敲门**公钥验证令牌（会话令牌用另一把密钥签，在此从密码学上验不过）
PUB="${BAIDI_GW_JWT_PUBKEY:-$HERE/../control/jwt-ed25519-knock.pem.pub}"
[ -f "$PUB" ] || { echo "   ✗ 找不到 control 的敲门公钥：$PUB"; echo "     （先启动一次 baidi-control 让它生成，或用 BAIDI_GW_JWT_PUBKEY 指定）"; exit 1; }
# ★带 -allow-no-preamble：本脚本第③步用 curl 直打隧道口，发的是 `GET /`（首字节非 'C'），
#   走的是**无 CONNECT 前导**那条路。该路径自 wave9 起默认 fail-closed——它不做任何
#   资源鉴权（Lookup/Authorize/DenyUsers 全跳过），而参考部署的默认后端正是控制面自身。
#   这里显式开启是为了让这个「暗→敲门→通→重暗」的最小演示仍然跑得动；**真实客户端
#   不走这条路**：它们经接入剖面拿到 resmap，每条连接都发 `CONNECT <资源id>` 并逐条鉴权。
nohup "$GW" -spa "$SPA" -proxy "$PROXY" -backend "$BACKEND" -allow-no-preamble -ttl 30s -jwt-pubkey "$PUB" >/tmp/baidi-gateway.log 2>&1 &
sleep 1

echo ""; echo "① 敲门前：curl 隧道端口（期望失败=对未授权者隐身）"
if curl -k -s --max-time 3 -o /dev/null "https://$PROXY/"; then echo "   ✗ 异常：竟然连上了"; else echo "   ✓ 被拒绝（隐身）"; fi

echo "② 登录取会话令牌 → 经 control 换短时效一次性敲门令牌 → SPA 敲门"
echo "   （会话令牌自身敲不开门：网关只认 use=knock 令牌，故敲门必过控制面的封禁/账号/合规三道闸）"
TOK=$(curl -s -X POST localhost:8090/api/v1/portal/login -H 'Content-Type: application/json' -d '{"username":"li.fang","password":"baidi@123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
[ -z "$TOK" ] && { echo "   ✗ 取不到 token，请确认 baidi-control 在 :8090 运行"; exit 1; }
"$KNOCK" -spa "$SPA" -token "$TOK" -control http://127.0.0.1:8090; sleep 0.6

echo "③ 敲门后：curl 隧道端口（期望成功，经 TLS 隧道代理到后端 OA）"
echo "   ⚠ 本步演示的是 SPA 隐身的开合，**不是资源鉴权**：curl 不发 CONNECT 前导，"
echo "     走的是 -allow-no-preamble 兼容路径（该路径不查资源 ACL）。资源级鉴权见 e2e.sh。"
OUT=$(curl -k -s --max-time 4 "https://$PROXY/" | head -2)
[ -n "$OUT" ] && echo "   ✓ 成功，后端响应：" && echo "$OUT" | sed 's/^/     /' || echo "   ✗ 失败"

echo "④ 用会话令牌直接敲门（期望被拒：strict 模式只认 control 签发的一次性敲门令牌）"
"$KNOCK" -spa "$SPA" -token "$TOK" 2>/dev/null && echo "   ✗ 异常：会话令牌竟被接受" || echo "   ✓ 客户端拒绝直发（-control 必填）"

echo "⑤ 等放行窗口(30s TTL)过期后再 curl（期望失败=重新隐身）"
sleep 32
if curl -k -s --max-time 3 -o /dev/null "https://$PROXY/"; then echo "   ✗ 异常：窗口没关"; else echo "   ✓ 窗口已关，恢复隐身"; fi

echo ""; echo "==> 网关日志："; tail -6 /tmp/baidi-gateway.log
echo "==> 清理：pkill -f $GW ; pkill -f 'http.server 19999'"
