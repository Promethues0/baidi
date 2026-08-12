#!/usr/bin/env bash
# 白帝全链路自检：一条命令拉起完整栈并验证「客户端真的能连上业务」。
#
# 与 demo.sh 的区别：demo.sh 只验证网关自身的「暗→敲门→隧道→默认后端」；
# 本脚本验证的是**整条产品链路**——控制面下发接入剖面、网关 mTLS 注册并上报
# 隧道证书指纹、客户端按剖面钉扎握手并按资源 id 路由到各自后端、越权被拒。
#
# 覆盖范围：从门户登录到后端响应的每一段。唯一未覆盖的是 utun 建卡（需 root），
# 那一段由 baidi-tun 承担；netstack 之后的所有环节都在这里被真实断言。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK=/tmp/baidi-e2e
CONTROL=http://127.0.0.1:8090
MTLS=https://127.0.0.1:8092
# 端口可覆盖：开发机上 18201/18443 这类常用端口常被别的项目占着，
# 撞port 时的表象是「握手报 protocol version not supported」之类完全不相干的错误，
# 极易被误判成白帝自身的 bug。故既允许覆盖，也在下面做显式预检。
SPA_PORT="${BAIDI_E2E_SPA_PORT:-18201}"
PROXY_PORT="${BAIDI_E2E_PROXY_PORT:-18443}"
BE1_PORT="${BAIDI_E2E_BE1_PORT:-19001}"
BE2_PORT="${BAIDI_E2E_BE2_PORT:-19002}"

# 端口预检：被占用就直接报清楚是谁占的，别让自检在后面以离奇的方式失败。
preflight_port() {
  local proto=$1 port=$2 label=$3 holder
  holder=$(lsof -nP -i"$proto":"$port" 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}')
  if [ -n "$holder" ]; then
    echo "   ✗ $label 端口 $port 已被占用：$holder"
    echo "     换端口重跑，例如：BAIDI_E2E_PROXY_PORT=28443 BAIDI_E2E_SPA_PORT=28201 $0"
    return 1
  fi
  return 0
}

cleanup() {
  echo ""
  echo "==> 清理"
  pkill -f "$WORK/baidi-gateway" 2>/dev/null
  pkill -f "$WORK/baidi-control" 2>/dev/null
  pkill -f "http.server $BE1_PORT" 2>/dev/null
  pkill -f "http.server $BE2_PORT" 2>/dev/null
  true
}
trap cleanup EXIT

mkdir -p "$WORK"

# ★自检必须跑在**独立的库与密钥材料**上：BAIDI_DB / BAIDI_PKI_DIR / 两把签名密钥
# 全部指向 ${WORK}。否则自检会改写使用者 control/baidi.db 里的演示资源后端
# （下面要把 oa/git 指向本机端口才能观测路由），把人家的演示环境搞坏。
export BAIDI_DB="$WORK/e2e.db"
export BAIDI_PKI_DIR="$WORK/pki"
export BAIDI_JWT_KEY="$WORK/jwt-ed25519.pem"
export BAIDI_JWT_KNOCK_KEY="$WORK/jwt-ed25519-knock.pem"
export BAIDI_MTLS_ADDR=127.0.0.1:8092

echo "==> 端口预检"
RC=0
preflight_port TCP 8090  "控制面"      || RC=1
preflight_port TCP 8092  "网关 mTLS"   || RC=1
preflight_port TCP "$PROXY_PORT" "隧道代理" || RC=1
preflight_port UDP "$SPA_PORT"   "SPA 敲门"  || RC=1
preflight_port TCP "$BE1_PORT"   "后端 A"    || RC=1
preflight_port TCP "$BE2_PORT"   "后端 B"    || RC=1
[ $RC -ne 0 ] && exit 1
echo "   ✓ 端口可用（spa=$SPA_PORT proxy=$PROXY_PORT 后端=$BE1_PORT/${BE2_PORT}）"

echo "==> 构建（预编译，避免每步 go run 重复编译拖慢自检）"
( cd "$HERE" && go build -o "$WORK/baidi-gateway" ./cmd/baidi-gateway ) || exit 1
( cd "$HERE" && go build -o "$WORK/baidi-e2e" ./cmd/baidi-e2e ) || exit 1
( cd "$ROOT/control" && go build -o "$WORK/baidi-control" ./cmd/baidi-control ) || exit 1

echo "==> 起控制面（独立库 ${BAIDI_DB}；含网关 mTLS 口）"
pkill -f "$WORK/baidi-control" 2>/dev/null; sleep 0.5
rm -f "$BAIDI_DB"   # 每次自检从干净种子起步，结果可复现
( cd "$WORK" && nohup "$WORK/baidi-control" >"$WORK/control.log" 2>&1 & )
for _ in $(seq 1 60); do
  curl -s --max-time 2 "$CONTROL/healthz" >/dev/null && break
  sleep 1
done
curl -s --max-time 2 "$CONTROL/healthz" >/dev/null || { echo "   ✗ 控制面未就绪，见 $WORK/control.log"; exit 1; }
echo "   ✓ 控制面就绪"

echo "==> 起两个可区分的后端（验证多资源路由不是幻觉）"
mkdir -p "$WORK/be-oa" "$WORK/be-git"
echo "<h1>OA 协同办公 · 后端 A</h1>" > "$WORK/be-oa/index.html"
echo "<h1>Git 仓库 · 后端 B</h1>"   > "$WORK/be-git/index.html"
( cd "$WORK/be-oa"  && nohup python3 -m http.server "$BE1_PORT" --bind 127.0.0.1 >/dev/null 2>&1 & )
( cd "$WORK/be-git" && nohup python3 -m http.server "$BE2_PORT" --bind 127.0.0.1 >/dev/null 2>&1 & )
sleep 1

echo "==> 签发网关 mTLS 客户端证书（机器身份的唯一路径）"
ADMIN=$(curl -s -X POST "$CONTROL/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"baidi@123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))")
[ -z "$ADMIN" ] && { echo "   ✗ admin 登录失败"; exit 1; }
curl -s -X POST "$CONTROL/api/v1/pki/gateway-certs" -H "Authorization: Bearer $ADMIN" \
  -H 'Content-Type: application/json' -d '{"gatewayId":"gw-1"}' > "$WORK/cert.json"
python3 - "$WORK" <<'PY'
import json, sys
w = sys.argv[1]
d = json.load(open(f"{w}/cert.json"))
for k, f in (('certPem','gw.crt'), ('keyPem','gw.key'), ('caPem','ca.crt')):
    open(f"{w}/{f}", 'w').write(d[k])
PY
echo "   ✓ 证书已签发"

echo "==> 把演示资源的后端指向本机两个端口"
for pair in "oa:$BE1_PORT:OA 协同办公" "git:$BE2_PORT:研发 Git 仓库"; do
  id="${pair%%:*}"; rest="${pair#*:}"; port="${rest%%:*}"; name="${rest#*:}"
  curl -s -X POST "$CONTROL/api/v1/resources" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
    -d "{\"id\":\"$id\",\"name\":\"$name\",\"backend\":\"127.0.0.1:$port\",\"allowRoles\":[\"admin\",\"user\"]}" >/dev/null
done
echo "   ✓ 资源后端已就位"

echo "==> 起网关（暗；mTLS 注册到控制面并上报隧道证书指纹）"
# 敲门公钥是控制面首启自动生成的（私钥同名 .pub），自检用 $WORK 下这套独立密钥
PUB="${BAIDI_GW_JWT_PUBKEY:-$WORK/jwt-ed25519-knock.pem.pub}"
[ -f "$PUB" ] || { echo "   ✗ 找不到 control 的敲门公钥：$PUB"; exit 1; }
nohup "$WORK/baidi-gateway" -spa "127.0.0.1:$SPA_PORT" -proxy "127.0.0.1:$PROXY_PORT" \
  -backend "127.0.0.1:$BE1_PORT" -ttl 60s -jwt-pubkey "$PUB" \
  -control "$MTLS" -gwid gw-1 \
  -mtls-cert "$WORK/gw.crt" -mtls-key "$WORK/gw.key" -mtls-ca "$WORK/ca.crt" \
  >"$WORK/gateway.log" 2>&1 &
sleep 4
grep -q '策略已拉取' "$WORK/gateway.log" || { echo "   ✗ 网关未能对接控制面，见 $WORK/gateway.log"; exit 1; }
echo "   ✓ 网关已注册（指纹：$(grep -o 'fp=[0-9a-f]*' "$WORK/gateway.log" | head -1 | cut -c4-19)…）"

echo ""
echo "════════ 全链路自检 ════════"
"$WORK/baidi-e2e"
RC=$?
echo ""
[ $RC -eq 0 ] && echo "日志：$WORK/{control,gateway}.log" || echo "✗ 自检失败，日志：$WORK/{control,gateway}.log"
exit $RC
