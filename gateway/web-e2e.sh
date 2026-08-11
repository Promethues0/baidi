#!/usr/bin/env bash
# 七层 Web 代理（PRD 8.3.3，B/S 免客户端接入）全链路自检。
#
# 与 e2e.sh 的分工：那条验的是 C/S 隧道（敲门 → 钉扎 → CONNECT 路由）；
# 这条验的是**浏览器路径**——门户取票 → 网关验票换 Cookie → 反代到真后端。
# 两条路共用同一份资源注册表与同一套授权判定，但入场方式完全不同。
#
# 九条断言（每一条都是"只有真做成了才可能成立"的性质）：
#   ① 不带票据直连 L7 端点 → 拒（含伪造票据）
#   ② 票据换 Cookie 成功，且 Cookie 带 HttpOnly/Secure/SameSite + 路径限定
#   ③ 经代理拿到后端**真实内容**（不是网关自己编的页面）
#   ④ 换一个应用的 Cookie 去开本应用 → 拒（跨应用不可用）
#   ⑤ 撤销授权后**同一个 Cookie 的下一个请求**就被拒（逐请求重新鉴权）
#   ⑥ 进站伪造的 XFF 被剥掉，后端看到的是真实对端
#   ⑦ 票据**真是一次性**：同一张票换第二次会话被拒（此前四处文案都这么写，实际可无限重放）
#   ⑧ 网关自己的会话 Cookie 不转发给后端；客户端可控的 Host 不当 X-Forwarded-Host 下发
#   ⑨ Web 票据不能当控制面 Bearer 用（用途闸的控制面这一侧）
#
# 自带起栈、无需 root / Docker。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK=/tmp/baidi-web-e2e
CONTROL=http://127.0.0.1:8090
MTLS=https://127.0.0.1:8092
SPA_PORT="${BAIDI_E2E_SPA_PORT:-18301}"
PROXY_PORT="${BAIDI_E2E_PROXY_PORT:-18343}"
WEB_PORT="${BAIDI_E2E_WEB_PORT:-18344}"
BE_PORT="${BAIDI_E2E_BE_PORT:-19101}"

PASS=0
FAIL=0
ok()   { echo "   ✓ $1"; PASS=$((PASS+1)); }
bad()  { echo "   ✗ $1"; FAIL=$((FAIL+1)); }

preflight_port() {
  local proto=$1 port=$2 label=$3 holder
  holder=$(lsof -nP -i"$proto":"$port" 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}')
  if [ -n "$holder" ]; then
    echo "   ✗ $label 端口 $port 已被占用：$holder"
    echo "     换端口重跑，例如：BAIDI_E2E_WEB_PORT=28344 $0"
    return 1
  fi
  return 0
}

cleanup() {
  echo ""
  echo "==> 清理"
  pkill -f "$WORK/baidi-gateway" 2>/dev/null
  pkill -f "$WORK/baidi-control" 2>/dev/null
  pkill -f "$WORK/backend.py" 2>/dev/null
  true
}
trap cleanup EXIT

mkdir -p "$WORK"

# ★独立的库与密钥材料：绝不碰使用者 control/baidi.db 里的演示数据
# （下面要把资源后端改到本机端口，还要来回改 ACL）。
export BAIDI_DB="$WORK/e2e.db"
export BAIDI_PKI_DIR="$WORK/pki"
export BAIDI_JWT_KEY="$WORK/jwt-ed25519.pem"
export BAIDI_JWT_KNOCK_KEY="$WORK/jwt-ed25519-knock.pem"
export BAIDI_JWT_WEB_KEY="$WORK/jwt-ed25519-web.pem"
export BAIDI_MTLS_ADDR=127.0.0.1:8092

echo "==> 端口预检"
RC=0
preflight_port TCP 8090 "控制面"      || RC=1
preflight_port TCP 8092 "网关 mTLS"   || RC=1
preflight_port TCP "$WEB_PORT" "七层 Web 代理" || RC=1
preflight_port TCP "$BE_PORT"  "业务后端"      || RC=1
[ $RC -ne 0 ] && exit 1
echo "   ✓ 端口可用（web=$WEB_PORT 后端=$BE_PORT）"

echo "==> 构建"
( cd "$HERE" && go build -o "$WORK/baidi-gateway" ./cmd/baidi-gateway ) || exit 1
( cd "$ROOT/control" && go build -o "$WORK/baidi-control" ./cmd/baidi-control ) || exit 1

# ── 业务后端：一个能把收到的请求头如实回给我们的最小 HTTP 服务 ──
# 用 python3 -m http.server 不行：断言 ⑥ 需要看到后端**实际收到**的 XFF。
cat > "$WORK/backend.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MARK = "BAIDI-BACKEND-REAL-CONTENT"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/echo"):
            body = json.dumps({
                "xff": self.headers.get("X-Forwarded-For", ""),
                "realip": self.headers.get("X-Real-IP", ""),
                "forwarded": self.headers.get("Forwarded", ""),
                "user": self.headers.get("X-Baidi-User", ""),
                "host": self.headers.get("Host", ""),
                "xfhost": self.headers.get("X-Forwarded-Host", ""),
                "xfproto": self.headers.get("X-Forwarded-Proto", ""),
                "cookie": self.headers.get("Cookie", ""),
            }).encode()
            ctype = "application/json"
        else:
            body = ("<h1>" + MARK + "</h1>").encode()
            ctype = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY

echo "==> 起控制面（独立库 $BAIDI_DB）"
pkill -f "$WORK/baidi-control" 2>/dev/null; sleep 0.5
rm -f "$BAIDI_DB"
( cd "$WORK" && nohup "$WORK/baidi-control" >"$WORK/control.log" 2>&1 & )
for _ in $(seq 1 60); do
  curl -s --max-time 2 "$CONTROL/healthz" >/dev/null && break
  sleep 1
done
curl -s --max-time 2 "$CONTROL/healthz" >/dev/null || { echo "   ✗ 控制面未就绪，见 $WORK/control.log"; exit 1; }
echo "   ✓ 控制面就绪"

echo "==> 起业务后端"
nohup python3 "$WORK/backend.py" "$BE_PORT" >/dev/null 2>&1 &
sleep 1
curl -s --max-time 2 "http://127.0.0.1:$BE_PORT/" | grep -q BAIDI-BACKEND || { echo "   ✗ 后端未就绪"; exit 1; }
echo "   ✓ 后端就绪（127.0.0.1:$BE_PORT）"

echo "==> 签发网关 mTLS 客户端证书"
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

# 资源 oa 指向本机后端；finance 保持存在（断言 ④ 要拿它的 Cookie 做跨应用反例）。
setres() { # setres <id> <name> <backend> <allowUsersJSON>
  curl -s -o /dev/null -X POST "$CONTROL/api/v1/resources" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' \
    -d "{\"id\":\"$1\",\"name\":\"$2\",\"backend\":\"$3\",\"allowUsers\":$4,\"webScheme\":\"http\"}"
}
echo "==> 把两个 Web 应用的资源后端指向本机"
setres oa      "OA 协同办公"   "127.0.0.1:$BE_PORT" '["admin"]'
setres finance "财务核算系统"   "127.0.0.1:$BE_PORT" '["admin"]'
echo "   ✓ 资源已就位"

echo "==> 起网关（开七层 Web 代理；策略轮询压到 2s 便于观测撤权生效）"
WEBPUB="$WORK/jwt-ed25519-web.pem.pub"
[ -f "$WEBPUB" ] || { echo "   ✗ 找不到 control 的 Web 票据公钥：$WEBPUB"; exit 1; }
nohup "$WORK/baidi-gateway" -spa "127.0.0.1:$SPA_PORT" -proxy "127.0.0.1:$PROXY_PORT" \
  -backend "127.0.0.1:$BE_PORT" -ttl 60s \
  -jwt-pubkey "$WORK/jwt-ed25519-knock.pem.pub" -web-jwt-pubkey "$WEBPUB" \
  -web "127.0.0.1:$WEB_PORT" -poll 2s \
  -control "$MTLS" -gwid gw-1 \
  -mtls-cert "$WORK/gw.crt" -mtls-key "$WORK/gw.key" -mtls-ca "$WORK/ca.crt" \
  >"$WORK/gateway.log" 2>&1 &
sleep 4
grep -q '策略已拉取' "$WORK/gateway.log" || { echo "   ✗ 网关未能对接控制面，见 $WORK/gateway.log"; exit 1; }
grep -q '七层 Web 代理监听' "$WORK/gateway.log" || { echo "   ✗ 七层监听没起来，见 $WORK/gateway.log"; exit 1; }
echo "   ✓ 网关已注册且七层监听就绪"

WEB="http://127.0.0.1:$WEB_PORT"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# ticket <appId> → 打印入口 URL（失败则打印空串）
ticket() {
  curl -s -X POST "$CONTROL/api/v1/portal/web-ticket" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' -d "{\"appId\":\"$1\"}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('url',''))" 2>/dev/null
}
# 换票并取出 Cookie 值；同时把响应头留在 $WORK/enter.h 供属性断言
enter() {
  curl -s -D "$WORK/enter.h" -o /dev/null "$1"
  grep -i '^set-cookie:' "$WORK/enter.h" | sed -n 's/.*baidi_web=\([^;]*\).*/\1/p' | tr -d '\r'
}

echo ""
echo "════════ 七层 Web 代理自检 ════════"

echo "① 未带票据 / 伪造票据直连 L7"
c1=$(code "$WEB/app/oa/")
c2=$(code "$WEB/__baidi/enter?t=not-a-real-ticket")
if [ "$c1" = "401" ] && [ "$c2" = "401" ]; then ok "裸访问与伪造票据都被拒（$c1/$c2）"
else bad "应各回 401，实得 $c1/$c2"; fi

echo "② 票据换会话 Cookie"
URL=$(ticket a1)
if [ -z "$URL" ]; then
  bad "控制面没签出票据（见 $WORK/control.log）"
  CK=""
else
  CK=$(enter "$URL")
  st=$(head -1 "$WORK/enter.h" | awk '{print $2}')
  attrs=$(grep -i '^set-cookie:' "$WORK/enter.h" | tr -d '\r')
  if [ -n "$CK" ] && [ "$st" = "302" ] \
     && echo "$attrs" | grep -qi 'HttpOnly' \
     && echo "$attrs" | grep -qi 'Secure' \
     && echo "$attrs" | grep -qi 'SameSite=Lax' \
     && echo "$attrs" | grep -q 'Path=/app/oa/'; then
    ok "换票 302 + Cookie 带 HttpOnly/Secure/SameSite=Lax 且路径限定到 /app/oa/"
  else
    bad "Cookie 属性不合格：状态=$st 头=$attrs"
  fi
fi

echo "③ 经代理拿到后端真实内容"
body=$(curl -s -H "Cookie: baidi_web=$CK" "$WEB/app/oa/")
if echo "$body" | grep -q 'BAIDI-BACKEND-REAL-CONTENT'; then
  ok "拿到的是后端真实页面，不是网关自己编的"
else
  bad "没拿到后端内容：$(echo "$body" | head -c 200)"
fi

echo "⑥ 进站伪造的 XFF 被剥掉"
echoed=$(curl -s -H "Cookie: baidi_web=$CK" \
  -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Real-IP: 1.2.3.4' -H 'Forwarded: for=1.2.3.4' \
  "$WEB/app/oa/echo")
gotxff=$(echo "$echoed" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('xff',''),d.get('forwarded',''),d.get('user',''))" 2>/dev/null)
if [ -z "$gotxff" ]; then
  bad "后端回显解析失败：$(echo "$echoed" | head -c 200)"
elif echo "$gotxff" | grep -q '1\.2\.3\.4'; then
  bad "★伪造的来源头透传到后端了：$gotxff"
elif echo "$gotxff" | grep -q '127\.0\.0\.1' && echo "$gotxff" | grep -q 'admin'; then
  ok "后端看到的是真实对端 + 网关验过的账号（$gotxff）"
else
  bad "剥掉了但没按真实对端重写：$gotxff"
fi

echo "④ 换一个应用的 Cookie 去开本应用"
FURL=$(ticket a2)
FCK=$(enter "$FURL")
if [ -z "$FCK" ]; then
  bad "拿不到财务应用的 Cookie（前置条件不成立，无法判定跨应用隔离）"
else
  c=$(code -H "Cookie: baidi_web=$FCK" "$WEB/app/oa/")
  # 反向再验一次，确保 403 来自"绑定不符"而不是"这个账号没权限"
  c2=$(code -H "Cookie: baidi_web=$FCK" "$WEB/app/finance/")
  if [ "$c" = "403" ] && [ "$c2" != "403" ]; then
    ok "财务应用的 Cookie 开不了 OA（403），开财务本身正常（$c2）"
  else
    bad "跨应用隔离不成立：用财务 Cookie 开 OA=$c，开财务=$c2"
  fi
fi

echo "⑦ 票据一次性：同一张票换第二次会话"
RURL=$(ticket a1)
if [ -z "$RURL" ]; then
  bad "取票失败，无法判定一次性"
else
  first=$(code -o /dev/null "$RURL")
  again=$(code -o /dev/null "$RURL")
  if [ "$first" = "302" ] && [ "$again" = "401" ]; then
    ok "首次换票 302、重放同一张票 401（jti 去重真有执行方）"
  else
    bad "★票据不是一次性的：首次=$first 重放=$again（票据会进浏览器历史与 nginx access.log）"
  fi
fi

echo "⑧ 网关会话 Cookie 不外泄给后端 + Host 注入不透传"
echoed2=$(curl -s -H "Cookie: baidi_web=$CK; biz=keep" -H "Host: evil.example.com" "$WEB/app/oa/echo")
got=$(echo "$echoed2" | python3 -c "import sys,json;d=json.load(sys.stdin);print('|'.join([d.get('cookie',''),d.get('xfhost',''),d.get('xfproto','')]))" 2>/dev/null)
if [ -z "$got" ]; then
  bad "后端回显解析失败：$(echo "$echoed2" | head -c 200)"
elif echo "$got" | grep -q 'baidi_web'; then
  bad "★网关会话凭据被白送给后端：$got"
elif echo "$got" | grep -q 'evil.example.com'; then
  bad "★客户端可控的 Host 被当作真实值下发（Host header injection）：$got"
elif echo "$got" | grep -q 'biz=keep'; then
  ok "业务 Cookie 原样转发、网关自己的不转发、Host 不冒充真实值（$got）"
else
  bad "业务自己的 Cookie 被误删了：$got"
fi

echo "⑨ Web 票据不得当控制面 Bearer 用"
WTOK=$(printf '%s' "$RURL" | sed -n 's/.*[?&]t=\([^&]*\).*/\1/p')
if [ -z "$WTOK" ]; then
  bad "取不到票据串，无法判定"
else
  c=$(code -H "Authorization: Bearer $WTOK" "$CONTROL/api/v1/users")
  c2=$(code -X POST -H "Authorization: Bearer $WTOK" -H 'Content-Type: application/json' \
        -d '{"appId":"a1"}' "$CONTROL/api/v1/portal/web-ticket")
  if [ "$c" = "403" ] && [ "$c2" = "403" ]; then
    ok "票据调控制面 API 与自我续签都被拒（$c/$c2）"
  else
    bad "★一张 60s 资源票等价于全量 API 会话：/users=$c 续签=$c2"
  fi
fi

echo "⑤ 撤销授权后同一个 Cookie 的下一个请求"
setres oa "OA 协同办公" "127.0.0.1:$BE_PORT" '["someone-else"]'
sleep 5   # 网关 -poll 2s，留两轮余量
c=$(code -H "Cookie: baidi_web=$CK" "$WEB/app/oa/")
if [ "$c" = "403" ]; then
  ok "撤权后同一 Cookie 立即被拒（逐请求重新鉴权，不是只在建会话时判一次）"
else
  bad "★撤权后仍能访问（HTTP $c）——说明没有逐请求鉴权"
fi

echo ""
echo "════════ 结果：通过 $PASS，失败 $FAIL ════════"
if [ $FAIL -ne 0 ]; then
  echo "日志：$WORK/{control,gateway}.log"
  exit 1
fi
echo "日志：$WORK/{control,gateway}.log"
exit 0
