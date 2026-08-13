#!/usr/bin/env bash
# 白帝**站点组网**全链路自检：一条命令拉起完整栈并验证「IPSec 是真的」。
#
# 与 e2e.sh 的分工：e2e.sh 验证南北向（用户 → 业务：SPA 敲门 + TLS 隧道 + 资源路由）；
# 本脚本验证东西向（站点 ↔ 站点：IKEv2 协商 + ESP 加密 + 跨隧道业务流量）。
#
# 全程**无需 root、无需 Docker**：
#   · IKE/NAT-T 用高位端口（默认 15500/15501、15600/15601），不碰 500/4500；
#   · 数据面用 gVisor netstack 而不是 TUN（建卡才需要 root，而那一段恰恰是整条链路里
#     最不需要验证的——协商与加解密都在它之上）。
#
# 数据隔离：BAIDI_DB / BAIDI_PKI_DIR / 两把 JWT 密钥 / PSK 主密钥全部指向 ${WORK}，
# **绝不碰使用者的 control/baidi.db**。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
WORK=/tmp/baidi-ipsec-e2e
CONTROL=http://127.0.0.1:8090
MTLS=https://127.0.0.1:8092

# 端口可覆盖：开发机上撞端口的表现往往是完全不相干的错误（本项目就被别的项目占用
# 18443 误导过一次），故既允许覆盖也做显式预检。
IKE_A="${BAIDI_IPSEC_E2E_IKE_A:-15500}"
NATT_A="${BAIDI_IPSEC_E2E_NATT_A:-15501}"
IKE_B="${BAIDI_IPSEC_E2E_IKE_B:-15600}"
NATT_B="${BAIDI_IPSEC_E2E_NATT_B:-15601}"

# wait_for <描述> <超时秒> <shell 探针> —— 按**墙钟死线**轮询，而不是等一个固定秒数。
#
# ★为什么值得单独写一个：这三个自检脚本里原先全是 `sleep N` 之后只查一次。
#   那个写法在开发机上几乎总是对的，一旦机器忙起来（CI、或者三个脚本连着跑）
#   就变成掷硬币 —— 而且**失败时报的原因是错的**：明明只是还差一秒，
#   报出来却是「网关未能对接控制面」，读的人会去查网关和控制面之间的信任链。
#   实测：三个脚本连着跑时 web-e2e.sh 的业务后端就这么假失败过一次，
#   单独跑则 9/9 全过 —— 正是这类偶发把 CI 拖成"红了先重跑一次看看"。
#   死线轮询同时修掉另一头：机器快的时候不再白等满 N 秒。
wait_for() {
  local what="$1" limit="$2" probe="$3"
  local deadline=$(( $(date +%s) + limit ))
  until eval "$probe" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "   ✗ 等「${what}」超过 ${limit}s 仍未就绪" >&2
      return 1
    fi
    sleep 0.3
  done
  return 0
}

preflight_port() {
  local proto=$1 port=$2 label=$3 holder
  # ★lsof 缺席时**说清楚探不到**，别静默放行。
  #   原先 `lsof … 2>/dev/null` 在没有 lsof 的机器上让 holder 恒为空，
  #   于是这道预检退化成"永远通过"——而它存在的全部意义就是提前拦下端口冲突。
  #   这不是假设：GitHub 的 ubuntu runner 镜像已经不默认装 lsof，
  #   把这些脚本接进 CI 的第一件事就会是端口预检无声失效。
  #   与本项目 posture / 设备指标那条「采不到就报不可判定，绝不当成 ok」同一条纪律。
  if ! command -v lsof >/dev/null 2>&1; then
    echo "   ⚠ 本机没有 lsof，端口 ${port}（${label}）**无法预检**——真撞上占用时，"
    echo "     报出来的会是后面某一步莫名其妙的失败，而不是这里一句话。"
    return 0
  fi
  holder=$(lsof -nP -i"$proto":"$port" 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}')
  if [ -n "$holder" ]; then
    echo "   ✗ $label 端口 $port 已被占用：$holder"
    echo "     换端口重跑，例如：BAIDI_IPSEC_E2E_IKE_A=25500 $0"
    return 1
  fi
  return 0
}

cleanup() {
  echo ""
  echo "==> 清理"
  pkill -f "$WORK/baidi-ipsec " 2>/dev/null
  pkill -f "$WORK/baidi-control" 2>/dev/null
  true
}
trap cleanup EXIT

mkdir -p "$WORK"

# ★独立的库与密钥材料。少了这一段，自检会把使用者演示环境里的 IPSec 站点改掉。
export BAIDI_DB="$WORK/e2e.db"
export BAIDI_PKI_DIR="$WORK/pki"
export BAIDI_JWT_KEY="$WORK/jwt-ed25519.pem"
export BAIDI_JWT_KNOCK_KEY="$WORK/jwt-ed25519-knock.pem"
export BAIDI_IPSEC_PSK_KEY="$WORK/ipsec-psk.key"
export BAIDI_MTLS_ADDR=127.0.0.1:8092

echo "==> 端口预检"
RC=0
preflight_port TCP 8090 "控制面"    || RC=1
preflight_port TCP 8092 "网关 mTLS" || RC=1
preflight_port UDP "$IKE_A"  "站点A IKE"   || RC=1
preflight_port UDP "$NATT_A" "站点A NAT-T" || RC=1
preflight_port UDP "$IKE_B"  "站点B IKE"   || RC=1
preflight_port UDP "$NATT_B" "站点B NAT-T" || RC=1
[ $RC -ne 0 ] && exit 1
echo "   ✓ 端口可用（A: $IKE_A/$NATT_A  B: $IKE_B/${NATT_B}）"

echo "==> 构建（预编译；用 go run 会让每一步都重新编译，之前因此被误判成卡死）"
( cd "$ROOT/control" && go build -o "$WORK/baidi-control" ./cmd/baidi-control ) || exit 1
( cd "$HERE" && go build -o "$WORK/baidi-ipsec" ./cmd/baidi-ipsec ) || exit 1
( cd "$HERE" && go build -o "$WORK/baidi-ipsec-e2e" ./cmd/baidi-ipsec-e2e ) || exit 1

echo "==> 起控制面（独立库 ${BAIDI_DB}）"
pkill -f "$WORK/baidi-control" 2>/dev/null; sleep 0.5
rm -f "$BAIDI_DB"   # 每次从干净种子起步，结果可复现
( cd "$WORK" && nohup "$WORK/baidi-control" >"$WORK/control.log" 2>&1 & )
for _ in $(seq 1 60); do
  curl -s --max-time 2 "$CONTROL/healthz" >/dev/null && break
  sleep 1
done
curl -s --max-time 2 "$CONTROL/healthz" >/dev/null || { echo "   ✗ 控制面未就绪，见 $WORK/control.log"; exit 1; }
echo "   ✓ 控制面就绪"

ADMIN=$(curl -s -X POST "$CONTROL/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"baidi@123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))")
[ -z "$ADMIN" ] && { echo "   ✗ admin 登录失败"; exit 1; }

echo "==> 签两张组网网关证书（CN 必须 ipsec-* ——控制面按前缀分权）"
for CN in ipsec-a ipsec-b; do
  curl -s -X POST "$CONTROL/api/v1/pki/gateway-certs" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' -d "{\"gatewayId\":\"$CN\"}" > "$WORK/$CN.json"
  python3 - "$WORK" "$CN" <<'PY'
import json, sys
w, cn = sys.argv[1], sys.argv[2]
d = json.load(open(f"{w}/{cn}.json"))
for k, f in (('certPem', f'{cn}.crt'), ('keyPem', f'{cn}.key'), ('caPem', 'ca.crt')):
    open(f"{w}/{f}", 'w').write(d[k])
PY
done
echo "   ✓ ipsec-a / ipsec-b 证书已签发"

echo "==> 建两条站点（互为对端），并各设一把 PSK"
# 站点 e2e-a 归 ipsec-a，e2e-b 归 ipsec-b。两端网段互为对方的 remoteSubnet。
mk_site() {
  local id=$1 gw=$2 peer=$3 local_net=$4 remote_net=$5 lid=$6 rid=$7 peernatt=$8
  curl -s -X POST "$CONTROL/api/v1/ipsec" -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
    -d "{\"id\":\"$id\",\"name\":\"$id\",\"gatewayId\":\"$gw\",\"enabled\":true,
         \"peer\":\"$peer\",\"localSubnet\":\"$local_net\",\"remoteSubnet\":\"$remote_net\",
         \"localId\":\"$lid\",\"remoteId\":\"$rid\",
         \"ikeVersion\":\"IKEv2\",\"auth\":\"psk\",\"suite\":\"standard\",
         \"phase1\":{\"enc\":\"AES256-GCM\",\"hash\":\"SHA256\",\"dh\":\"group19\"},
         \"phase2\":{\"enc\":\"AES256-GCM\",\"hash\":\"SHA256\",\"dh\":\"group19\"},
         \"pfs\":true,\"pqHybrid\":false,\"peerNatPort\":$peernatt}" >/dev/null
  curl -s -X PUT "$CONTROL/api/v1/ipsec/$id/psk" -H "Authorization: Bearer $ADMIN" \
    -H 'Content-Type: application/json' -d '{"psk":"baidi-e2e-shared-secret-please-rotate"}' >/dev/null
}
# ★peerNatPort 必须显式给：两个网关在同一个 127.0.0.1 上，只能用不同端口，
# 而 IKEv2 没有通告对端封装端口的机制（RFC 3948 定死 4500），实现只能按对称假设推算。
# 不给的话隧道照样协商成功、显示 up，但 ESP 被发到没人监听的端口，字节数恒为 0。
# 生产上两端都是 4500，这个参数留空即可。
mk_site e2e-a ipsec-a "127.0.0.1:$IKE_B" 10.90.0.0/24 10.91.0.0/24 a.baidi b.baidi "$NATT_B"
mk_site e2e-b ipsec-b "127.0.0.1:$IKE_A" 10.91.0.0/24 10.90.0.0/24 b.baidi a.baidi "$NATT_A"
echo "   ✓ e2e-a / e2e-b 已落库并配好 PSK"

echo "==> 起两个 baidi-ipsec（netstack 数据面，无 root）"
start_node() {
  local cn=$1 ike=$2 natt=$3 addr=$4
  nohup "$WORK/baidi-ipsec" \
    -gwid "$cn" -control "$MTLS" \
    -mtls-cert "$WORK/$cn.crt" -mtls-key "$WORK/$cn.key" -mtls-ca "$WORK/ca.crt" \
    -listen 127.0.0.1 -ike-port "$ike" -natt-port "$natt" \
    -datapath netstack -tun-ip "$addr" -poll 3s -log-level debug \
    >"$WORK/$cn.log" 2>&1 &
}
start_node ipsec-a "$IKE_A" "$NATT_A" 10.90.0.1/24
start_node ipsec-b "$IKE_B" "$NATT_B" 10.91.0.1/24
for cn in ipsec-a ipsec-b; do
  wait_for "$cn 进程起来" 20 "pgrep -f '$WORK/baidi-ipsec .*-gwid $cn'" || {
    echo "   ✗ $cn 未能启动，日志尾部："; tail -20 "$WORK/$cn.log"; exit 1; }
done
echo "   ✓ 两个组网网关已启动"

echo ""
"$WORK/baidi-ipsec-e2e"
RC=$?
echo ""
if [ $RC -eq 0 ]; then
  echo "日志：$WORK/{control,ipsec-a,ipsec-b}.log"
else
  echo "✗ 自检失败。日志：$WORK/{control,ipsec-a,ipsec-b}.log"
  echo "  两端协商日志对照看（AUTH 失败的根因通常只在一端可见）："
  echo "    grep -iE 'ike|auth|proposal|失败' $WORK/ipsec-a.log | tail -30"
fi
exit $RC
