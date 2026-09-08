#!/usr/bin/env bash
# install-remote.sh 里那段 ACME 的本地夹具。
# 做法：从真文件里**原样抽出**那一段（连同它依赖的 render / nginx_current_crt），
# 只把三个绝对路径重定向到夹具目录，并逐个断言原字符串存在——真文件一改形状，夹具当场炸，
# 不会出现「夹具还在绿、代码早已不是那段」的情况。
set -euo pipefail
FX="$(cd "$(dirname "$0")" && pwd)"
# 仓库根：夹具在 deploy/acme-fixture/ 下，上两级即是（不写死绝对路径，换台机器也能跑）
ROOT="$(cd "$FX/../.." && pwd)"
SRC="${SRC:-$ROOT/deploy/install-remote.sh}"
export PATH="$FX/bin:$PATH"

pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then echo "    ✓ $1"; pass=$((pass+1)); else echo "    ✗ $1：期望[$3] 实得[$2]"; fail=$((fail+1)); fi; }
ckc() { if echo "$2" | grep -q "$3"; then echo "    ✓ $1"; pass=$((pass+1)); else echo "    ✗ $1：输出里找不到 [$3]"; fail=$((fail+1)); fi; }

# 运行目录放系统临时区（跑完即删）：放在仓库里会让每跑一次夹具就多出一堆未跟踪文件
R="$(mktemp -d)"; trap 'rm -rf "$R"' EXIT
extract() { # → $R/block.sh
  python3 - "$SRC" "$R/block.sh" "$R" <<'PY'
import sys
src, dst, root = sys.argv[1:4]
s = open(src).read()
# ① render()：从 "render() { sed -e" 到第一行以 '"$1"; }' 结尾
i = s.index('render() { sed -e')
j = s.index('"$1"; }', i) + len('"$1"; }')
render = s[i:j]
# ② nginx_current_crt()：单行函数
k = s.index('nginx_current_crt() {')
render += "\n" + s[k:s.index("\n", k)]
# ③ ACME 段：acme_state=disabled … 到「nginx 就绪后再启动控制面」之前
a = s.index('acme_state=disabled')
b = s.index('# nginx 就绪后再启动控制面')
block = s[a:b]
for old, new in (("/etc/systemd/system/", root + "/etc/systemd/system/"),
                 ("/etc/nginx/conf.d/",  root + "/etc/nginx/conf.d/"),
                 ("/var/www/html",       root + "/var/www/html")):
    assert old in block or old in render, "夹具重定向的路径 %s 在真文件里找不到了" % old
    block = block.replace(old, new); render = render.replace(old, new)
open(dst, "w").write(render + "\n" + block + '\necho "ACME_STATE=$acme_state"\necho "BD_TLS_CRT=$BD_TLS_CRT"\n')
PY
}

setup() { # $1=WITH_ACME_IP_CERT $2=PUBLIC_HOST $3=BD_HTTPS_PORT $4=ACME_EMAIL $5=lego(ok|bad|none) $6=已有证书剩余小时(空=无)
  rm -rf "$R"; mkdir -p "$R/etc/tls" "$R/bin" "$R/etc/nginx/conf.d" "$R/etc/systemd/system" "$R/pkg/bin" "$R/pkg/systemd"
  printf 'SELF-CERT\n' > "$R/etc/tls/server.crt"; printf 'SELF-KEY\n' > "$R/etc/tls/server.key"
  # 续期脚本模板里 CONF 是写死的 /etc/nginx/conf.d/baidi.conf（生产上就该写死）；
  # 夹具把它重定向到本地，并断言原行存在。
  python3 - $ROOT/deploy/acme-renew.sh "$R/pkg/acme-renew.sh" "$R" <<'PY2'
import sys
src,dst,root=sys.argv[1:4]
s=open(src).read()
old="CONF=/etc/nginx/conf.d/baidi.conf"
assert old in s, "acme-renew.sh 里 CONF 那行变了，夹具需同步"
open(dst,"w").write(s.replace(old,"CONF=%s/etc/nginx/conf.d/baidi.conf"%root))
PY2
  cp $ROOT/deploy/systemd/baidi-acme-renew.service "$R/pkg/systemd/"
  cp $ROOT/deploy/systemd/baidi-acme-renew.timer   "$R/pkg/systemd/"
  case "$5" in
    ok)  cat > "$R/pkg/bin/lego" <<EOF
#!/usr/bin/env bash
echo "lego(fake) \$*"
# 记下收到的 argv：有些断言要检查某个参数**没有**出现（例如空邮箱时不许传 --email，
# 传空串会被 LE 判 invalidContact）。只看退出码是查不出这种事的。
printf '%s\n' "\$@" > "$R/lego.argv"
mkdir -p "$R/etc/acme/certificates"
printf 'LE-CERT-NEW\n' > "$R/etc/acme/certificates/$2.crt"
printf '158\n'          > "$R/etc/acme/certificates/$2.crt.hours"
exit 0
EOF
         chmod +x "$R/pkg/bin/lego" ;;
    bad) printf '#!/usr/bin/env bash\necho "lego(fake) 失败：acme: error: 403 urn:ietf:params:acme:error:unauthorized"\nexit 1\n' > "$R/pkg/bin/lego"
         chmod +x "$R/pkg/bin/lego" ;;
    none) : ;;
  esac
  if [ -n "$6" ]; then
    printf 'LE-CERT-OLD\n' > "$R/etc/tls/le.crt"; printf '%s\n' "$6" > "$R/etc/tls/le.crt.hours"
    printf 'LE-KEY\n' > "$R/etc/tls/le.key"; printf "FAKE-CSR san=IP:$2\n" > "$R/etc/tls/le.csr"
  fi
  cat > "$R/etc/nginx/conf.d/baidi.conf" <<EOF
server {
    ssl_certificate     $R/etc/tls/server.crt;
    ssl_certificate_key $R/etc/tls/server.key;
}
EOF
  printf '#!/usr/bin/env bash\nexit 0\n' > "$FX/bin/nginx";     chmod +x "$FX/bin/nginx"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$FX/bin/systemctl"; chmod +x "$FX/bin/systemctl"
  extract
  cat > "$R/harness.sh" <<EOF
set -euo pipefail
HERE="$R/pkg"; BD_PREFIX="$R"
PUBLIC_HOST="$2"; BD_HTTPS_PORT="$3"
WITH_ACME_IP_CERT="$1"; ACME_EMAIL="$4"
ACME_SERVER=https://example.invalid/dir; ACME_PROFILE=shortlived
SELF_CRT="\$BD_PREFIX/etc/tls/server.crt"; SELF_KEY="\$BD_PREFIX/etc/tls/server.key"
LE_CRT="\$BD_PREFIX/etc/tls/le.crt"; LE_KEY="\$BD_PREFIX/etc/tls/le.key"; LE_CSR="\$BD_PREFIX/etc/tls/le.csr"
BD_TLS_CRT="\$SELF_CRT"; BD_TLS_KEY="\$SELF_KEY"
# render() 里引用的其它占位变量（本段用不到，给空值以免 set -u 踩空）
BD_USER=baidi; GW_USER=baidi; GW_PF=""; GW_STEALTH_DEP="#"; CONTROL_PORT=8090
PUBLIC_ORIGIN='*'; MTLS_PORT=8092; GW_ID=gw-1; IPSEC_GW_ID=ipsec-gw-1; IKE_PORT=500; NATT_PORT=4500
. "$R/block.sh"
EOF
}
crt_now() { sed -nE 's#^[[:space:]]*ssl_certificate[[:space:]]+(.*);#\1#p' "$R/etc/nginx/conf.d/baidi.conf" | head -n1; }
runit() { set +e; OUT="$(bash "$R/harness.sh" 2>&1)"; RC=$?; set -e; }
state() { echo "$OUT" | sed -n 's/^ACME_STATE=//p'; }
tlscrt() { echo "$OUT" | sed -n 's/^BD_TLS_CRT=//p'; }

echo "I1 开关关闭 —— 与今天逐字一致：什么都不做"
setup 0 203.0.113.7 443 ops@example.com ok ""; runit
ck "退出码 0"        "$RC" 0
ck "状态 disabled"   "$(state)" disabled
ck "仍是自签"        "$(tlscrt)" "$R/etc/tls/server.crt"
ck "没装定时器"      "$(ls "$R/etc/systemd/system" | wc -l | tr -d ' ')" 0

echo "I1b 开关关闭、但机器上还留着上一轮的 LE 证书 —— 必须当面说（否则定时器续着、站点用自签）"
setup 0 203.0.113.7 443 ops@example.com ok 200; runit
ckc "点出了残留" "$OUT" 'WITH_ACME_IP_CERT=0，但机器上有'
ckc "给了关闭命令" "$OUT" 'systemctl disable --now baidi-acme-renew.timer'

echo "I2 PUBLIC_HOST 不是裸 IP —— 拒绝并说清是 IP 证书"
setup 1 baidi.example.com 443 ops@example.com ok ""; runit
ck "状态 failed"   "$(state)" failed
ck "仍是自签"      "$(tlscrt)" "$R/etc/tls/server.crt"
ckc "点名 IPv4"    "$OUT" '不是裸 IPv4'
ckc "说了保持自签" "$OUT" '保持自签证书'

echo "I2b 半截 IP（1.2.3）也要拒 —— 宽松判据会让它一路走到 lego 那里报 ACME 侧的错"
setup 1 1.2.3 443 ops@example.com ok ""; runit
ck "状态 failed" "$(state)" failed
echo "I2c 越界 IP（1.2.3.999）同上"
setup 1 1.2.3.999 443 ops@example.com ok ""; runit
ck "状态 failed" "$(state)" failed

echo "I3 共存端口（9443）—— 拒绝，理由是 80 归烛龙"
setup 1 203.0.113.7 9443 ops@example.com ok ""; runit
ck "状态 failed" "$(state)" failed
ckc "点名 80 端口" "$OUT" 'HTTP-01 挑战必须由本机 80 端口应答'

echo "I4 没填邮箱 —— 放行，走无邮箱注册（LE 自 2025-06 起不再发到期提醒邮件，"
echo "   「邮箱是提醒的唯一去处」这条旧理由已不成立；到期由本机定时器负责）"
setup 1 203.0.113.7 443 "" ok ""; runit
ck "状态 ok（不因空邮箱被拒）" "$(state)" ok
ck "仍切到了 LE"              "$(tlscrt)" "$R/etc/tls/le.crt"
# ★关键：命令行里**不能**出现 --email（传空串 lego 会拿它当邮箱去注册，被 LE 判
#   invalidContact）。夹具里的 lego 垫片会把收到的 argv 记进 $R/lego.argv。
if [ -f "$R/lego.argv" ] && grep -q -- '--email' "$R/lego.argv"; then
  ck "空邮箱时命令行里没有 --email" "有 --email" "没有 --email"
else
  ck "空邮箱时命令行里没有 --email" "没有 --email" "没有 --email"
fi

echo "I5 包里没带 lego —— 明确报错并说清怎么补，绝不静默"
setup 1 203.0.113.7 443 ops@example.com none ""; runit
ck "状态 failed" "$(state)" failed
ck "仍是自签"    "$(tlscrt)" "$R/etc/tls/server.crt"
ckc "点名 lego"  "$OUT" '部署包里没有 bin/lego'
ckc "给了补救"   "$OUT" '重跑 deploy/build.sh'

echo "I5b 包里没带 lego、但机器上已经有一份 —— 沿用它，别把部署变成一次降级"
setup 1 203.0.113.7 443 ops@example.com none 200
cat > "$R/bin/lego" <<EOF
#!/usr/bin/env bash
echo "lego(machine-fake) \$*"
exit 0
EOF
chmod +x "$R/bin/lego"
runit
ck "状态 ok（沿用机器上那份，证书仍新鲜）" "$(state)" ok
ck "nginx 指向 LE" "$(crt_now)" "$R/etc/tls/le.crt"
ckc "当面说了沿用" "$OUT" '沿用机器上已有的'

echo "I6 一切就绪 + 首签成功 —— 站点切到 LE，定时器与续期脚本都装上"
setup 1 203.0.113.7 443 ops@example.com ok ""; runit
ck "退出码 0"        "$RC" 0
ck "状态 ok"         "$(state)" ok
ck "BD_TLS_CRT=LE"   "$(tlscrt)" "$R/etc/tls/le.crt"
ck "nginx 已指向 LE" "$(crt_now)" "$R/etc/tls/le.crt"
ck "证书已落盘"      "$(cat "$R/etc/tls/le.crt")" "LE-CERT-NEW"
ck "续期脚本已装"    "$([ -x "$R/bin/acme-renew.sh" ] && echo y)" y
ck "service 已装"    "$([ -f "$R/etc/systemd/system/baidi-acme-renew.service" ] && echo y)" y
ck "timer 已装"      "$([ -f "$R/etc/systemd/system/baidi-acme-renew.timer" ] && echo y)" y
ckc "CSR 是自造的"   "$OUT" 'CN 空、SAN=IP:203.0.113.7'

echo "I7 首签失败 —— 保持自签、站点可用、原因当面说"
setup 1 203.0.113.7 443 ops@example.com bad ""; runit
ck "退出码 0（部署不因证书失败而失败）" "$RC" 0
ck "状态 failed" "$(state)" failed
ck "仍是自签"    "$(tlscrt)" "$R/etc/tls/server.crt"
ck "nginx 仍自签" "$(crt_now)" "$R/etc/tls/server.crt"
ckc "列了成因①" "$OUT" '公网打不到本机 80 端口'
ckc "定时器仍装上了（下一轮还能自愈）" "$OUT" '续期脚本与定时器已装'

echo "I8 已有新鲜证书、但本次部署刚把 nginx 渲染回自签 —— 必须重新指向 LE"
echo "   （这正是本轨要消灭的静默状态：证书续着、没人用）"
setup 1 203.0.113.7 443 ops@example.com bad 200; runit
ck "状态 ok"         "$(state)" ok
ck "nginx 指向 LE"   "$(crt_now)" "$R/etc/tls/le.crt"
ck "没重签（lego 一次都没成功也没关系）" "$(cat "$R/etc/tls/le.crt")" "LE-CERT-OLD"

echo "I9 CSR 的 SAN 与本次 PUBLIC_HOST 不符 —— 必须重造，不能拿旧 IP 的 CSR 去签"
setup 1 203.0.113.7 443 ops@example.com ok 200
printf 'FAKE-CSR san=IP:198.51.100.9\n' > "$R/etc/tls/le.csr"
runit
ckc "识别出不符" "$OUT" '现有 CSR 的 SAN 与 203.0.113.7 不符'
ckc "重造了 CSR" "$OUT" 'CN 空、SAN=IP:203.0.113.7'

echo "I10 签发成功、但续期脚本没能把 nginx 切过去（模拟 nginx -t 常失败）—— 摘要必须说出真实原因"
setup 1 203.0.113.7 443 ops@example.com ok ""
printf '#!/usr/bin/env bash\nexit 1\n' > "$FX/bin/nginx"; chmod +x "$FX/bin/nginx"
runit
printf '#!/usr/bin/env bash\nexit 0\n' > "$FX/bin/nginx"; chmod +x "$FX/bin/nginx"
ck "状态 failed" "$(state)" failed
ckc "说清是切换没成而不是占位文案" "$OUT" '但 nginx 站点仍指向'
ck "没留下占位理由" "$(echo "$OUT" | grep -c '这行不该被看到')" 0

echo ""
echo "install-remote.sh ACME 段夹具：通过 ${pass}，失败 ${fail}"
[ "$fail" = 0 ]
