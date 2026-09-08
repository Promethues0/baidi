#!/usr/bin/env bash
# acme-renew.sh 的本地夹具：真跑那份模板（渲染后），外部命令全部换成垫片。
# 只改一处——CONF 指向夹具里的假 nginx 配置（并断言原行存在，模板改了会当场炸）。
set -euo pipefail
FX="$(cd "$(dirname "$0")" && pwd)"
# 运行目录放系统临时区（跑完即删）
TMPS=()
trap 'for d in "${TMPS[@]:-}"; do [ -n "$d" ] && rm -rf "$d"; done' EXIT
# 仓库根：夹具在 deploy/acme-fixture/ 下，上两级即是（不写死绝对路径，换台机器也能跑）
ROOT="$(cd "$FX/../.." && pwd)"
SRC=$ROOT/deploy/acme-renew.sh
export PATH="$FX/bin:$PATH"

pass=0; fail=0
ck() { if [ "$2" = "$3" ]; then echo "    ✓ $1"; pass=$((pass+1)); else echo "    ✗ $1：期望[$3] 实得[$2]"; fail=$((fail+1)); fi; }

setup() { # $1=剩余小时（空=没有 le.crt）  $2=当前 nginx 指向 self|le  $3=lego 成败 ok|bad|missing
  R="$(mktemp -d)"; TMPS+=("$R"); mkdir -p "$R/etc/tls" "$R/etc/acme/certificates" "$R/bin"
  printf 'SELF-CERT\n' > "$R/etc/tls/server.crt"; printf 'SELF-KEY\n' > "$R/etc/tls/server.key"
  printf 'FAKE-CSR san=IP:203.0.113.7\n' > "$R/etc/tls/le.csr"; printf 'LE-KEY\n' > "$R/etc/tls/le.key"
  if [ -n "$1" ]; then printf 'LE-CERT-OLD\n' > "$R/etc/tls/le.crt"; printf '%s\n' "$1" > "$R/etc/tls/le.crt.hours"; fi
  case "$3" in
    ok)   cat > "$R/bin/lego" <<EOF
#!/usr/bin/env bash
echo "lego(fake) \$*"
printf 'LE-CERT-NEW\n' > "$R/etc/acme/certificates/203.0.113.7.crt"
printf '158\n'          > "$R/etc/acme/certificates/203.0.113.7.crt.hours"
exit 0
EOF
          chmod +x "$R/bin/lego" ;;
    bad)  printf '#!/usr/bin/env bash\necho "lego(fake) 失败：acme: error presenting token"\nexit 1\n' > "$R/bin/lego"
          chmod +x "$R/bin/lego" ;;
    missing) : ;;
  esac
  # 假 nginx 配置：只要那两行 ssl_certificate 的形状与模板一致即可
  mkdir -p "$R/nginx"
  if [ "$2" = le ]; then c="$R/etc/tls/le.crt"; k="$R/etc/tls/le.key"; else c="$R/etc/tls/server.crt"; k="$R/etc/tls/server.key"; fi
  cat > "$R/nginx/baidi.conf" <<EOF
server {
    listen 443 ssl http2;
    ssl_certificate     $c;
    ssl_certificate_key $k;
}
EOF
  # 渲染模板 + 把 CONF 指到夹具（断言原行在，模板改了要炸）
  python3 - "$SRC" "$R/acme-renew.sh" "$R" <<'PY'
import sys
src, dst, root = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(src).read()
for k, v in (("@BD_PREFIX@", root), ("@PUBLIC_HOST@", "203.0.113.7"),
             ("@ACME_SERVER@", "https://example.invalid/dir"),
             ("@ACME_EMAIL@", "ops@example.com"), ("@ACME_PROFILE@", "shortlived")):
    s = s.replace(k, v)
old = "CONF=/etc/nginx/conf.d/baidi.conf"
assert old in s, "模板里 CONF 那行变了，夹具需同步"
s = s.replace(old, "CONF=%s/nginx/baidi.conf" % root)
open(dst, "w").write(s)
PY
  chmod +x "$R/acme-renew.sh"
  # 垫片：nginx -t / systemctl reload 一律成功（另有用例单独让 -t 失败）
  printf '#!/usr/bin/env bash\nexit 0\n' > "$FX/bin/nginx"; chmod +x "$FX/bin/nginx"
  printf '#!/usr/bin/env bash\nexit 0\n' > "$FX/bin/systemctl"; chmod +x "$FX/bin/systemctl"
}
crt_now() { sed -nE 's#^[[:space:]]*ssl_certificate[[:space:]]+(.*);#\1#p' "$R/nginx/baidi.conf" | head -n1; }

echo "R1 证书还很新(200h) + nginx 却指着自签 —— 必须把 nginx 指回 LE，且不调 lego"
setup 200 self ok
out="$("$R/acme-renew.sh" 2>&1)"; rc=$?
ck "退出码 0"            "$rc" 0
ck "nginx 已指向 LE"     "$(crt_now)" "$R/etc/tls/le.crt"
ck "没调用 lego"         "$(echo "$out" | grep -c 'lego(fake)')" 0
ck "证书内容未被换掉"    "$(cat "$R/etc/tls/le.crt")" "LE-CERT-OLD"

echo "R2 剩 50h + lego 成功 —— 续期、换证、指向 LE"
setup 50 le ok
out="$("$R/acme-renew.sh" 2>&1)"; rc=$?
ck "退出码 0"            "$rc" 0
ck "调用了 lego"         "$(echo "$out" | grep -c 'lego(fake)')" 1
ck "证书已换成新的"      "$(cat "$R/etc/tls/le.crt")" "LE-CERT-NEW"
ck "仍指向 LE"           "$(crt_now)" "$R/etc/tls/le.crt"

echo "R3 剩 10h + lego 失败 —— 切回自签（过期比自签更糟）"
setup 10 le bad
set +e; out="$("$R/acme-renew.sh" 2>&1)"; rc=$?; set -e
ck "退出码 1"            "$rc" 1
ck "已切回自签"          "$(crt_now)" "$R/etc/tls/server.crt"
ck "说了为什么切"        "$(echo "$out" | grep -c '切回自签')" 1

echo "R4 剩 50h + lego 失败 —— 时间还够，保持现状等下一轮，绝不提前切自签"
setup 50 le bad
set +e; out="$("$R/acme-renew.sh" 2>&1)"; rc=$?; set -e
ck "退出码 1"            "$rc" 1
ck "仍指向 LE"           "$(crt_now)" "$R/etc/tls/le.crt"
ck "没切自签"            "$(echo "$out" | grep -c '切回自签')" 0

echo "R5 lego 二进制不在 —— 明确报错，不动任何配置"
setup 50 le missing
set +e; out="$("$R/acme-renew.sh" 2>&1)"; rc=$?; set -e
ck "退出码 1"            "$rc" 1
ck "点名缺了什么"        "$(echo "$out" | grep -c '缺少.*/bin/lego')" 1
ck "配置没被动过"        "$(crt_now)" "$R/etc/tls/le.crt"

echo "R6 还没签过证书（le.crt 不在）+ lego 成功 —— 续期路径也能兜住首签"
setup "" self ok
out="$("$R/acme-renew.sh" 2>&1)"; rc=$?
ck "退出码 0"            "$rc" 0
ck "证书已落盘"          "$(cat "$R/etc/tls/le.crt")" "LE-CERT-NEW"
ck "nginx 指向 LE"       "$(crt_now)" "$R/etc/tls/le.crt"

echo "R7 续期成功但 nginx -t 不过 —— 必须回退到改之前那张，绝不留一个起不来的配置"
setup 200 self ok
printf '#!/usr/bin/env bash\nexit 1\n' > "$FX/bin/nginx"; chmod +x "$FX/bin/nginx"
set +e; out="$("$R/acme-renew.sh" 2>&1)"; rc=$?; set -e
ck "配置已回退到自签"    "$(crt_now)" "$R/etc/tls/server.crt"
ck "说了 -t 没过"        "$(echo "$out" | grep -c 'nginx -t 未通过')" 1

echo ""
echo "acme-renew.sh 夹具：通过 ${pass}，失败 ${fail}"
[ "$fail" = 0 ]
