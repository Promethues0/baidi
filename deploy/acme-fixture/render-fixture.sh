#!/usr/bin/env bash
# 夹具：验证「重新部署不得把在用 LE 的机器渲染回自签」（F2）。
# 手法与 install-fixture 同款——从真文件里原样抽段执行，抽不到就当场炸。
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$ROOT/deploy/install-remote.sh"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
ok(){ echo "    ✓ $1"; pass=$((pass+1)); }
no(){ echo "    ✗ $1"; fail=$((fail+1)); }

# 抽出渲染段（从 write_nginx_site 定义到 write_nginx_site 调用），并断言原字符串还在
SEG="$W/seg.sh"
python3 - "$SRC" "$SEG" <<'PY'
import sys,re
src,dst=sys.argv[1],sys.argv[2]
s=open(src).read()
a=s.index("write_nginx_site() {")
b=s.index("write_nginx_site\n# 防御①")
seg=s[a:b]+"write_nginx_site\n"
assert "nginx_current_crt()" in seg, "夹具锚点失效：nginx_current_crt 不在这一段里"
assert "本次渲染沿用它" in seg, "夹具锚点失效：F2 那段不在（是不是被改回去了？）"
open(dst,"w").write(seg)
PY
[ -s "$SEG" ] || { echo "抽段失败"; exit 1; }

run_render() {   # $1=既有配置里写的 crt 路径（空=配置不存在） $2=le.crt 是否存在
  local pre="$1" hasle="$2"
  rm -rf "$W/etc"; mkdir -p "$W/etc/nginx/conf.d" "$W/tls"
  BD_PREFIX="$W" ; SELF_CRT="$W/tls/server.crt"; SELF_KEY="$W/tls/server.key"
  LE_CRT="$W/tls/le.crt"; LE_KEY="$W/tls/le.key"
  : > "$SELF_CRT"; : > "$SELF_KEY"
  [ "$hasle" = yes ] && { echo x > "$LE_CRT"; echo x > "$LE_KEY"; }
  [ -n "$pre" ] && printf '    ssl_certificate     %s;\n    ssl_certificate_key %s;\n' "$pre" "${pre%.crt}.key" > "$W/etc/nginx/conf.d/baidi.conf"
  BD_TLS_CRT="$SELF_CRT"; BD_TLS_KEY="$SELF_KEY"; BD_HTTPS_PORT=443
  HERE="$ROOT/deploy"
  render() { sed -e "s#@BD_TLS_CRT@#$BD_TLS_CRT#g" -e "s#@BD_TLS_KEY@#$BD_TLS_KEY#g" \
                 -e "s#@BD_HTTP80_BEGIN@##g" -e "s#@BD_HTTP80_END@##g" "$1"; }
  # 把真段里的 /etc/nginx 重定向到夹具目录
  sed "s#/etc/nginx/conf.d/baidi.conf#$W/etc/nginx/conf.d/baidi.conf#g" "$SEG" > "$W/seg.run.sh"
  . "$W/seg.run.sh" >/dev/null 2>&1
  sed -nE 's#^[[:space:]]*ssl_certificate[[:space:]]+(.*);#\1#p' "$W/etc/nginx/conf.d/baidi.conf" | head -n1
}

echo "R1 机器上已在用 LE 且材料齐全 → 渲染必须沿用 LE（本条就是 F2）"
got=$(run_render "$W/tls/le.crt" yes)
[ "$got" = "$W/tls/le.crt" ] && ok "沿用 LE（$got）" || no "被渲染回自签：$got"

echo "R2 已在用 LE、但 le.key 丢了 → 必须退回自签（材料不全不能硬用）"
rm -rf "$W/etc"; mkdir -p "$W/etc/nginx/conf.d" "$W/tls"
printf '    ssl_certificate     %s;\n' "$W/tls/le.crt" > "$W/etc/nginx/conf.d/baidi.conf"
: > "$W/tls/server.crt"; : > "$W/tls/server.key"; echo x > "$W/tls/le.crt"; rm -f "$W/tls/le.key"
BD_PREFIX="$W" SELF_CRT="$W/tls/server.crt" SELF_KEY="$W/tls/server.key" \
LE_CRT="$W/tls/le.crt" LE_KEY="$W/tls/le.key" BD_TLS_CRT="$W/tls/server.crt" \
BD_TLS_KEY="$W/tls/server.key" BD_HTTPS_PORT=443 HERE="$ROOT/deploy" bash -c '
  render(){ sed -e "s#@BD_TLS_CRT@#$BD_TLS_CRT#g" -e "s#@BD_TLS_KEY@#$BD_TLS_KEY#g" -e "s#@BD_HTTP80_BEGIN@##g" -e "s#@BD_HTTP80_END@##g" "$1"; }
  sed "s#/etc/nginx/conf.d/baidi.conf#'"$W"'/etc/nginx/conf.d/baidi.conf#g" '"$SEG"' > /tmp/segr.sh; . /tmp/segr.sh' >/dev/null 2>&1
got=$(sed -nE 's#^[[:space:]]*ssl_certificate[[:space:]]+(.*);#\1#p' "$W/etc/nginx/conf.d/baidi.conf" | head -n1)
[ "$got" = "$W/tls/server.crt" ] && ok "退回自签（$got）" || no "材料不全却用了 LE：$got"

echo "R3 全新机器（配置不存在）→ 自签"
got=$(run_render "" no)
[ "$got" = "$W/tls/server.crt" ] && ok "自签（$got）" || no "意外：$got"

echo "R4 机器上在用自签 → 保持自签"
got=$(run_render "$W/tls/server.crt" yes)
[ "$got" = "$W/tls/server.crt" ] && ok "保持自签（$got）" || no "意外切到 LE：$got"

echo
echo "渲染段夹具：通过 $pass，失败 $fail"
[ "$fail" = 0 ]
