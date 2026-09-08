#!/usr/bin/env bash
# 续期 Let's Encrypt **IP 地址证书**（SAN=IP，只能走 shortlived profile，有效期 6 天 15 小时）。
# 本文件是**模板**：占位由 install-remote.sh 渲染后装到 @BD_PREFIX@/bin/acme-renew.sh，
# 由 systemd 定时器 baidi-acme-renew.timer 每日两次拉起。手工跑一次也完全等价。
#
# ══ 为什么必须有「切回自签」这条回退 ══
#
# 6 天有效期意味着「续不上」很快就变成「证书已过期」，而**过期证书比自签更糟**：
# 自签浏览器还给一个「继续访问」的出口，过期在多数浏览器/客户端上同样拦、而且更容易
# 被读成「站点整个挂了」；桌面端 fetch 与安卓 WebView 在两种情况下的报错也分不开。
# 所以本脚本在「续不下来 **且** 剩余不足 24h」时主动把 nginx 指回自签证书：
# 最坏结果是退回到没启用 ACME 之前的状态（浏览器警告 + 客户端要导信任锚），
# 而不是站点 TLS 直接不可用。
#
# ★回退是**有执行方**的一句话，不是文案：下面 fallback_to_self_signed() 真的改 nginx 配置
#   并 reload。改坏它的症状是静默的——证书照常过期，而这里仍然打印「已切回自签」。
#
# ══ 与 install-remote.sh 的分工 ══
#
#   install-remote.sh  首次签发 + 决定本次部署 nginx 指向哪张证书（每次部署都重渲染配置）
#   本脚本             两次部署**之间**的生命周期：续期、续上了指回 LE、续不上且快过期切自签
#
# 两边都会改 nginx 那两行 ssl_certificate。判据一致：以「文件里真正写着哪条路径」为准，
# 不记任何额外状态——多一份状态就多一次两者不一致的机会，而不一致时的症状
# （证书续着、没人用）恰恰是本功能要消灭的那一种。
set -o pipefail

CRT=@BD_PREFIX@/etc/tls/le.crt
KEY=@BD_PREFIX@/etc/tls/le.key
CSR=@BD_PREFIX@/etc/tls/le.csr
SELF_CRT=@BD_PREFIX@/etc/tls/server.crt
SELF_KEY=@BD_PREFIX@/etc/tls/server.key
ACME_DIR=@BD_PREFIX@/etc/acme
LEGO=@BD_PREFIX@/bin/lego
CONF=/etc/nginx/conf.d/baidi.conf
IP=@PUBLIC_HOST@
ACME_SERVER=@ACME_SERVER@
ACME_EMAIL=@ACME_EMAIL@
ACME_PROFILE=@ACME_PROFILE@

# 剩 4 天以内就续（LE 的建议是剩 1/3 生命周期时续；6 天证书的 1/3 约 2 天，
# 这里取 4 天是给「定时器每天只跑两次 + 一次失败还能再试几轮」留余量）。
RENEW_BELOW_HOURS=96
# 剩不到 1 天还续不上就切自签（见顶部）。
FALLBACK_BELOW_HOURS=24

log() { echo "$(date -Is) $*"; }

# 证书剩余小时数。读不出来（文件不存在 / 不是 PEM）时**返回非零**，由调用方决定怎么办——
# 绝不回 0 冒充「已过期」：那两件事的处置不同（前者是「还没签过」，后者是「该切自签了」）。
hours_left() {
  local end now exp
  end="$(openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2)" || return 1
  [ -n "$end" ] || return 1
  exp="$(date -d "$end" +%s 2>/dev/null)" || return 1
  now="$(date +%s)"
  echo $(( (exp - now) / 3600 ))
}

# 把 nginx 站点里那两行 ssl_certificate / ssl_certificate_key 指向给定的证书对。
# 正则锚在「行首空白 + 指令名 + 空白」上：
#   · 不依赖模板里的对齐方式（install-remote.sh 渲染出来的空格数将来可能变）；
#   · `ssl_certificate` 后面要求**空白**，因此不会误伤 `ssl_certificate_key`（那里跟的是下划线）。
point_nginx_to() { # $1=crt $2=key
  sed -i -E "s#^([[:space:]]*ssl_certificate[[:space:]]+).*;#\1$1;#; \
             s#^([[:space:]]*ssl_certificate_key[[:space:]]+).*;#\1$2;#" "$CONF"
}

# 当前 nginx 配置里写的是哪张证书（判据只有这一个：文件里真正写着的那条路径）。
current_crt() { sed -nE 's#^[[:space:]]*ssl_certificate[[:space:]]+(.*);#\1#p' "$CONF" | head -n1; }

# 改完必须 -t 通过才 reload；-t 不过就原样退回，绝不留一个会让 nginx 起不来的配置
# （这台机可能与烛龙共存，半残配置会毒化对方的下一次 reload）。
apply_nginx() { # $1=改之前的 crt 路径（用于回退）$2=改之前的 key 路径
  if ! nginx -t >/dev/null 2>&1; then
    log "✗ nginx -t 未通过，回退 ssl_certificate 到 $1"
    point_nginx_to "$1" "$2"
    nginx -t >/dev/null 2>&1 || log "✗ 回退后 nginx -t 仍不通过——请人工检查 $CONF"
    return 1
  fi
  systemctl reload nginx || { log "✗ nginx reload 失败"; return 1; }
  return 0
}

switch_to_le() {
  [ "$(current_crt)" = "$CRT" ] && return 0
  log "把 nginx 指向 LE 证书（此前是 $(current_crt)）"
  point_nginx_to "$CRT" "$KEY"
  apply_nginx "$SELF_CRT" "$SELF_KEY"
}

fallback_to_self_signed() {
  [ "$(current_crt)" = "$SELF_CRT" ] && { log "已经是自签，无需回退"; return 0; }
  if [ ! -s "$SELF_CRT" ] || [ ! -s "$SELF_KEY" ]; then
    log "✗ 自签证书不存在（$SELF_CRT），无法回退——站点将带着一张即将/已经过期的证书继续跑"
    return 1
  fi
  log "⚠ 切回自签证书（过期证书比自签更糟：自签还能点「继续」，过期只会被读成站点挂了）"
  point_nginx_to "$SELF_CRT" "$SELF_KEY"
  apply_nginx "$CRT" "$KEY"
}

# ── 前置材料检查：缺什么就说什么，绝不静默空转 ──
for f in "$LEGO" "$CSR"; do
  if [ ! -s "$f" ]; then
    log "✗ 缺少 $f —— 无法续期。这台机上的 LE 证书会一路走到过期。"
    log "  修法：重新部署（deploy.sh，config.env 里 WITH_ACME_IP_CERT=1），由 install-remote.sh 重装材料。"
    exit 1
  fi
done

left="$(hours_left "$CRT")" || {
  log "读不出 $CRT 的有效期（还没签过？不是 PEM？）——按「需要签发」处理"
  left=0
}
log "LE 证书剩余 ${left}h（低于 ${RENEW_BELOW_HOURS}h 才续）"

if [ "$left" -gt "$RENEW_BELOW_HOURS" ]; then
  # ★即使不需要续期，也要确认 nginx 真的在用它。
  #   少了这一句就会落进本功能要消灭的那个静默状态：证书天天续着，而 nginx 配置
  #   在某次重新部署后指回了自签，页面上、日志里、定时器里全都看不出任何异常。
  if ! switch_to_le; then
    log "✗ 证书仍然有效，但把 nginx 指向它这一步没成功（原因见上）"
    log "  站点还在用 $(current_crt) —— 配置已回退到可用状态，但这不是预期姿态。"
    exit 1
  fi
  log "无需续期"
  exit 0
fi

# renew 的 --days 与上面的阈值同源：lego 自己也会判「还早着呢」，两个阈值不一致时
# 会出现「本脚本说该续了、lego 说不用续」的空转，且退出码为 0，看起来一切正常。
renew_days=$(( RENEW_BELOW_HOURS / 24 ))

# ★参数位置有讲究（踩过）：`--csr` 是**全局**参数（lego 之后、子命令之前），
#   `--profile` 是 **renew/run 子命令**的参数。放反了报的是
#   `flag provided but not defined`，与「证书签不下来」看起来是两回事。
# ★`--csr` 指向我们自造的 CSR：CN 必须为空、IP 只能进 SAN，否则 LE 直接回
#   `badCSR :: CSR contains IP address in Common Name`。CSR 由 install-remote.sh 生成。
# 空邮箱不传 --email（同 install-remote.sh：传空串会被 LE 判 invalidContact）。
acme_email_arg=()
if [ -n "$ACME_EMAIL" ]; then acme_email_arg=(--email "$ACME_EMAIL"); fi
# ★写成 if 而不是 `[ -n … ] && …`：后者在 set -e 下、邮箱为空时整条 && 链返回 1，
#   会把脚本当场干掉——而症状是「ACME 段一声不响地什么都没发生」。
# ★展开写成 "${arr[@]+"${arr[@]}"}" 而不是 "${arr[@]}"：后者在 set -u 下、
#   数组为空时，**老 bash（macOS 3.2）会报 unbound variable** 并当场退出。
#   Linux 上的 bash 5 不会，所以这个坑只在本地夹具里才暴露得出来。
if "$LEGO" --server "$ACME_SERVER" --accept-tos "${acme_email_arg[@]+"${acme_email_arg[@]}"}" \
     --http --http.webroot /var/www/html \
     --path "$ACME_DIR" --csr "$CSR" \
     renew --profile "$ACME_PROFILE" --days "$renew_days" 2>&1 | tail -20; then
  # lego 以 CSR 里的第一个标识（这里就是 IP）命名产物。
  if [ -s "$ACME_DIR/certificates/${IP}.crt" ]; then
    # ★install 之前先记下有效期：lego 在 ARI 判「还不到续期时候」时会 exit 0 且
    #   不产出新证书，这里就会把**旧**证书原样 install 一遍。不比一下的话，
    #   脚本会对着一张一个字节都没变的证书报「✓ 续期成功」——而那正是过期前
    #   最后几次运行会看到的假象。
    before_left="$(hours_left "$CRT")" || before_left="?"
    install -m 0644 "$ACME_DIR/certificates/${IP}.crt" "$CRT"
    now_left="$(hours_left "$CRT")" || now_left="?"
    # ★switch_to_le 的返回值必须往上抛：.service 不吞退出码，systemctl --failed 是
    #   这件事在机器上唯一的可见面。丢掉它 = 切换失败而单元显示成功。
    if ! switch_to_le; then
      log "✗ 新证书已就位，但把 nginx 指向它这一步没成功（原因见上）"
      log "  站点还在用 $(current_crt) —— 配置已回退到可用状态。"
      exit 1
    fi
    if [ "$now_left" = "$before_left" ]; then
      # 措辞必须与真实动作一致：没换证书就不能说「续期成功」。
      log "· lego 判定尚不需要续期（ARI/--days），证书未更换，保持现状（剩余 ${now_left}h）"
    else
      log "✓ 续期成功并已 reload（剩余 ${before_left}h → ${now_left}h）"
    fi
    exit 0
  fi
  log "✗ lego 退出码为 0，但 $ACME_DIR/certificates/${IP}.crt 不存在或为空"
  log "  （多半是 CSR 里的标识与 ${IP} 不一致——产物按 CSR 里的标识命名）"
fi

log "⚠ 续期失败（剩余 ${left}h）"
if [ "$left" -lt "$FALLBACK_BELOW_HOURS" ]; then
  fallback_to_self_signed
else
  log "  剩余时间仍充裕，保持现状等下一轮定时器重试（每日两次）"
  # 证书还有效就该在用它——这一步与 left>96 那条分支同理：续期失败不等于
  # 「配置指向哪张」也该跟着错。一次重新部署若把配置写回自签，这里是第二道纠正点。
  switch_to_le || log "  ⚠ 且 nginx 未指向它（见上）"
fi
exit 1
