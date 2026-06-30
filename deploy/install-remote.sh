#!/usr/bin/env bash
# 在目标服务器上安装/更新白帝（root 运行）。渲染占位 → 落盘 → systemd + nginx。
# 用法：sudo BD_PREFIX=/opt/baidi BD_USER=baidi CONTROL_PORT=8090 PUBLIC_ORIGIN='*' ./install-remote.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${BD_PREFIX:=/opt/baidi}"
: "${BD_USER:=baidi}"
: "${CONTROL_PORT:=8090}"
: "${PUBLIC_ORIGIN:=*}"
: "${BD_HTTPS_PORT:=9443}"          # 白帝独立端口，绝不碰烛龙的 80/443
: "${PUBLIC_HOST:=_}"               # nginx server_name + 证书 SAN

echo "==> 目标：prefix=$BD_PREFIX user=$BD_USER control_port=$CONTROL_PORT https_port=$BD_HTTPS_PORT"

# 用户与目录
id -u "$BD_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$BD_USER"
mkdir -p "$BD_PREFIX"/{bin,web,data,etc/tls}

# 二进制 + 前端
install -m 0755 "$HERE/bin/baidi-control" "$BD_PREFIX/bin/baidi-control"
rm -rf "$BD_PREFIX/web"; mkdir -p "$BD_PREFIX/web"
cp -R "$HERE/web/." "$BD_PREFIX/web/"

# JWT 密钥（仅首次生成，保密 0600）
if [ ! -f "$BD_PREFIX/etc/baidi.env" ]; then
  echo "BAIDI_JWT_SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '=+/')" > "$BD_PREFIX/etc/baidi.env"
  chmod 0600 "$BD_PREFIX/etc/baidi.env"
  echo "==> 已生成随机 JWT 密钥 → $BD_PREFIX/etc/baidi.env"
fi

# 自签 TLS（仅首次；生产请换正式证书）。SAN 区分 IP/域名；私钥严格 0600（umask 兜底）。
if [ ! -f "$BD_PREFIX/etc/tls/server.crt" ]; then
  san="DNS:baidi"
  if [ "$PUBLIC_HOST" != "_" ]; then
    case $PUBLIC_HOST in
      *[!0-9.]*) san="$san,DNS:$PUBLIC_HOST" ;; # 含非 IP 字符 → 域名
      *)         san="$san,IP:$PUBLIC_HOST"  ;; # 纯数字与点 → IPv4
    esac
  fi
  ( umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
      -keyout "$BD_PREFIX/etc/tls/server.key" -out "$BD_PREFIX/etc/tls/server.crt" \
      -subj "/CN=baidi" -addext "subjectAltName=$san" >/dev/null 2>&1 )
  chmod 0700 "$BD_PREFIX/etc/tls"; chmod 0600 "$BD_PREFIX/etc/tls/server.key"; chmod 0644 "$BD_PREFIX/etc/tls/server.crt"
  echo "==> 已生成自签 TLS 证书（SAN=$san，私钥 0600）"
fi

chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX"

# 渲染 systemd 单元（先装单元，nginx 校验通过后再启动控制面，避免无入口空跑）
render() { sed -e "s#@BD_PREFIX@#$BD_PREFIX#g" -e "s#@BD_USER@#$BD_USER#g" \
               -e "s#@CONTROL_PORT@#$CONTROL_PORT#g" -e "s#@PUBLIC_ORIGIN@#$PUBLIC_ORIGIN#g" \
               -e "s#@BD_HTTPS_PORT@#$BD_HTTPS_PORT#g" -e "s#@PUBLIC_HOST@#$PUBLIC_HOST#g" "$1"; }
render "$HERE/systemd/baidi-control.service" > /etc/systemd/system/baidi-control.service
systemctl daemon-reload

# 确保 nginx 已装（独占机原业务可能没用 nginx，/etc/nginx/conf.d 可能不存在）
if ! command -v nginx >/dev/null 2>&1; then
  echo "==> 安装 nginx"
  (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx) \
    || yum install -y nginx \
    || { echo "✗ 安装 nginx 失败，请手动安装后重试"; exit 1; }
fi
mkdir -p /etc/nginx/conf.d
# 若主配置没 include conf.d（非标准/被改过），补一行（写进 http 块前的兜底，幂等）
if ! grep -rqs 'conf.d/\*.conf' /etc/nginx/nginx.conf; then
  echo "==> nginx.conf 未 include conf.d，补 include"
  sed -i 's#^\(\s*\)include /etc/nginx/sites-enabled/\*;#\1include /etc/nginx/sites-enabled/*;\n\1include /etc/nginx/conf.d/*.conf;#' /etc/nginx/nginx.conf 2>/dev/null || true
  grep -rqs 'conf.d/\*.conf' /etc/nginx/nginx.conf || sed -i '/http {/a\    include /etc/nginx/conf.d/*.conf;' /etc/nginx/nginx.conf 2>/dev/null || true
fi

# 渲染并校验 nginx 站点（备份→防御→端口预检→nginx -t→reload-or-restart，任一失败即还原）
[ -f /etc/nginx/conf.d/baidi.conf ] && cp -a /etc/nginx/conf.d/baidi.conf /etc/nginx/conf.d/baidi.conf.bak
restore_nginx() { # 有旧备份则还原可用配置，仅首装无备份才删（绝不留半残文件毒化烛龙后续 reload）
  if [ -f /etc/nginx/conf.d/baidi.conf.bak ]; then mv -f /etc/nginx/conf.d/baidi.conf.bak /etc/nginx/conf.d/baidi.conf
  else rm -f /etc/nginx/conf.d/baidi.conf; fi
}
render "$HERE/nginx/baidi.conf" > /etc/nginx/conf.d/baidi.conf
# 独占标准端口(443)时补一个 80→443 跳转：具名 server（server_name=本机），非 default_server，
# 与烛龙共存契约不冲突（名匹配，不抢兜底）；裸 IP / http:// 访问自动跳 https。非 443 端口(共存模式)不加。
if [ "$BD_HTTPS_PORT" = "443" ]; then
  cat >> /etc/nginx/conf.d/baidi.conf <<EOF

# HTTP→HTTPS 跳转（具名，非 default_server）
server {
    listen 80;
    server_name ${PUBLIC_HOST};
    return 301 https://\$host\$request_uri;
}
EOF
fi
# 防御①：白帝绝不得声明 default_server（剥注释后再查，避免被说明性注释里的字样误伤）
if sed 's/#.*//' /etc/nginx/conf.d/baidi.conf | grep -q 'default_server'; then
  restore_nginx; echo "✗ 拒绝：baidi nginx 站点含 default_server，已还原（绝不抢占烛龙 80/443）"; exit 1
fi
# 防御②：端口占用预检——只拦「非 nginx 进程」占用（nginx 占用=baidi/烛龙自己的，我们会重配+nginx -t 兜底）
if command -v ss >/dev/null 2>&1; then
  occ="$(ss -ltnpH "sport = :$BD_HTTPS_PORT" 2>/dev/null)"
  if echo "$occ" | grep -q LISTEN && ! echo "$occ" | grep -q '"nginx"'; then
    restore_nginx; echo "✗ 端口 $BD_HTTPS_PORT 被非 nginx 进程占用，已还原 baidi 配置"; exit 1
  fi
fi
# 防御③：nginx -t 失败即还原
if ! nginx -t; then
  restore_nginx; echo "✗ nginx -t 失败，已还原 baidi 配置（烛龙站点未受影响）"; exit 1
fi
# reload-or-restart：nginx 在跑就 reload(共存场景)，被 wipe 停了就 start(独占场景)
systemctl enable nginx >/dev/null 2>&1 || true
if ! systemctl reload-or-restart nginx; then
  restore_nginx; systemctl reload-or-restart nginx >/dev/null 2>&1 || true
  echo "✗ nginx 重载/启动失败，已还原 baidi 配置"; exit 1
fi
rm -f /etc/nginx/conf.d/baidi.conf.bak

# nginx 就绪后再启动控制面
systemctl enable --now baidi-control
systemctl restart baidi-control

# 可选：数据面网关（SPA 单包授权 + 国密 TLCP 隧道代理）
if [ "${WITH_GATEWAY:-0}" = "1" ]; then
  echo "==> 安装数据面网关 baidi-gateway + 生成国密证书"
  install -m 0755 "$HERE/bin/baidi-gateway" "$BD_PREFIX/bin/baidi-gateway"
  install -m 0755 "$HERE/bin/baidi-gmca" "$BD_PREFIX/bin/baidi-gmca"
  "$BD_PREFIX/bin/baidi-gmca" -dir "$BD_PREFIX/etc/gmcerts" >/dev/null
  chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX/etc/gmcerts" "$BD_PREFIX/bin"
  render "$HERE/systemd/baidi-gateway.service" > /etc/systemd/system/baidi-gateway.service
  systemctl daemon-reload
  systemctl enable --now baidi-gateway
  systemctl restart baidi-gateway
  sleep 1
  systemctl is-active --quiet baidi-gateway && echo "  ✓ baidi-gateway 已起：SPA :18201/udp + 国密 TLCP 代理 :18443/tcp（与 control 同密钥，后端=control:${CONTROL_PORT}）" \
    || { echo "  ✗ baidi-gateway 启动失败，看日志："; journalctl -u baidi-gateway --no-pager -n 12; }
fi

echo "✓ 安装完成。控制台: https://${PUBLIC_HOST}:${BD_HTTPS_PORT}/  ·  门户: /portal/login"
echo "  需在腾讯云安全组放行 TCP ${BD_HTTPS_PORT}（如要公网客户端，再放 gateway 18443/tcp + 18201/udp）"
echo "  管理员演示账号 admin / baidi@123（生产请改后端登录逻辑或接 IdP）"
echo "  回滚：systemctl disable --now baidi-control; rm /etc/nginx/conf.d/baidi.conf /etc/systemd/system/baidi-control.service; nginx -t && systemctl reload nginx"
systemctl --no-pager status baidi-control | head -5 || true
