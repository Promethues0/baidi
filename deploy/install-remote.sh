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

# 自签 TLS（仅首次；生产请换正式证书）。带 IP/host SAN，避免按 IP 访问告警。
if [ ! -f "$BD_PREFIX/etc/tls/server.crt" ]; then
  san="DNS:baidi"
  [ "$PUBLIC_HOST" != "_" ] && san="$san,IP:$PUBLIC_HOST"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$BD_PREFIX/etc/tls/server.key" -out "$BD_PREFIX/etc/tls/server.crt" \
    -subj "/CN=baidi" -addext "subjectAltName=$san" >/dev/null 2>&1
  echo "==> 已生成自签 TLS 证书（SAN=$san）"
fi

chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX"

# 渲染并安装 systemd 单元
render() { sed -e "s#@BD_PREFIX@#$BD_PREFIX#g" -e "s#@BD_USER@#$BD_USER#g" \
               -e "s#@CONTROL_PORT@#$CONTROL_PORT#g" -e "s#@PUBLIC_ORIGIN@#$PUBLIC_ORIGIN#g" \
               -e "s#@BD_HTTPS_PORT@#$BD_HTTPS_PORT#g" -e "s#@PUBLIC_HOST@#$PUBLIC_HOST#g" "$1"; }
render "$HERE/systemd/baidi-control.service" > /etc/systemd/system/baidi-control.service
systemctl daemon-reload
systemctl enable --now baidi-control
systemctl restart baidi-control

# 渲染并安装 nginx 站点（对烛龙零副作用的双重防御）
render "$HERE/nginx/baidi.conf" > /etc/nginx/conf.d/baidi.conf
# 防御①：白帝绝不得声明 default_server 指令（否则与烛龙的 default_server 冲突）。
#         先剥掉所有注释(整行+行内 # 之后)，再查，避免被说明性注释里的字样误伤。
if sed 's/#.*//' /etc/nginx/conf.d/baidi.conf | grep -q 'default_server'; then
  rm -f /etc/nginx/conf.d/baidi.conf
  echo "✗ 拒绝：baidi nginx 站点含 default_server，已撤销（绝不抢占烛龙 80/443）"; exit 1
fi
# 防御②：nginx -t 失败即撤销坏文件并退出，保证烛龙配置不被半残文件影响
if ! nginx -t; then
  rm -f /etc/nginx/conf.d/baidi.conf
  echo "✗ nginx -t 失败，已撤销 baidi 配置（烛龙站点未受影响）"; exit 1
fi
systemctl reload nginx

echo "✓ 安装完成（与烛龙共存）。控制台: https://${PUBLIC_HOST}:${BD_HTTPS_PORT}/  ·  门户: /portal/login"
echo "  需在腾讯云安全组放行 TCP ${BD_HTTPS_PORT}（如要公网客户端，再放 gateway 18443/tcp + 18201/udp）"
echo "  管理员演示账号 admin / baidi@123（生产请改后端登录逻辑或接 IdP）"
echo "  回滚：systemctl disable --now baidi-control; rm /etc/nginx/conf.d/baidi.conf /etc/systemd/system/baidi-control.service; nginx -t && systemctl reload nginx"
systemctl --no-pager status baidi-control | head -5 || true
