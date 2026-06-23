#!/usr/bin/env bash
# 在目标服务器上安装/更新白帝（root 运行）。渲染占位 → 落盘 → systemd + nginx。
# 用法：sudo BD_PREFIX=/opt/baidi BD_USER=baidi CONTROL_PORT=8090 PUBLIC_ORIGIN='*' ./install-remote.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${BD_PREFIX:=/opt/baidi}"
: "${BD_USER:=baidi}"
: "${CONTROL_PORT:=8090}"
: "${PUBLIC_ORIGIN:=*}"

echo "==> 目标：prefix=$BD_PREFIX user=$BD_USER control_port=$CONTROL_PORT"

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

# 自签 TLS（仅首次；生产请换正式证书）
if [ ! -f "$BD_PREFIX/etc/tls/server.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$BD_PREFIX/etc/tls/server.key" -out "$BD_PREFIX/etc/tls/server.crt" \
    -subj "/CN=baidi" >/dev/null 2>&1
  echo "==> 已生成自签 TLS 证书"
fi

chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX"

# 渲染并安装 systemd 单元
render() { sed -e "s#@BD_PREFIX@#$BD_PREFIX#g" -e "s#@BD_USER@#$BD_USER#g" \
               -e "s#@CONTROL_PORT@#$CONTROL_PORT#g" -e "s#@PUBLIC_ORIGIN@#$PUBLIC_ORIGIN#g" "$1"; }
render "$HERE/systemd/baidi-control.service" > /etc/systemd/system/baidi-control.service
systemctl daemon-reload
systemctl enable --now baidi-control
systemctl restart baidi-control

# 渲染并安装 nginx 站点
render "$HERE/nginx/baidi.conf" > /etc/nginx/conf.d/baidi.conf
nginx -t && systemctl reload nginx

echo "✓ 安装完成。控制台: https://<server>/  ·  门户: https://<server>/portal/login"
echo "  管理员演示账号 admin / baidi@123（生产请改后端登录逻辑或接 IdP）"
systemctl --no-pager status baidi-control | head -5 || true
