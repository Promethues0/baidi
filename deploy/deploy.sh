#!/usr/bin/env bash
# 一键部署：本地构建 → rsync 到服务器 → 远程 install-remote.sh
# 先 cp config.env.example config.env 并填好，再运行本脚本。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/config.env" ] || { echo "缺少 $HERE/config.env（参考 config.env.example）"; exit 1; }
# shellcheck disable=SC1091
source "$HERE/config.env"

: "${SERVER_SSH:?需在 config.env 设置 SERVER_SSH，如 root@124.223.225.77}"
: "${BD_PREFIX:=/opt/baidi}"; : "${BD_USER:=baidi}"; : "${CONTROL_PORT:=8090}"; : "${PUBLIC_ORIGIN:=*}"

echo "==> 本地构建"
bash "$HERE/build.sh"

echo "==> 上传到 $SERVER_SSH:/tmp/baidi-deploy"
ssh "$SERVER_SSH" 'rm -rf /tmp/baidi-deploy && mkdir -p /tmp/baidi-deploy'
rsync -az --delete "$HERE/_out/" "$SERVER_SSH:/tmp/baidi-deploy/"

echo "==> 远程安装"
ssh "$SERVER_SSH" "sudo BD_PREFIX='$BD_PREFIX' BD_USER='$BD_USER' CONTROL_PORT='$CONTROL_PORT' PUBLIC_ORIGIN='$PUBLIC_ORIGIN' bash /tmp/baidi-deploy/install-remote.sh"

echo "✓ 部署完成 → https://${PUBLIC_HOST:-<server>}/"
