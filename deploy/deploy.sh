#!/usr/bin/env bash
# 一键部署：本地构建 → rsync 到服务器 → 远程 install-remote.sh（与烛龙共存，独立端口）
# 先 cp config.env.example config.env 并填好，再运行本脚本。
set -eo pipefail   # 不用 -u：旧 bash(如 macOS 3.2)对数组/参数展开会误报 unbound；下面用 := 兜底默认值
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$HERE/config.env" ] || { echo "缺少 $HERE/config.env（参考 config.env.example）"; exit 1; }
# shellcheck disable=SC1091
source "$HERE/config.env"

: "${SERVER_SSH:?需在 config.env 设置 SERVER_SSH，如 root@101.43.125.131}"
: "${BD_PREFIX:=/opt/baidi}"; : "${BD_USER:=baidi}"; : "${CONTROL_PORT:=8090}"; : "${PUBLIC_ORIGIN:=*}"
: "${BD_HTTPS_PORT:=9443}"; : "${PUBLIC_HOST:=}"; : "${SSH_KEY:=}"; : "${WIPE:=0}"; : "${WITH_GATEWAY:=0}"

# 若指定私钥则用之（如 ubuntu 用户需 -i ~/.ssh/xxx）
SSH=(ssh); RSYNC_E=(ssh)
[ -n "$SSH_KEY" ] && { SSH=(ssh -i "$SSH_KEY"); RSYNC_E=(ssh -i "$SSH_KEY"); }

echo "==> 本地构建"
bash "$HERE/build.sh"

echo "==> 上传到 $SERVER_SSH:/tmp/baidi-deploy"
"${SSH[@]}" "$SERVER_SSH" 'rm -rf /tmp/baidi-deploy && mkdir -p /tmp/baidi-deploy'
rsync -az --delete -e "${RSYNC_E[*]}" "$HERE/_out/" "$SERVER_SSH:/tmp/baidi-deploy/"

if [ "$WIPE" = "1" ]; then
  echo "==> ⚠ WIPE=1：铲除目标机原有业务（停服务+备份 nginx+释放 80/443）"
  "${SSH[@]}" "$SERVER_SSH" "sudo bash /tmp/baidi-deploy/wipe-remote.sh"
fi

echo "==> 远程安装（sudo；独立端口 $BD_HTTPS_PORT）"
"${SSH[@]}" "$SERVER_SSH" "sudo BD_PREFIX='$BD_PREFIX' BD_USER='$BD_USER' CONTROL_PORT='$CONTROL_PORT' PUBLIC_ORIGIN='$PUBLIC_ORIGIN' BD_HTTPS_PORT='$BD_HTTPS_PORT' PUBLIC_HOST='${PUBLIC_HOST:-_}' WITH_GATEWAY='$WITH_GATEWAY' bash /tmp/baidi-deploy/install-remote.sh"

echo "✓ 部署完成 → https://${PUBLIC_HOST:-<server>}:${BD_HTTPS_PORT}/"
