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
# 站点组网（默认关）。这几项必须显式转发给远端：install-remote.sh 是经 ssh 起的新 shell，
# config.env 里的值不会自动过去——漏转的症状是「config.env 里写了 WITH_IPSEC=1，
# 部署成功，机器上却根本没有 baidi-ipsec」，且全程无报错。
: "${WITH_IPSEC:=0}"; : "${IPSEC_GW_ID:=}"; : "${IKE_PORT:=}"; : "${NATT_PORT:=}"
# 首登强制改密：**默认 1**（wave8 行动 16）。同样必须显式转发，否则 config.env 里写了也悄悄不生效。
#
# ★为什么默认翻成 1：NFR-SEC-05 是 P0，验收词就是「默认安全开局：首登强制改密、
# 无默认弱口令」。默认 0 的实际后果是——按参考流程装出来的**生产机开局就带着一个
# 写在 README / CLAUDE.md / 演示站说明里的公开口令**（baidi@123），而系统不催任何人改。
# 本项目在「收口默认值与逃生舱」一节确立过判据：三个 HS256 逃生舱都被翻成默认 false，
# 理由是「默认值就是绝大多数部署的真实姿态」——这一项此前恰恰反着来。
# 演示便利由演示机在 config.env 里**显式**置 0 承担（那是一次有意识的选择，
# 而不是一个谁也没看见的默认值）。
: "${BAIDI_SEED_MUST_CHANGE:=1}"

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

# 环境基线自检的旋钮必须**跟着这条路径转发**：install-remote.sh 的自检是本脚本历史上
# 第一个能拦住部署的闸，而这条 ssh 是白名单式显式转发。不转发的话，中止文案里那句
# 「BD_FORCE=1 可跳过」在标准部署路径上根本够不着——运维只能改走手工 ssh 拼环境变量，
# 等于把一条逃生舱写在了门外。
: "${BD_FORCE:=}" "${BD_MIN_CPU:=}" "${BD_MIN_MEM_MB:=}" "${BD_MIN_DISK_MB:=}" "${BD_DNS_PROBE_HOST:=}"

echo "==> 远程安装（sudo；独立端口 ${BD_HTTPS_PORT}）"
"${SSH[@]}" "$SERVER_SSH" "sudo BD_PREFIX='$BD_PREFIX' BD_USER='$BD_USER' CONTROL_PORT='$CONTROL_PORT' PUBLIC_ORIGIN='$PUBLIC_ORIGIN' BD_HTTPS_PORT='$BD_HTTPS_PORT' PUBLIC_HOST='${PUBLIC_HOST:-_}' WITH_GATEWAY='$WITH_GATEWAY' WITH_IPSEC='$WITH_IPSEC' IPSEC_GW_ID='$IPSEC_GW_ID' IKE_PORT='$IKE_PORT' NATT_PORT='$NATT_PORT' BAIDI_SEED_MUST_CHANGE='$BAIDI_SEED_MUST_CHANGE' BD_FORCE='$BD_FORCE' BD_MIN_CPU='$BD_MIN_CPU' BD_MIN_MEM_MB='$BD_MIN_MEM_MB' BD_MIN_DISK_MB='$BD_MIN_DISK_MB' BD_DNS_PROBE_HOST='$BD_DNS_PROBE_HOST' bash /tmp/baidi-deploy/install-remote.sh"

echo "✓ 部署完成 → https://${PUBLIC_HOST:-<server>}:${BD_HTTPS_PORT}/"
