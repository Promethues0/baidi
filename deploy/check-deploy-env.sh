#!/usr/bin/env bash
# 部署入参的转发自检：config.env.example 里每一个可设项，deploy.sh 都必须真的转发给远端。
#
# 用法：deploy/check-deploy-env.sh    （无参数，只查仓库里这两份文件）
#
# ══ 守的是什么 ══
#
# install-remote.sh 是经 ssh 起的**新 shell**，config.env 里的值不会自动过去——deploy.sh 那条
# ssh 命令行是一张**显式白名单**。漏掉一项的症状永远是同一个：config.env 里写了、部署也报
# 「✓ 部署完成」，而机器上那一项根本没生效，全程零报错。本仓已经踩到过三次：
#   · WITH_IPSEC / WITH_STEALTH（各自的注释里都写着这段话，是被踩出来才补的）；
#   · BAIDI_BACKUP_*（wave9 做好了主机侧定期自动备份的执行方，四项却既不在模板里也不在
#     白名单里 → **每一台按脚本装出来的机器上它都是关的**，而 /diag 那条 warn 的补救提示
#     恰恰指着那份没有它的模板）；
#   · MTLS_PORT / GW_ID（模板里明明白白列着、还写了"多网关时每台一个"，却从没被转发过 →
#     两台网关都拿装机脚本的默认 CN=gw-1，控制面把它们当同一台：心跳互相覆盖、剖面里只有
#     一个落点，症状是"配了两台网关，控制台上只有一台"）。
#
# ★判据选「模板里的可设项」而不是「install-remote.sh 读到的变量」，理由是前者才是**对运维的
#   承诺**：写进 config.env.example 就等于说"你可以在这里配它"。后者会连带扫出一堆脚本内部
#   常量与逃生舱（ACME_PROFILE / BD_REC_* / FORCE 别名…），噪声大到没人会认真看，而一条没人
#   看的检查等于没有检查。
# ★反方向（转发了但模板里没有）刻意不查：BD_FORCE / BD_MIN_* / BAIDI_CLIENT_SRC_REV 这些是
#   逃生舱或由 deploy.sh 现算的，不该出现在给运维填的模板里。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TPL="$HERE/config.env.example"
DEP="$HERE/deploy.sh"

[ -f "$TPL" ] || { echo "✗ 找不到 $TPL"; exit 1; }
[ -f "$DEP" ] || { echo "✗ 找不到 $DEP"; exit 1; }

fail=0
bad() { echo "✗ $*"; fail=1; }

echo "==> 自检部署入参转发：${TPL} → ${DEP}"

# deploy.sh 里那条起远端安装脚本的 ssh 命令行。整行抓出来一次，后面逐项在里面找。
ssh_line="$(grep -n 'install-remote.sh' "$DEP" | grep 'sudo ' | head -n1 | cut -d: -f2-)"
[ -n "$ssh_line" ] || bad "在 deploy.sh 里找不到那条 \`sudo … bash …/install-remote.sh\` 的 ssh 命令行"

# 本地专用、按设计**不转发**的三项。每一项都要说得出为什么，否则这个豁免名单会变成
# 「检查报错就往里加一行」的垃圾桶——那时它比没有检查更坏。
local_only() {
  case $1 in
    SERVER_SSH) echo "deploy.sh 自己用来 ssh 的目标，转发过去没有意义" ;;
    SSH_KEY)    echo "deploy.sh 自己用来 ssh 的私钥路径，是本地文件" ;;
    WIPE)       echo "决定本地要不要先跑 wipe-remote.sh，install-remote.sh 不读它" ;;
    *)          echo "" ;;
  esac
}

# 模板里的可设项：行首（可带一个注释号）+ 大写变量名 + 等号。
# 注释掉的项同样算——`# BAIDI_BACKUP_PASSPHRASE=` 就是在告诉运维"这里可以配它"。
while read -r k; do
  [ -n "$k" ] || continue
  why="$(local_only "$k")"
  if [ -n "$why" ]; then
    continue
  fi
  # 形状要求 `NAME='$NAME…'`：前面那个空格是词边界（否则查 GW_ID 会被 IPSEC_GW_ID 顶包），
  # 后面要求值真的引用同名变量——只写 `NAME=''` 是"转发了个空值"，比不转发更难查。
  if ! printf '%s' "$ssh_line" | grep -qE " ${k}='\\\$\\{?${k}"; then
    bad "config.env.example 里的 ${k} 没有被 deploy.sh 转发给 install-remote.sh（或转的不是同名变量的值）——config.env 里写了会静默不生效，而部署照样报「✓ 部署完成」"
  fi
done <<EOF
$(grep -E '^#? *[A-Z][A-Z0-9_]*=' "$TPL" | sed -E 's/^#? *//; s/=.*//' | sort -u)
EOF

if [ "$fail" -ne 0 ]; then
  echo "✗ 部署入参转发自检未通过（见上）"
  exit 1
fi
echo "✓ 部署入参转发自检通过：config.env.example 里每一个可设项都在 deploy.sh 的转发白名单里"
