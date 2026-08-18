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

# ── 部署前环境基线自检（FR-DEPLOY-01）────────────────────────────────────────
# 姿态照抄本文件下面两处既有预检（nginx default_server 防御① / 端口占用防御②）：
# 中止时当场说清三件事——检出了什么、为什么这就不行、怎么绕过。
#
# 位置刻意放在**一切写操作之前**（useradd / mkdir / install 全在下面）：中止时这台
# 机器一个字节都没被改过，运维不必先做清理才能重来。
#
# 两档阈值，刻意不是一刀切：
#   硬下限 —— 低于即中止。只收「这台机连一次部署都做不完 / 起来必被 OOM 杀」的量。
#   推荐值 —— 低于只警告。按 deploy/_out 的实测体积与常驻进程数给出的舒适量。
# ★宁可宽松不可误杀：这段跑在**远端生产机**上，一次假阳性 = 一次本可成功的部署被
#   自己的脚本挡在门外，而运维此刻手里没有第二条路。所以 CPU / DNS / 时间同步三项
#   **永不中止**：它们判出来的「不达标」要么只是慢，要么根本是「判不了」——
#   而「判不了 ≠ 不达标」是本项目在 posture 采集三态、gateway_metrics 不补 0 上
#   反复写过的同一条纪律，这里不破例。
: "${BD_MIN_CPU:=2}"          # CPU 推荐核数（仅警告，永不中止）
: "${BD_MIN_MEM_MB:=400}"     # 内存硬下限 MiB（低于即中止）
: "${BD_REC_MEM_MB:=1900}"    # 内存推荐值 MiB（仅警告）
: "${BD_MIN_DISK_MB:=600}"    # BD_PREFIX 所在分区可用磁盘硬下限 MiB（低于即中止）
: "${BD_REC_DISK_MB:=4096}"   # 可用磁盘推荐值 MiB（仅警告）
: "${BD_DNS_PROBE_HOST:=archive.ubuntu.com}"   # DNS 自检探的域名（内网部署可换成内部域名）
: "${BD_FORCE:=${FORCE:-0}}"  # =1 跳过硬下限中止（FORCE 是兼容别名）

echo "==> 环境基线自检（FR-DEPLOY-01）"
envck_bad=0    # 低于硬下限的项数（>0 且未 BD_FORCE 即中止）
envck_warn=0   # 仅警告的项数（含「判不了」）

# 阈值必须是纯数字：下面全用 [ -lt ] 比，喂进非数字会让 test 直接报
# 「integer expression expected」并在 set -e 下退 2——那条报错既不说是哪个变量，
# 也不说该怎么改。宁可在这里当场点名。
for v in BD_MIN_CPU BD_MIN_MEM_MB BD_REC_MEM_MB BD_MIN_DISK_MB BD_REC_DISK_MB; do
  # ${!v} 间接展开（bash 2 起就有，3.2 也吃）；上面的 := 保证这五个一定已赋值，set -u 不会踩空。
  case "${!v}" in
    ''|*[!0-9]*)
      echo "✗ ${v}=${!v} 不是非负整数，拒绝安装（阈值是拿来做数值比较的）"; exit 1 ;;
  esac
done

# 本次会常驻在这台机上的进程，内存文案要按它报数而不是含糊说「几个服务」。
bd_procs="baidi-control + nginx"
if [ "${WITH_GATEWAY:-0}" = "1" ]; then bd_procs="${bd_procs} + baidi-gateway"; fi
if [ "${WITH_IPSEC:-0}" = "1" ]; then bd_procs="${bd_procs} + baidi-ipsec"; fi

# ① CPU 核数。**永不中止**：核少只会慢，不会装不上、也不会起不来；而 1C 云主机是
#    演示/测试环境最常见的形态，为它中止就是纯粹的误杀。把 BD_MIN_CPU 调高也只是
#    抬高这行文案的门槛，仍然只警告。
bd_cpu="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo '')"
case "$bd_cpu" in ''|*[!0-9]*) bd_cpu="" ;; esac
if [ -z "$bd_cpu" ]; then
  echo "  ⚠ CPU 核数：读不出（无 nproc、也无 getconf）——不可判定，不当作不达标"
  envck_warn=$((envck_warn + 1))
elif [ "$bd_cpu" -lt "$BD_MIN_CPU" ]; then
  echo "  ⚠ CPU 核数：${bd_cpu}（推荐 ≥ ${BD_MIN_CPU}，不中止）"
  echo "      后果只是慢：TLS/TLCP 握手、SM2 签验、用户态 ESP 加解密全在 CPU 上，"
  echo "      单核时它们与 baidi-control 抢同一个核，表现为登录与隧道建立变慢。"
  envck_warn=$((envck_warn + 1))
else
  echo "  ✓ CPU 核数：${bd_cpu}"
fi

# ② 内存总量（/proc/meminfo 的 MemTotal，单位 kB）。
# ★阈值刻意避开整数边界。MemTotal 报的是内核可用内存，固件与内核预留会吃掉一截：
#   标称 2 GiB 的云主机通常只报 1.9 GiB 出头，写 2048 会让**每一台** 2G 机器都无谓
#   报一次警。硬下限 400 同理——标称 512 MiB 的机器报不到 500，它能跑只是紧；
#   被这道闸拦下的是 256/384 MiB 那一档，那一档是真的起不来。
#   内存这两个数是**按常驻进程数与 Go 运行时量级估的，不是实测 RSS**（本仓库没做过
#   RSS 基准）——所以硬下限只敢定在「必然 OOM」那一侧，不拿估计值去卡边界。
bd_mem_mb=""
if [ -r /proc/meminfo ]; then
  bd_mem_kb="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo '')"
  case "$bd_mem_kb" in ''|*[!0-9]*) bd_mem_kb="" ;; esac
  if [ -n "$bd_mem_kb" ]; then bd_mem_mb=$((bd_mem_kb / 1024)); fi
fi
if [ -z "$bd_mem_mb" ]; then
  echo "  ⚠ 内存总量：读不出 /proc/meminfo——不可判定，不当作不达标"
  envck_warn=$((envck_warn + 1))
elif [ "$bd_mem_mb" -lt "$BD_MIN_MEM_MB" ]; then
  echo "  ✗ 内存总量：${bd_mem_mb} MiB，低于硬下限 ${BD_MIN_MEM_MB} MiB"
  echo "      这台机装得上但跑不住：常驻的 ${bd_procs} 之外，安装期还要跑 apt/yum 与 openssl；"
  echo "      OOM killer 挑的是 RSS 最大的那个（通常正是 baidi-control），"
  echo "      表现为「部署显示成功、服务过几分钟自己没了」，而 journal 里只有一行 Killed。"
  envck_bad=$((envck_bad + 1))
elif [ "$bd_mem_mb" -lt "$BD_REC_MEM_MB" ]; then
  echo "  ⚠ 内存总量：${bd_mem_mb} MiB（推荐 ≥ ${BD_REC_MEM_MB} MiB，不中止）"
  echo "      常驻进程：${bd_procs}；控制面用的是纯 Go SQLite（modernc），页缓存与 GC 都吃内存。"
  envck_warn=$((envck_warn + 1))
else
  echo "  ✓ 内存总量：${bd_mem_mb} MiB"
fi

# ③ 目标分区可用磁盘。**看 BD_PREFIX 所在分区，不是 /**：把 /opt 或 /data 单挂一块盘
#    是常见做法，查 / 得出的数字与安装目标毫无关系——典型症状是「预检通过、cp -R 中途
#    ENOSPC」，而那时 web/ 已经是半棵目录树了。
# ★首装时 BD_PREFIX 还不存在（mkdir 在下面几行），而 df 对不存在的路径直接报错，
#   所以往上找最近一个存在的祖先目录再问。不兜这一下的话，这项检查在首装时永远走不到。
bd_dfpath="$BD_PREFIX"
while [ ! -d "$bd_dfpath" ]; do
  bd_parent="$(dirname "$bd_dfpath")"
  if [ "$bd_parent" = "$bd_dfpath" ]; then break; fi
  bd_dfpath="$bd_parent"
done
if [ ! -d "$bd_dfpath" ]; then bd_dfpath="/"; fi
# -P 保证一个文件系统只占一行（长设备名默认会折行，折了 NR==2 取到的是设备名那半行），
# -k 固定 1024 字节块（不加就吃 POSIXLY_CORRECT/BLOCKSIZE 的脸色，数值会差一倍）。
bd_avail_mb=""
bd_avail_kb="$(df -Pk "$bd_dfpath" 2>/dev/null | awk 'NR == 2 {print $4}' || echo '')"
case "$bd_avail_kb" in ''|*[!0-9]*) bd_avail_kb="" ;; esac
if [ -n "$bd_avail_kb" ]; then bd_avail_mb=$((bd_avail_kb / 1024)); fi
if [ -z "$bd_avail_mb" ]; then
  echo "  ⚠ 可用磁盘：df 读不出 ${bd_dfpath} 所在分区——不可判定，不当作不达标"
  envck_warn=$((envck_warn + 1))
elif [ "$bd_avail_mb" -lt "$BD_MIN_DISK_MB" ]; then
  echo "  ✗ 可用磁盘：${bd_dfpath} 所在分区仅剩 ${bd_avail_mb} MiB，低于硬下限 ${BD_MIN_DISK_MB} MiB"
  echo "      一次部署的峰值实测约 334 MiB：交付包落盘 127（bin 45 + web 2 + 客户端包 80）"
  echo "      + /tmp/baidi-deploy 的暂存副本同样 127 + 客户端包原子切换期并存的第二份 80。"
  echo "      不够时的失败点在 cp -R 中途，留下的是半棵 web/ 目录树而不是一次干净的失败。"
  envck_bad=$((envck_bad + 1))
elif [ "$bd_avail_mb" -lt "$BD_REC_DISK_MB" ]; then
  echo "  ⚠ 可用磁盘：${bd_dfpath} 所在分区剩 ${bd_avail_mb} MiB（推荐 ≥ ${BD_REC_DISK_MB} MiB，不中止）"
  echo "      推荐值留的是长期量：审计默认存 180 天、告警 90 天、攻击源 30 天、设备指标 72 小时，"
  echo "      再加 journald 与 /api/v1/upgrade/backup 产出的配置备份归档。"
  envck_warn=$((envck_warn + 1))
else
  echo "  ✓ 可用磁盘：${bd_dfpath} 所在分区剩 ${bd_avail_mb} MiB"
fi

# ④ DNS 解析自检。**永不中止**，两个理由都实打实：
#    a) 内网/离线部署本就没有公网 DNS，这类机器解析得了内部域名就够用，拿一个公网
#       域名解不出来当「环境不达标」是误杀；
#    b) 工具一个都没有时是「判不了」，不是「不达标」。
# ★优先 getent：它走 nsswitch（/etc/hosts + DNS + …），与 control/gateway 里 Go 解析器
#   看到的口径最接近。dig/host 只问 DNS 服务器，会把「靠 /etc/hosts 解析」误判成失败。
bd_dns_tool=""
# ★这一步必须能自己停下来。目标机的 resolv.conf 指着一台不可达的 DNS 时，
# getent/host/nslookup 会按 timeout×attempts×nameservers 阻塞（默认可到几十秒），
# 而这里没有任何"正在探测"的回显——现场看到的就是部署卡死。dig 自带 +time/+tries，
# 其余三条套一层 timeout；没有 timeout 命令的机器就照旧（宁可慢，不要因为缺工具而中止）。
bd_to=""
if command -v timeout >/dev/null 2>&1; then bd_to="timeout 5"; fi

for t in getent host dig nslookup; do
  if command -v "$t" >/dev/null 2>&1; then bd_dns_tool="$t"; break; fi
done
if [ -z "$bd_dns_tool" ]; then
  echo "  ⚠ DNS 解析：机器上 getent/host/dig/nslookup 一个都没有——不可判定，不当作不达标"
  envck_warn=$((envck_warn + 1))
else
  bd_dns_ok=1
  case "$bd_dns_tool" in
    getent)   ${bd_to} getent hosts "$BD_DNS_PROBE_HOST" >/dev/null 2>&1 || bd_dns_ok=0 ;;
    host)     ${bd_to} host "$BD_DNS_PROBE_HOST" >/dev/null 2>&1 || bd_dns_ok=0 ;;
    # dig 解不出来照样退 0（"没有记录" 不是它的错误），所以判的是输出空不空。
    dig)      if [ -z "$(dig +short +time=3 +tries=1 "$BD_DNS_PROBE_HOST" 2>/dev/null || echo '')" ]; then bd_dns_ok=0; fi ;;
    nslookup) ${bd_to} nslookup "$BD_DNS_PROBE_HOST" >/dev/null 2>&1 || bd_dns_ok=0 ;;
  esac
  if [ "$bd_dns_ok" = "1" ]; then
    echo "  ✓ DNS 解析：${bd_dns_tool} 解得出 ${BD_DNS_PROBE_HOST}"
  else
    echo "  ⚠ DNS 解析：${bd_dns_tool} 解不出 ${BD_DNS_PROBE_HOST}（不中止）"
    echo "      装机期：本机若还没装 nginx，下面那步 apt-get/yum 取包会失败（脚本会在那里明确报错）。"
    echo "      运行期：认证源（LDAP/OIDC）、消息通道（SMTP/webhook）、审计外送（syslog/HTTP）里"
    echo "      凡按域名填的目标都连不上，而这类错在页面上表现为「保存成功、就是不发/不通」。"
    echo "      → 内网部署本来就没有公网 DNS 的话，这条无视即可；换内部域名复检："
    echo "         BD_DNS_PROBE_HOST=<你的内部域名> bash install-remote.sh"
    envck_warn=$((envck_warn + 1))
  fi
fi

# ⑤ 时间同步。**永不中止**（判据本身就只是「有没有在跑」，不是「准不准」），
#    但后果必须说透：控制面按自己的钟签敲门令牌、网关按**它自己的钟**校验有效期，
#    两边漂过 90s（knockTTL，control/internal/api/api.go:36）之后，合法客户端的每一次
#    敲门都会以「令牌过期」被拒——SPA 是单包无回应、客户端看不到任何错误；控制面的
#    签发日志一切正常；网关那边只累积「验签失败」。三处都不指向时钟。
bd_ntp="unknown"; bd_ntp_svc=""
if command -v timedatectl >/dev/null 2>&1; then
  # 刻意不加 --value：那是 systemd 239+ 才有的参数，老机器上整条命令直接报错退出，
  # 于是「chrony 明明在跑」也会被判成不可判定。解析 KEY=VALUE 新旧都吃得下。
  case "$(timedatectl show -p NTPSynchronized 2>/dev/null || echo '')" in
    *=yes) bd_ntp="ok" ;;
    *=no)  bd_ntp="no" ;;
  esac
fi
if command -v systemctl >/dev/null 2>&1; then
  for u in chrony chronyd systemd-timesyncd ntp ntpsec openntpd; do
    if systemctl is-active --quiet "$u" 2>/dev/null; then bd_ntp_svc="$u"; break; fi
  done
fi
if [ "$bd_ntp" = "ok" ]; then
  echo "  ✓ 时间同步：内核已标记时钟已同步（守护进程：${bd_ntp_svc:-未识别}）"
elif [ "$bd_ntp" = "no" ] && [ -n "$bd_ntp_svc" ]; then
  # 有守护进程在跑、内核还没标记：刚开机 / 刚装上时是正常过渡态，不该吓唬人。
  echo "  ⚠ 时间同步：${bd_ntp_svc} 在跑，但内核尚未标记「已同步」（刚开机或刚装上属正常，几分钟后复查）"
  envck_warn=$((envck_warn + 1))
elif [ -n "$bd_ntp_svc" ]; then
  # timedatectl 不支持 show 子命令（systemd < 239），只知道有进程在跑。
  # ★不能顺手写成「尚未同步」——那是编一个我们根本没读到的状态；
  #   同步与否在这台机上就是不可判定。
  echo "  ⚠ 时间同步：检测到 ${bd_ntp_svc} 在跑，但本机 timedatectl 不支持 show（systemd < 239），同步状态不可判定（不中止）"
  envck_warn=$((envck_warn + 1))
else
  echo "  ⚠ 时间同步：未发现 chrony / systemd-timesyncd / ntp 中任何一个在跑（不中止）"
  echo "      后果不在这台机上，在敲门链路：控制面与网关的钟漂过 90s（敲门令牌有效期）后，"
  echo "      合法敲门会被整片判成「令牌过期」——SPA 单包无回应、客户端无错误、控制面签发日志正常，"
  echo "      只有网关侧累积验签失败，三处都不指向时钟。管理台 /diag 的「控制面与网关时钟一致性」"
  echo "      就是为这个失败形态加的，装完记得去看一眼。"
  echo "      → 装一个：apt-get install -y chrony（或 systemctl enable --now systemd-timesyncd）"
  envck_warn=$((envck_warn + 1))
fi

# 结论。硬下限项才决定中止；警告项只报数，绝不影响退出码。
if [ "$envck_bad" -gt 0 ]; then
  if [ "$BD_FORCE" = "1" ]; then
    echo "  ⚠ 结论：不达标（${envck_bad} 项低于硬下限）——BD_FORCE=1，继续安装"
    echo "     出问题时先回看上面这几行，它们已经写明了会怎么坏。"
  else
    echo "✗ 结论：环境基线不达标，拒绝安装（${envck_bad} 项低于硬下限，另有 ${envck_warn} 项警告）"
    echo "  ${BD_PREFIX} 下一个字节都没动，扩容后原样重跑即可。"
    echo "  （若经 deploy.sh 部署：/tmp/baidi-deploy 里还有约 130 MiB 暂存副本，可 rm -rf 回收）"
    echo "  → 确知无碍要强行装，把 BD_FORCE=1 加在**远端这条命令**上："
    echo "     sudo BD_FORCE=1 BD_PREFIX=${BD_PREFIX} … bash install-remote.sh"
    echo "  ★deploy.sh 只显式转发固定那几个变量，不含 BD_FORCE——写进 config.env 到不了这里。"
    echo "  → 也可单项放宽（同样必须给在远端命令上）：BD_MIN_MEM_MB=… / BD_MIN_DISK_MB=…"
    exit 1
  fi
elif [ "$envck_warn" -gt 0 ]; then
  echo "  ✓ 结论：达标（另有 ${envck_warn} 项警告，不影响安装；每条上面都写了后果）"
else
  echo "  ✓ 结论：达标"
fi

# 用户与目录
id -u "$BD_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$BD_USER"
mkdir -p "$BD_PREFIX"/{bin,web,data,etc/tls}

# 二进制 + 前端
install -m 0755 "$HERE/bin/baidi-control" "$BD_PREFIX/bin/baidi-control"
# 温备节点与切换脚本（PRD 15.5）：**主机上也装**。
# 备机侧显然要用；主机侧装它的理由是——这台机器将来也可能是"被提升的那台"，
# 而灾难当天没人有心情先去打包一个二进制。两者都不起任何服务，装着不占资源。
# ★用 if 而不是 `[ ] && install`：后者在条件为假时整条语句返回 1，set -e 下会让
# 安装脚本在这里静默中止（同本文件末尾那条注释里踩过的坑）。
if [ -f "$HERE/bin/baidi-standby" ]; then
  install -m 0755 "$HERE/bin/baidi-standby" "$BD_PREFIX/bin/baidi-standby"
fi
if [ -f "$HERE/promote-standby.sh" ]; then
  install -m 0755 "$HERE/promote-standby.sh" "$BD_PREFIX/bin/promote-standby.sh"
fi
rm -rf "$BD_PREFIX/web"; mkdir -p "$BD_PREFIX/web"
cp -R "$HERE/web/." "$BD_PREFIX/web/"

# 客户端安装包（先落新目录再瞬时切换，重部署期间进行中的下载不中断于拷贝窗口）
if [ -d "$HERE/downloads" ]; then
  rm -rf "$BD_PREFIX/downloads.new"
  mkdir -p "$BD_PREFIX/downloads.new"
  cp -R "$HERE/downloads/." "$BD_PREFIX/downloads.new/"
  chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX/downloads.new"
  rm -rf "$BD_PREFIX/downloads"
  mv "$BD_PREFIX/downloads.new" "$BD_PREFIX/downloads"
fi

# 身份密钥材料目录（control 私钥与内部 CA；网关拿不到这里的任何东西）
mkdir -p "$BD_PREFIX/etc/keys" "$BD_PREFIX/etc/pki"
chmod 0700 "$BD_PREFIX/etc/keys" "$BD_PREFIX/etc/pki"

# control 专属 env（0600）。注意：令牌已全部由 Ed25519 私钥签发，
# BAIDI_JWT_SECRET 只在 BAIDI_ACCEPT_HS256=1 的过渡逃生舱下才有意义，
# 这里仍生成一个随机值以备回滚，但默认不参与任何鉴权。
if [ ! -f "$BD_PREFIX/etc/baidi.env" ]; then
  echo "BAIDI_JWT_SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '=+/')" > "$BD_PREFIX/etc/baidi.env"
  chmod 0600 "$BD_PREFIX/etc/baidi.env"
  echo "==> 已生成 control 专属 env（HS256 逃生舱备用密钥）→ $BD_PREFIX/etc/baidi.env"
fi

# IPSec 站点 PSK 的主密钥**文件路径**（control 用它 AES-256-GCM 加密 PSK 落库）。
# 与 WITH_IPSEC 无关：只要管理员在控制台上给站点设了 PSK，control 就会用到它，
# 哪怕这台机不跑 baidi-ipsec。
# ★不钉这一项的话默认值是相对路径 ipsec-psk.key，会落在 WorkingDirectory（${BD_PREFIX}）根下，
#   与 etc/keys 里其它私钥不在一处。备份清单漏掉它的后果是：库还原了、所有 PSK 解不开，
#   而报错是「authentication failed」——看起来像两端 PSK 配错了，不像密钥丢了。
# 幂等追加：已有该项就一个字节都不动（重装时改路径 = 存量 PSK 全部解不开）。
if ! grep -q '^BAIDI_IPSEC_PSK_KEY=' "$BD_PREFIX/etc/baidi.env" 2>/dev/null; then
  echo "BAIDI_IPSEC_PSK_KEY=$BD_PREFIX/etc/keys/ipsec-psk.key" >> "$BD_PREFIX/etc/baidi.env"
  chmod 0600 "$BD_PREFIX/etc/baidi.env"
  echo "==> 已登记 IPSec PSK 主密钥路径 → $BD_PREFIX/etc/keys/ipsec-psk.key（首次用到时由 control 自动生成 0600）"
fi

# 首登强制改密：**默认开**（wave8 行动 16）。control 首次建库会把种子账号（含 admin）
# 全部置「首登须改密」。仅首启建库生效——库已存在时写入无副作用；幂等追加。
#
# ★缺省值与 deploy.sh 一致（1）。直接 ssh 跑本脚本、没经 deploy.sh 转发时也是开的：
# 两处缺省不一致的话，「按 README 手工装」与「按 deploy.sh 装」会得到两种安全姿态，
# 而两者在机器上完全同形。
if [ "${BAIDI_SEED_MUST_CHANGE:-1}" = "1" ] && ! grep -q '^BAIDI_SEED_MUST_CHANGE=' "$BD_PREFIX/etc/baidi.env" 2>/dev/null; then
  echo "BAIDI_SEED_MUST_CHANGE=1" >> "$BD_PREFIX/etc/baidi.env"
  chmod 0600 "$BD_PREFIX/etc/baidi.env"
  echo "==> 已开启首登强制改密（仅首次建库时对种子账号生效）"
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
  echo "==> 已生成自签 TLS 证书（SAN=${san}，私钥 0600）"
fi

chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX"

# 渲染 systemd 单元（先装单元，nginx 校验通过后再启动控制面，避免无入口空跑）
MTLS_PORT="${MTLS_PORT:-8092}"   # 网关接口的 mTLS 独立监听（回环）
# 以运行用户身份执行（runuser 属 util-linux，比 sudo 更可靠地存在于精简镜像）
as_bd() { if command -v runuser >/dev/null 2>&1; then runuser -u "$BD_USER" -- "$@"; else sudo -u "$BD_USER" "$@"; fi; }
GW_ID="${GW_ID:-gw-1}"           # 本机网关 id（= mTLS 客户端证书 CN）
# 站点组网网关（WITH_IPSEC=1 才用到）。CN 默认 ipsec-<接入网关 id>：
# 两个进程共用同一套 CA 与同一个 mTLS 端口，控制面靠 CN 前缀分权，故必须能一眼区分。
IPSEC_GW_ID="${IPSEC_GW_ID:-ipsec-$GW_ID}"
IKE_PORT="${IKE_PORT:-500}"      # IKE 监听（<1024，靠 CAP_NET_BIND_SERVICE 绑）
NATT_PORT="${NATT_PORT:-4500}"   # NAT-T / ESP-in-UDP 监听
render() { sed -e "s#@BD_PREFIX@#$BD_PREFIX#g" -e "s#@BD_USER@#$BD_USER#g" \
               -e "s#@CONTROL_PORT@#$CONTROL_PORT#g" -e "s#@PUBLIC_ORIGIN@#$PUBLIC_ORIGIN#g" \
               -e "s#@BD_HTTPS_PORT@#$BD_HTTPS_PORT#g" -e "s#@PUBLIC_HOST@#$PUBLIC_HOST#g" \
               -e "s#@MTLS_PORT@#$MTLS_PORT#g" -e "s#@GW_ID@#$GW_ID#g" \
               -e "s#@IPSEC_GW_ID@#$IPSEC_GW_ID#g" \
               -e "s#@IKE_PORT@#$IKE_PORT#g" -e "s#@NATT_PORT@#$NATT_PORT#g" "$1"; }
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
[ -f /etc/nginx/conf.d/baidi-proxy-api.inc ] && cp -a /etc/nginx/conf.d/baidi-proxy-api.inc /etc/nginx/conf.d/baidi-proxy-api.inc.bak
restore_nginx() { # 有旧备份则还原可用配置，仅首装无备份才删（绝不留半残文件毒化烛龙后续 reload）
  if [ -f /etc/nginx/conf.d/baidi.conf.bak ]; then mv -f /etc/nginx/conf.d/baidi.conf.bak /etc/nginx/conf.d/baidi.conf
  else rm -f /etc/nginx/conf.d/baidi.conf; fi
  if [ -f /etc/nginx/conf.d/baidi-proxy-api.inc.bak ]; then mv -f /etc/nginx/conf.d/baidi-proxy-api.inc.bak /etc/nginx/conf.d/baidi-proxy-api.inc
  else rm -f /etc/nginx/conf.d/baidi-proxy-api.inc; fi
}
# ★片段文件必须是 .inc 而不是 .conf：conf.d/*.conf 会被 nginx 直接 include 进 http{}，
# 而这份里全是 proxy_* 这类只能出现在 location 里的指令——落成 .conf 会让
# **整台机器的 nginx** 起不来（包括与我们共存的烛龙站点）。
render "$HERE/nginx/baidi-proxy-api.inc" > /etc/nginx/conf.d/baidi-proxy-api.inc
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

  # 网关身份材料：mTLS 客户端证书 + CA 公证书 + 敲门公钥。
  # 由 control 离线签发（同一套 PKI 与库，指纹登记进白名单以便随时吊销）。
  # ★网关只拿到 knock 公钥与自己的客户端证书——**没有任何签发能力**：
  #   会话签名私钥留在 etc/keys（0700），网关连它的公钥都拿不到。
  echo "==> 签发网关身份材料（mTLS 客户端证书 + 敲门公钥）"
  as_bd env \
    BAIDI_DB="$BD_PREFIX/data/baidi.db" \
    BAIDI_JWT_KEY="$BD_PREFIX/etc/keys/jwt-ed25519.pem" \
    BAIDI_JWT_KNOCK_KEY="$BD_PREFIX/etc/keys/jwt-ed25519-knock.pem" \
    BAIDI_JWT_WEB_KEY="$BD_PREFIX/etc/keys/jwt-ed25519-web.pem" \
    BAIDI_PKI_DIR="$BD_PREFIX/etc/pki" \
    "$BD_PREFIX/bin/baidi-control" -issue-gateway-cert "$GW_ID" -out "$BD_PREFIX/etc/gwcerts" \
    || { echo "  ✗ 网关身份材料签发失败"; exit 1; }

  # 网关专属 env：只含公钥与自己的证书路径，与 control 的 baidi.env 彻底分开
  cat > "$BD_PREFIX/etc/baidi-gateway.env" <<GWENV
# 白帝网关专属配置——只有验证材料，没有任何签发能力。
# 令牌验证：只装 control 的**敲门**公钥；会话令牌用另一把密钥签，其 kid 在此查不到。
BAIDI_GW_JWT_PUBKEY=$BD_PREFIX/etc/gwcerts/knock.pub
# 七层 Web 代理（B/S 免客户端）的票据公钥。★监听默认**不开**：
# 该端口必须对浏览器可达，不受 SPA 隐身保护，是一个真实的入站攻击面。
# 要开就取消下面 BAIDI_GW_WEB 的注释，并**务必**在它前面放一层 HTTPS
# （会话 Cookie 恒带 Secure，纯 HTTP 暴露时浏览器根本不会保存它）。
BAIDI_GW_WEB_JWT_PUBKEY=$BD_PREFIX/etc/gwcerts/web.pub
#BAIDI_GW_WEB=127.0.0.1:18444
# ★开了 BAIDI_GW_WEB 就**必须**同时填这一行：前置 nginx 的地址（逗号分隔可多段）。
# 只有来自这些网段的请求，其 X-Forwarded-For / -Proto / -Host 才被采信。
# 不填的后果全是静默的：后端看到的客户端 IP 恒为 nginx 自己（按 IP 的风控、限速、
# 审计定位全部失效，而不少内网应用还把 127.0.0.1 当免认证的本机来源），
# 且 X-Forwarded-Proto 恒为 http —— 后端一旦开了 HTTPS 强制跳转，
# 就会与网关的 Location 改写咬成无限重定向，而每一跳在两侧日志里都正常。
#BAIDI_GW_WEB_TRUSTED_PROXIES=127.0.0.1
# 对外主机名（如 oa.example.com:9443）。不填时网关**不下发** X-Forwarded-Host——
# Host 头是客户端可控的，把它当真实值转发就是 Host header injection
# （后端据它拼出的找回密码链接会指向攻击者的域名）。
#BAIDI_GW_WEB_EXTERNAL_HOST=
# 机器身份：mTLS 客户端证书（CN=${GW_ID}），控制面据此认人并可即刻吊销
BAIDI_GW_MTLS_CERT=$BD_PREFIX/etc/gwcerts/gw.crt.pem
BAIDI_GW_MTLS_KEY=$BD_PREFIX/etc/gwcerts/gw.key.pem
BAIDI_GW_MTLS_CA=$BD_PREFIX/etc/gwcerts/ca.crt.pem
GWENV
  chmod 0640 "$BD_PREFIX/etc/baidi-gateway.env"
  chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX/etc/gmcerts" "$BD_PREFIX/etc/gwcerts" \
    "$BD_PREFIX/etc/baidi-gateway.env" "$BD_PREFIX/bin"
  render "$HERE/systemd/baidi-gateway.service" > /etc/systemd/system/baidi-gateway.service
  systemctl daemon-reload
  systemctl enable --now baidi-gateway
  systemctl restart baidi-gateway
  sleep 1
  systemctl is-active --quiet baidi-gateway && echo "  ✓ baidi-gateway 已起：SPA :18201/udp + 国密 TLCP 代理 :18443/tcp（mTLS 身份 CN=${GW_ID}，经 :${MTLS_PORT} 拉策略，后端=control:${CONTROL_PORT}）" \
    || { echo "  ✗ baidi-gateway 启动失败，看日志："; journalctl -u baidi-gateway --no-pager -n 12; }
fi

# 可选：站点组网网关（自研 IKEv2/ESP，站点↔站点东西向）
# ★默认关（WITH_IPSEC=0）：很多部署只要远程接入、不要站点组网，不该被迫背上一个
#   需要 CAP_NET_BIND_SERVICE + CAP_NET_ADMIN 的组件。开不开是部署者的决定。
if [ "${WITH_IPSEC:-0}" = "1" ]; then
  echo "==> 安装站点组网网关 baidi-ipsec（IKE :${IKE_PORT}/udp + NAT-T :${NATT_PORT}/udp）"

  # ① CN 前缀闸：装机期就拦，不留到运行时才 403。
  # 控制面按 ipsec- 前缀分权（见 control/internal/api/mtls.go 的 ipsecCNOnly）：
  # 前缀不对时，站点清单/PSK/状态回报三个接口全部 403，而进程本身能正常启动——
  # 表现为「服务是 active 的，站点却永远 down」，最容易被当成协议问题查半天。
  case "$IPSEC_GW_ID" in
    ipsec-*) ;;
    *) echo "✗ IPSEC_GW_ID=$IPSEC_GW_ID 不以 ipsec- 开头，拒绝安装。"
       echo "  控制面按证书 CN 前缀分权：ipsec-* 才能调 /api/v1/gateways/ipsec*。"
       echo "  → 改成前缀形态，例如 IPSEC_GW_ID=ipsec-${GW_ID}"
       echo "    （最常见的写法错误是 ${GW_ID}-ipsec —— 后缀不算，前缀才算）"
       exit 1 ;;
  esac

  # ② 端口预检：检出即中止（照抄本脚本 nginx 段与 build.sh default_server 自检的姿态）。
  # ★这台机可能跑着 strongSwan（baidi-gateway.service 的注释里已提示过）。抢 500/4500 的
  #   症状极难查：先绑上的进程收走全部报文，后来者要么起不来，要么一个 IKE 包都收不到——
  #   控制台上站点永远 down 且没有任何协商记录，看起来像「对端没配」。
  # ★不自作主张换端口继续装：端口一改，对端配置和云安全组规则都得跟着改，那是人的决定。
  # 过滤掉 baidi-ipsec 自己：重装场景下旧实例还绑着端口，那不是冲突（下面会 restart）。
  if command -v ss >/dev/null 2>&1; then
    for p in "$IKE_PORT" "$NATT_PORT"; do
      occ="$(ss -lunpH "sport = :$p" 2>/dev/null | grep -v 'baidi-ipsec' || true)"
      if [ -n "$occ" ]; then
        echo "✗ UDP $p 已被其它进程占用，拒绝安装站点组网网关："
        echo "$occ" | sed 's/^/    /'
        echo "  → 若是 strongSwan：先 systemctl stop strongswan（或 ipsec stop）再重装；"
        echo "  → 确需共存就换高位端口重装，例如："
        echo "     IKE_PORT=15500 NATT_PORT=15501 WITH_IPSEC=1 bash install-remote.sh"
        echo "     ★换端口后对端站点配置与云安全组规则必须同步改，否则隧道永远建不起来"
        exit 1
      fi
    done
  else
    echo "  ⚠ 未找到 ss，跳过 ${IKE_PORT}/${NATT_PORT} 占用预检——若该机跑着 strongSwan，两者会互相抢包"
  fi

  install -m 0755 "$HERE/bin/baidi-ipsec" "$BD_PREFIX/bin/baidi-ipsec"

  # ③ 组网网关自己的身份材料，**独立目录 etc/ipseccerts，绝不与 etc/gwcerts 共用**。
  # 离线签发写的是固定文件名（gw.crt.pem/gw.key.pem/…），共用目录 = 后签的那张
  # 直接覆盖前一张：两个进程会拿着同一个 CN 的证书互相顶，控制面按 CN 分权后
  # 一定有一方全程 403。这一条是纯粹的踩坑预防，别为了少个目录合并。
  echo "==> 签发站点组网网关身份材料（mTLS 客户端证书 CN=${IPSEC_GW_ID}）"
  as_bd env \
    BAIDI_DB="$BD_PREFIX/data/baidi.db" \
    BAIDI_JWT_KEY="$BD_PREFIX/etc/keys/jwt-ed25519.pem" \
    BAIDI_JWT_KNOCK_KEY="$BD_PREFIX/etc/keys/jwt-ed25519-knock.pem" \
    BAIDI_JWT_WEB_KEY="$BD_PREFIX/etc/keys/jwt-ed25519-web.pem" \
    BAIDI_PKI_DIR="$BD_PREFIX/etc/pki" \
    "$BD_PREFIX/bin/baidi-control" -issue-gateway-cert "$IPSEC_GW_ID" -out "$BD_PREFIX/etc/ipseccerts" \
    || { echo "  ✗ 站点组网网关身份材料签发失败"; exit 1; }
  # 顺手删掉敲门公钥：组网网关不验任何令牌（它的接口全靠 mTLS CN 认身份），
  # 留着只会让下一个人以为它参与敲门链路。
  rm -f "$BD_PREFIX/etc/ipseccerts/knock.pub" "$BD_PREFIX/etc/ipseccerts/web.pub"

  # ④ 组网专属 env：只有身份材料路径，**没有任何密钥原文**。
  # PSK 不落盘也不进 env——进程运行时经 mTLS 按版本单取，只在内存里。
  cat > "$BD_PREFIX/etc/baidi-ipsec.env" <<IPSECENV
# 白帝站点组网网关专属配置——只有 mTLS 身份材料的路径。
# ★这里不会出现 PSK：站点 PSK 由进程运行时经 mTLS 单取
#   （GET /api/v1/gateways/ipsec/{id}/psk），只存在于内存，不落盘、不进 env、不写日志。
# 单元文件里以显式 flag 传了同一组值（flag 优先）；这份文件是给运维看「本机组网身份在哪」。
BAIDI_IPSEC_ID=$IPSEC_GW_ID
BAIDI_IPSEC_CONTROL=https://127.0.0.1:$MTLS_PORT
BAIDI_IPSEC_MTLS_CERT=$BD_PREFIX/etc/ipseccerts/gw.crt.pem
BAIDI_IPSEC_MTLS_KEY=$BD_PREFIX/etc/ipseccerts/gw.key.pem
BAIDI_IPSEC_MTLS_CA=$BD_PREFIX/etc/ipseccerts/ca.crt.pem
IPSECENV
  chmod 0640 "$BD_PREFIX/etc/baidi-ipsec.env"
  chown -R "$BD_USER":"$BD_USER" "$BD_PREFIX/etc/ipseccerts" "$BD_PREFIX/etc/baidi-ipsec.env" "$BD_PREFIX/bin"

  render "$HERE/systemd/baidi-ipsec.service" > /etc/systemd/system/baidi-ipsec.service
  systemctl daemon-reload
  systemctl enable --now baidi-ipsec
  systemctl restart baidi-ipsec
  sleep 1
  if systemctl is-active --quiet baidi-ipsec; then
    echo "  ✓ baidi-ipsec 已起：IKE :${IKE_PORT}/udp + NAT-T :${NATT_PORT}/udp（mTLS 身份 CN=${IPSEC_GW_ID}，经 :${MTLS_PORT} 拉站点配置）"
    echo "  ★控制台上建站点时，「所属网关」必须逐字符填 $IPSEC_GW_ID"
    echo "    控制面按 gateway_id == 证书 CN 精确过滤下发；填错拉到的是**空站点列表而不是错误**，"
    echo "    站点会安静地永远 down、日志里一条协商记录都没有。"
    echo "  ★还需在云安全组放行 UDP ${IKE_PORT} 和 UDP ${NATT_PORT}（两个都要，只放前者会卡在协商中途）"
  else
    echo "  ✗ baidi-ipsec 启动失败，看日志："; journalctl -u baidi-ipsec --no-pager -n 12
    echo "    若是 \"permission denied\" 绑 ${IKE_PORT}：检查单元里的 AmbientCapabilities/NoNewPrivileges=false 是否被改过"
  fi
fi

echo "✓ 安装完成。控制台: https://${PUBLIC_HOST}:${BD_HTTPS_PORT}/  ·  门户: /portal/login"
echo "  需在腾讯云安全组放行 TCP ${BD_HTTPS_PORT}（如要公网客户端，再放 gateway 18443/tcp + 18201/udp）"
# 用 if 而不是 `[ ] && echo`：后者在条件为假时整条语句返回 1，set -e 下会把
# 「没开组网」变成一次部署失败。
if [ "${WITH_IPSEC:-0}" = "1" ]; then
  echo "  站点组网还需放行 UDP ${IKE_PORT} + UDP ${NATT_PORT}（IKE 与 NAT-T，缺一不可）"
fi
# ★内核态隐身（NFR-SEC-01）当面交代：不装就不装，但不能让人以为装了。
# 未开 -pf 时未敲门的 TCP 连接会先完成三次握手再被用户态断开（proxy.go 的
# accept-then-close），nmap 判 open——与「端口在网络层不存在」是两种安全等级。
# 网关页与 /diag 现在会逐台如实标出这一点，这里同步说一遍，免得部署完就忘。
if [ "${WITH_GATEWAY:-0}" = "1" ]; then
  echo ""
  echo "  ⚠ 内核态隐身（SPA 真隐身）**未启用**：本脚本不装 nftables 规则集，网关也不带 -pf。"
  echo "    现状：未敲门的 TCP 连接会先完成三次握手再被立即断开，端口对扫描器表现为 open 而非 filtered。"
  echo "    业务仍然接入不了（无 SPA 授权即断连），但网关本身并未隐身。"
  echo "    不默认启用的原因：该机 strongSwan-gm 也用 nft，两套 ruleset 需先评审避免互相覆盖。"
  echo "    要启用： sudo PROXY_PORT=18443 SPA_PORT=18201 gateway/firewall/baidi-nft.sh setup"
  echo "             然后给 baidi-gateway.service 的启动参数加 -pf 并以 root 运行（重启后规则集需重新装）。"
  echo "    生效与否可在「网关与隐身」页逐台核对（回执来自网关实测，不是配置回显）。"
fi
# 首登口令姿态：**关掉时必须醒目告警**（wave8 行动 16）。
# ★这条告警的意义在于「关掉」是一次有意识的取舍——种子口令 baidi@123 是公开的
# （README / CLAUDE.md / 演示站说明里都有）。不喊出来的话，一台按 config.env 装出来的
# 生产机开局就带着一个人人都知道的口令，而部署输出里一个字都没提。
if [ "${BAIDI_SEED_MUST_CHANGE:-1}" = "1" ]; then
  echo "  ✓ 首登强制改密：已开启（种子账号首次登录必须改掉公开口令 baidi@123 才能拿到会话）"
else
  echo ""
  echo "  ⚠ 首登强制改密**已被显式关闭**（config.env 里 BAIDI_SEED_MUST_CHANGE=0）"
  echo "    本机的种子账号（含 admin）现在可以用公开口令 baidi@123 直接登录，"
  echo "    而那个口令写在本项目的 README、CLAUDE.md 与在线演示站说明里。"
  echo "    这只适合演示机。生产请删掉 config.env 里那一行（默认即为开启）后**重建数据库**，"
  echo "    或立刻用管理员改掉全部种子账号的口令——该开关只在首次建库时生效。"
  echo ""
fi
echo "  管理员演示账号 admin / baidi@123（生产请改后端登录逻辑或接 IdP）"
echo "  回滚：systemctl disable --now baidi-control; rm /etc/nginx/conf.d/baidi.conf /etc/nginx/conf.d/baidi-proxy-api.inc /etc/systemd/system/baidi-control.service; nginx -t && systemctl reload nginx"
systemctl --no-pager status baidi-control | head -5 || true
