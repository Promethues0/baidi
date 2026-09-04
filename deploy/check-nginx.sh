#!/usr/bin/env bash
# 交付 nginx 站点配置的自检：限流指令 / 存活探测通路 / 烛龙共存契约 / 片段文件命名。
#
# 用法：deploy/check-nginx.sh [nginx 目录]
#   缺省查仓库里那份模板 deploy/nginx/；deploy/build.sh 传的是 _out/nginx（交付件本身）。
#   两个都要能查：模板改坏了要在 CI 上当场红，而交付件是「装到机器上的那一份」，
#   中间隔着一次 cp，历史上出过「旧模板混进产物」这种事。
#
# ══ 为什么这批检查要从 build.sh 里抽出来单独成文件 ══
#
# 抽出来之前它们只有一个触发方式：有人手工跑 `deploy/build.sh`。而 build.sh 会先
# `npm ci && npm run build` 再交叉编译五个 Go 二进制——几分钟起步，改一行 nginx 配置
# 没人会为了跑这几条 grep 去跑一遍全量构建。`.github/workflows/server.yml` 的 paths
# 虽然含 `deploy/**`，但它的四个 job（actionlint / go test / console / gateway e2e）
# **没有一个读 deploy/nginx/ 或执行 build.sh**——改 nginx 配置时 CI 只是空转一遍全绿。
# 也就是说这批「构建期执行方」在真实工作流里几乎不执行。现在 server.yml 直接跑本文件。
#
# ══ 判据必须分「定义」与「引用」两组 ══
#
# 改造前 build.sh 里是一句循环，逐条纯子串匹配这五个字面量：
#   limit_req_zone / limit_conn_zone / zone=baidi_login / zone=baidi_api / limit_conn baidi_dl
# 而 baidi.conf 顶部那三行 zone **定义**是这样写的：
#   limit_req_zone  $binary_remote_addr zone=baidi_login:10m rate=20r/m;
#   limit_req_zone  $binary_remote_addr zone=baidi_api:10m   rate=30r/s;
#   limit_conn_zone $binary_remote_addr zone=baidi_dl:10m;
# 前四个字面量**在这三行里全部出现**——`zone=baidi_login` 是 `zone=baidi_login:10m` 的子串，
# `limit_req_zone` 更是定义指令本身。于是那四条检查实际上只在检查「zone 定义还在不在」，
# 一条都没碰过**应用点**（`limit_req zone=…` / `limit_conn baidi_dl 4`）。
# 实测（2026-09-04）：`sed -E '/limit_req[[:space:]]+zone=/d'` 删掉全部 5 个 limit_req
# 应用点（grep -c 5→0），逐字复跑那段循环 —— **五条全绿**。
# 真正检到应用点的只有 `limit_conn baidi_dl` 一条，纯属巧合：定义行写的是
# `limit_conn_zone … zone=baidi_dl`，与它字面不同，才没被定义行顶包。
#
# 而 wave8 的落地记里写着「实测抽掉 `limit_conn baidi_dl` 即中止」——当年的变异测试
# **只跑了那唯一正确的一条**。五条判据里四条假绿，被一次抽样掩了一年。
#
# ★这是**潜伏**缺陷不是当前生效的缺陷：HEAD 上六个应用点一个不少，今天交付的机器
#   限流是真的。坏的是守卫，不是配置——它骗的是后来改这份配置的维护者，
#   不是管理员（控制台根本不呈现限流状态）。
#
# ★所以本文件把两组分开各查一次：
#   ① 定义组 —— 锚在行首的 `limit_req_zone` / `limit_conn_zone` 指令上，且要求 `zone=名:`
#      带冒号（`zone=baidi_login:10m` 里的尺寸段），引用点写不出这个形状。
#   ② 应用组 —— `limit_req` 后面必须是**空白**再接 `zone=`（词边界）。这一条就把
#      `limit_req_zone` 排除干净了：那里 `limit_req` 后面跟的是 `_`。
#      并且逐条**限定在它该出现的那个 location 花括号块内**扫（照 /healthz 那道的写法）：
#      全文范围找 `limit_req zone=baidi_login` 的话，把它从三条登录端点里挪到
#      `location /` 上也照样绿，而那时登录端点一点限速都没有。
#
# ★zone 定义被删掉、而应用点还在时，nginx 自己会在 `nginx -t` 报
#   "unknown limit_req_zone" 并拒绝加载（install-remote.sh 会 reload 前 -t）。
#   所以定义组这几条是「早一步、说人话」，不是唯一防线；应用组才是没有别的东西兜的那半。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="${1:-$HERE/nginx}"
CONF="$DIR/baidi.conf"

[ -f "$CONF" ] || { echo "✗ 找不到 ${CONF}"; exit 1; }

fail=0
bad() { echo "✗ $*"; fail=1; }

# 剥注释后再判：本文件上面这一大段说明文字里就出现了 limit_req、default_server 等字样，
# 不剥的话说明性注释会替配置自证（baidi.conf 自己的注释同理）。
#
# ★顺带把制表符换成空格，好让下面所有正则只用普通空格、不出现 POSIX 字符类：
#   这批检查现在要在 CI 的 ubuntu runner 上跑，那里的 `awk` 是 **mawk**，而
#   POSIX 字符类在老 mawk（1.3.3）的动态正则里是不支持的——一旦不支持，
#   `$0 ~ loc` 恒不匹配，于是**每一条 location 检查都会红**……或者更糟，
#   如果哪天判据写成了反向匹配，就会变成每条都绿。本仓库反复栽在
#   「本机怎么跑都对、只在别的机器上错」这一类上（bash 3.2 吞全角字符、
#   PowerShell 按 ANSI 读 .ps1…），没有理由在这里赌一个发行版的 awk 版本。
strip() { sed 's/#.*//' "$CONF" | tr '\t' ' '; }

# 在某个 location 花括号块**内部**查一条指令。
# ★为什么必须限定在块内：先前 /healthz 那道写成「命中 location 后一路往下找 proxy_pass」，
#   它会越过块边界撞上下面 `location /api/` 里的那一行，把「/healthz 只剩个空壳子」判成通过。
#   一道检查不出错误的检查比没有检查更坏——它带着「已验证」的措辞。
block_has() {
  strip | awk -v loc="$1" -v want="$2" '
    $0 ~ loc        { f = 1; next }
    f && /^ *}/     { f = 0 }
    f && $0 ~ want  { hit = 1 }
    END { exit !hit }'
}

echo "==> 自检 nginx 站点配置：${CONF}"

# ── ① 烛龙共存契约：交付站点绝不得含 default_server ─────────────────────────
# 防旧模板混入毒化烛龙后续 reload（该机已有烛龙独占 80/443 的 default_server）。
if strip | grep -q 'default_server'; then
  bad "含 default_server 指令（绝不抢占烛龙 80/443）"
fi

# ── ② 限流区定义（http 级）─────────────────────────────────────────────────
# 形状锚在指令名 + `zone=名:`（带冒号的尺寸段）上，引用点写不出这个形状。
while IFS='|' read -r re why; do
  [ -n "$re" ] || continue
  strip | grep -Eq "$re" || bad "缺少限流区定义：${why}"
done <<'EOF'
^ *limit_req_zone .* zone=baidi_login:|limit_req_zone … zone=baidi_login:（登录端点速率区）
^ *limit_req_zone .* zone=baidi_api:|limit_req_zone … zone=baidi_api:（已认证 API 速率区）
^ *limit_conn_zone .* zone=baidi_dl:|limit_conn_zone … zone=baidi_dl:（下载并发区）
EOF

# ── ③ 限流应用点：逐 location 块内查 ────────────────────────────────────────
#
# 这一组才是「限流到底生不生效」的判据。六个应用点分别对应 CLAUDE.md 里写明的
# 三块真实覆盖面：登录面（管理员关掉 lockout 的 IP 维度之后剩下的那道）、
# 已认证 API 零配额、以及价值最高、**没有任何应用层替代闸**的免认证大文件下载并发闸。
#
# `limit_req +zone=` 里那个空白是词边界，把定义指令 `limit_req_zone` 排除在外
# （那里 `limit_req` 后面跟的是下划线）。zone 名后面跟 `[^A-Za-z0-9_]` 同理，
# 免得 `baidi_api` 顺手匹配到某个叫 `baidi_api2` 的区。
while IFS='|' read -r loc want why; do
  [ -n "$loc" ] || continue
  block_has "$loc" "$want" || bad "${why}"
done <<'EOF'
^ *location *= */api/v1/auth/login |limit_req +zone=baidi_login[^A-Za-z0-9_]|管理台登录端点 /api/v1/auth/login 块内没有 limit_req zone=baidi_login
^ *location *= */api/v1/portal/login |limit_req +zone=baidi_login[^A-Za-z0-9_]|门户登录端点 /api/v1/portal/login 块内没有 limit_req zone=baidi_login
^ *location *= */api/v1/auth/totp |limit_req +zone=baidi_login[^A-Za-z0-9_]|二次认证端点 /api/v1/auth/totp 块内没有 limit_req zone=baidi_login
^ *location +/api/ |limit_req +zone=baidi_api[^A-Za-z0-9_]|管理 API /api/ 块内没有 limit_req zone=baidi_api（已认证 API 会退回零配额）
^ *location *= */healthz |limit_req +zone=baidi_api[^A-Za-z0-9_]|存活探测 /healthz 块内没有 limit_req zone=baidi_api（它是免认证入口，不挂就是零配额）
^ *location +/downloads/ |limit_conn +baidi_dl[^A-Za-z0-9_]|下载出口 /downloads/ 块内没有 limit_conn baidi_dl（免认证大文件直发，并发是唯一的闸）
EOF

# ── ④ 存活探测通路：必须存在、必须精确匹配、必须真反代 ──────────────────────
#
# ★没有它，`location = /healthz` 是一行谁删了都不会有人发现的配置——删掉之后 /healthz
#   静静地落回 `location /` 的 SPA 回退，恒回 200 HTML，客户端的「控制中心可达」
#   变成一个**永远为真**的指示灯（2026-09-03 抓到的正是这个形态）。
# ★一并钉住 `=`：写成前缀匹配 `location /healthz` 语义就变了（/healthzXXX 也命中），
#   而且 SPA 那条也是前缀匹配，两条前缀规则的优先级不是一眼能看出来的东西。
#   上面 ③ 里那条 /healthz 限流检查用的是同一个带 `=` 的 location 正则，
#   所以「location 被改成前缀匹配」这两处会一起红，不会只剩一处。
# ★proxy_pass 必须在**同一个块内**：只有 location 壳子时 nginx 会去 root 下找静态文件
#   → 恒 404，与「控制面挂了」依旧分不开，只是把假阳性换成了假阴性。
block_has '^ *location *= */healthz ' 'proxy_pass' \
  || bad "缺少精确匹配的 /healthz 反代通路（或该块内没有 proxy_pass）——客户端「控制中心可达」会变成永真指示灯"

# ── ⑤ proxy 公共片段：必须随包发，且不能叫 .conf ────────────────────────────
# conf.d/*.conf 会被 include 进 http{}，而这份片段全是只能出现在 location 里的
# proxy_* 指令 → 整台机器的 nginx 起不来（含共存的烛龙）。
[ -f "$DIR/baidi-proxy-api.inc" ] || bad "缺少 nginx/baidi-proxy-api.inc"
if ls "$DIR/"*.inc.conf >/dev/null 2>&1; then
  bad "nginx 片段不得以 .conf 结尾（会被 include 进 http{} 而炸掉整台机器的 nginx）"
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ nginx 站点配置自检未通过（见上）"
  exit 1
fi
echo "✓ nginx 站点配置自检通过：限流区 3 条定义 + 6 个应用点、/healthz 精确匹配且真反代、片段命名合规"
