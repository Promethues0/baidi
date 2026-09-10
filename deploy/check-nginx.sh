#!/usr/bin/env bash
# 交付 nginx 站点配置的自检：限流指令 / 安全响应头 / 存活探测通路 / 烛龙共存契约 / 片段文件命名。
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

# 只取**终结 TLS 的那个 server 块**的块内内容（判据：块里有 ssl_certificate）。
#
# ★为什么要单独有这么一个视图：install-remote.sh 在非 443 部署上会
#   `sed '/@BD_HTTP80_BEGIN@/,/@BD_HTTP80_END@/d'` 把 80 那段**整个删掉**。安全响应头若被
#   挪进那一段，共存机（9443，最常见的形态）上就一条都不剩，而 443 独占机上一切正常——
#   两台机器行为相反且都不报错。所以这几条头必须断言在这个视图里出现，全文范围找会漏掉它。
#
# ★判据刻意**不用 @BD_HTTP80_BEGIN@ 那对标记截断**，虽然那样写更短：baidi.conf 的注释里
#   会（也应该）提到这对标记名，而注释里那一次出现会让「截断点」提前到文件中段——
#   于是本节四条检查全部误报"头不见了"。第一版就是这么写的，当场被自己的检查抓出来。
#   现在按结构判：块起于 `^ *server *{`、止于**顶格** `}`（location 的收尾都是缩进的），
#   保留其中含 ssl_certificate 的那一个。80 端口块没有证书指令，天然被排除。
# ★先剥注释再分块：不剥的话注释里的 `server {` 会把分块整个带偏。
https_part() {
  strip | awk '
    /^ *server *\{/ { inblk = 1; n = 0; want = 0; next }
    inblk && /^\}/  { if (want) { for (i = 1; i <= n; i++) print buf[i] } inblk = 0; next }
    inblk           { buf[++n] = $0; if ($0 ~ /ssl_certificate/) { want = 1 } }
  '
}

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

# ── ④ 安全响应头（NFR-SEC-08）：必须在位、必须带 always、必须在 server 级 ──────
#
# ★守的是什么：改造前这个站点一条安全响应头都没有，管理台与门户同源共用它，
#   任何外部页面都能整页 iframe 进去做点击劫持。补上之后，这几条**同样是一删就静默失效**
#   的配置——nginx -t 不会说话，页面一切正常，只有响应头空了。
#
# ★三组判据分别对应三种真实的改坏方式，缺一种就漏一种：
#   ① 头本身没了 / 不带 always（后者只让 200/30x 带头，403/404/5xx 裸奔，
#      而那些恰恰是最容易被稳定拿到、也照样能被 iframe 的响应）；
#   ② 被挪进 80 端口块（共存机上会被 install-remote.sh 整段删掉，见 https_part 的注释）；
#   ③ 某个 location 里出现了 add_header —— nginx 的 add_header 是**就近整组覆盖**不是叠加，
#      那一条 location 会把 server 级这四条全部丢掉。这一条是本节里最容易踩、
#      也最不可能被人肉发现的：加头的人只看见自己那条生效了。
while IFS='|' read -r name why; do
  [ -n "$name" ] || continue
  https_part | grep -Eq "^ *add_header +$name .* always;" || bad "HTTPS server 块内缺少安全响应头 ${name}（或没带 always）：${why}"
done <<'EOF'
X-Frame-Options|管理台/门户同源，缺了就能被整页 iframe 做点击劫持；always 是为了让 403/404/5xx 也带上
X-Content-Type-Options|缺了浏览器会对 /downloads/ 的安装包与 API 响应做内容嗅探
Referrer-Policy|缺了跳转到外部业务系统时会把管理台完整 URL（含页面路径）带出去
Content-Security-Policy|真正拦 XSS 与点击劫持的那条；frame-ancestors 是 X-Frame-Options 的现代等价物
EOF

# CSP 的内容判据：只钉两条**改了就等于没有**的。
# ★frame-ancestors：X-Frame-Options 在现代浏览器里已被它取代，只留前者等于把防点击劫持
#   交给一条正在退役的头。
# ★script-src 里不得出现 unsafe-inline / unsafe-eval：那两个一加进去，CSP 对 XSS 的价值就
#   归零，而页面看起来完全正常——这正是"页面白了就先加 unsafe-inline"的必然下场。
#   `script-src[^;]*` 把范围严格限制在这一条指令内，不会误伤 style-src 里那个
#   **确实必要**的 'unsafe-inline'（Vue 的 :style 绑定与 Arco 运行时组件都写元素 style 属性）。
csp_line="$(https_part | grep -E '^ *add_header +Content-Security-Policy ' || true)"
if [ -n "$csp_line" ]; then
  echo "$csp_line" | grep -q "frame-ancestors" \
    || bad "CSP 里没有 frame-ancestors（X-Frame-Options 已被它取代，只留旧头等于把防点击劫持交给一条正在退役的头）"
  if echo "$csp_line" | grep -Eq "script-src[^;]*unsafe-(inline|eval)"; then
    bad "CSP 的 script-src 里出现了 unsafe-inline/unsafe-eval —— CSP 对 XSS 的价值就此归零，而页面看起来完全正常。console 的 Vite 产物没有内联 script，实测不需要它们（理由与验证方式见 nginx/baidi.conf 的注释）"
  fi
fi

# 反向断言：**任何 location 块内部都不得出现 add_header**。
# nginx 的 add_header 就近整组覆盖 —— 一条 location 里自加一条，server 级那四条对它全部失效，
# 且 nginx -t 通过、页面正常。真要给某个 location 单加头，必须把 server 级那四条一并抄进去。
if strip | awk '
    $0 ~ /^ *location /  { inloc = 1; next }
    inloc && /^ *}/      { inloc = 0; next }
    inloc && /add_header/ { hit = 1 }
    END { exit !hit }'; then
  bad "有 add_header 写在 location 块内：nginx 的 add_header 是就近整组覆盖不是叠加，该 location 会把 server 级的全部安全响应头丢掉（nginx -t 通过、页面正常，只有响应头空了）"
fi

# ── ⑤ 存活探测通路：必须存在、必须精确匹配、必须真反代 ──────────────────────
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

# ── ⑥ proxy 公共片段：必须随包发，且不能叫 .conf ────────────────────────────
# conf.d/*.conf 会被 include 进 http{}，而这份片段全是只能出现在 location 里的
# proxy_* 指令 → 整台机器的 nginx 起不来（含共存的烛龙）。
[ -f "$DIR/baidi-proxy-api.inc" ] || bad "缺少 nginx/baidi-proxy-api.inc"
if ls "$DIR/"*.inc.conf >/dev/null 2>&1; then
  bad "nginx 片段不得以 .conf 结尾（会被 include 进 http{} 而炸掉整台机器的 nginx）"
fi

# ── ⑦ 80 端口块：ACME 挑战通路 + 跳转必须在 location 内 ────────────────────
#
# ★守的是什么：nginx 的 `return` 属于 rewrite 模块，**在 rewrite 阶段执行、早于 location
#   选择**。写成 server 级的 `return 301 https://…;` 时，本 server 收到的每一个请求
#   （含 /.well-known/acme-challenge/xxx）都在挑 location 之前就被 301 走——下面那条
#   挑战 location 一次都不会命中。而这件事在机器上**完全看不出来**：nginx -t 通过、
#   站点正常、跳转也正常，只有签发那一步失败，且 lego 报的是「拿不到挑战文件 / 404」，
#   看起来像 webroot 配错了。2026-09-08 演示站上就是先踩了这个形态，改成
#   「挑战 location + return 301 挪进 location /」之后一次签发成功。
#   本文件这三条就是不让后来的人把它改回去（"顺手简化成 server 级 return" 太自然了）。
#
# ★这个 80 块此前是 install-remote.sh 里的一段 heredoc，本自检**看不到**它。
#   现在它写在模板里、由 install-remote.sh 按 @BD_HTTP80_BEGIN@/@BD_HTTP80_END@
#   在非 443 端口时整段删掉——所以这对标记也要钉住：标记没了，共存机（9443）就会
#   带上一个抢 80 端口的 server 块，与烛龙的共存契约当场破裂，而 nginx -t 照样通过。
for m in '@BD_HTTP80_BEGIN@' '@BD_HTTP80_END@'; do
  grep -q -- "$m" "$CONF" || bad "80 端口块缺少标记 ${m}（install-remote.sh 靠这对标记在非 443 端口上整段删掉它；缺了就会在共存机上抢 80）"
done

# ★这条**必须用 grep 而不是 block_has**：`^~` 里那个 `^` 出现在正则中段，
#   awk 的动态正则里它是语法错误（BSD awk 直接报 syntax error，mawk/gawk 行为也不一致）。
#   grep -E 里写成 `\^` 就是普通字符。判据分两半：`^~` 的形状用 grep 查，块内有没有
#   root 用 block_has 查（后者的 loc 正则绕开那个 `^`）。
strip | grep -Eq '^ *location +\^~ +/\.well-known/acme-challenge/' \
  || bad "缺少 ACME HTTP-01 挑战通路（location ^~ /.well-known/acme-challenge/）——Let's Encrypt 证书将永远签不下来，而站点一切正常"
block_has '^ *location .*acme-challenge' 'root ' \
  || bad "ACME 挑战 location 块内没有 root（挑战文件的落点没了，lego 会报 404）"

block_has '^ *location +/ ' 'return +301' \
  || bad "80 端口块里的 return 301 不在 location 内（或整个跳转没了）"

# 反向断言：剥注释后，任何 location 块**外**都不得出现 return 301。
# 这一条才是真正拦住「改回 server 级 return」的那道——上面那条只保证「location 里有一条」，
# 两条都写着的时候 server 级那条照样会先执行、照样吃掉挑战。
if strip | awk '
    $0 ~ /^ *location /   { inloc = 1; next }
    inloc && /^ *}/       { inloc = 0; next }
    !inloc && /return +301/ { hit = 1 }
    END { exit !hit }'; then
  bad "有 return 301 写在 location 块之外（server 级）：它在 rewrite 阶段执行、早于 location 选择，会把 ACME 挑战一起重定向掉——证书永远签不下来而处处正常"
fi

if [ "$fail" -ne 0 ]; then
  echo "✗ nginx 站点配置自检未通过（见上）"
  exit 1
fi
echo "✓ nginx 站点配置自检通过：限流区 3 条定义 + 6 个应用点、安全响应头 4 条（server 级 + always + 无 location 自加）、/healthz 精确匹配且真反代、ACME 挑战通路在位且 return 301 在 location 内、片段命名合规"
