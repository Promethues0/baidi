#!/usr/bin/env bash
# 构建白帝交付物：console 静态产物 + baidi-control 的 linux/amd64 二进制 → deploy/_out/
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$HERE/_out"

# 定位 go（交互 shell/版本管理器可能没把它加进 PATH）
GO="${GO:-go}"
if ! command -v "$GO" >/dev/null 2>&1; then
  for c in "$HOME/.local/share/mise/shims/go" /usr/local/go/bin/go /opt/homebrew/bin/go "$HOME/go/bin/go" \
           "$HOME"/.local/share/mise/installs/go/*/bin/go; do
    [ -x "$c" ] && GO="$c" && break
  done
fi
"$GO" version >/dev/null 2>&1 || { echo "✗ 找不到 go：把 go 加入 PATH，或运行 GO=/path/to/go ./deploy.sh"; exit 1; }
echo "==> 用 go：$("$GO" version) @ $GO"

echo "==> 清理输出目录 $OUT"
rm -rf "$OUT"; mkdir -p "$OUT/web" "$OUT/bin"

echo "==> 构建 console（Vite）"
( cd "$ROOT/console" && (npm ci || npm install) && npm run build )
cp -R "$ROOT/console/dist/." "$OUT/web/"

echo "==> 交叉编译 baidi-control（linux/amd64，纯 Go 无 cgo）"
( cd "$ROOT/control" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -ldflags='-s -w' -o "$OUT/bin/baidi-control" ./cmd/baidi-control )

# 网关版本号（编译期注入 main.version，随 mTLS 心跳上报控制面）：
# 优先 BAIDI_VERSION，缺省取 git 短哈希；两者都取不到时保留源码缺省 "dev"。
BD_VERSION="${BAIDI_VERSION:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)}"
echo "==> 交叉编译数据面 baidi-gateway（版本 ${BD_VERSION}）+ baidi-gmca（linux/amd64）"
( cd "$ROOT/gateway" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -ldflags="-s -w -X main.version=$BD_VERSION" -o "$OUT/bin/baidi-gateway" ./cmd/baidi-gateway )
( cd "$ROOT/gateway" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -ldflags='-s -w' -o "$OUT/bin/baidi-gmca" ./cmd/baidi-gmca )

# 站点组网网关（东西向，自研 IKEv2/ESP）。无条件编译、由 install-remote.sh 的 WITH_IPSEC 决定装不装：
# 交付包里多一个 3MB 二进制的成本，远小于「现场想开组网却发现产物里没有」的成本。
echo "==> 交叉编译站点组网网关 baidi-ipsec（linux/amd64）"
( cd "$ROOT/gateway" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -ldflags='-s -w' -o "$OUT/bin/baidi-ipsec" ./cmd/baidi-ipsec )

# 控制面温备节点（PRD 15.5）。同 baidi-ipsec：无条件编译、装不装由部署时决定。
# ★它同时是**提升流程的执行方**——promote-standby.sh 靠它校验备份完整性与解包。
# 产物里没有它的话，系统页上那条切换命令就是一句谎话（脚本第一步就会退出）。
echo "==> 交叉编译控制面温备节点 baidi-standby（linux/amd64）"
( cd "$ROOT/control" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -ldflags='-s -w' -o "$OUT/bin/baidi-standby" ./cmd/baidi-standby )

# ACME 客户端 lego（只有 WITH_ACME_IP_CERT=1 的部署才用得到，见 config.env.example）。
#
# ★为什么要由**构建机**编译进包，而不是让目标机自己去取：演示站（腾讯云大陆机）实测
#   访问 codeload.github.com 超时，装机脚本里现取 = 那台机上这个功能永远开不起来。
#   ubuntu 自带的 certbot 2.9 也用不了——它不支持 `--preferred-profile`，而 LE 的
#   **IP 地址证书只能走 shortlived profile**。lego 是单二进制纯 Go，交叉编译最省事。
#
# ★取不到模块时**只跳过 lego，不让整个构建失败**：这是一个可选组件（默认关的开关），
#   为它拖垮 console + 五个 Go 二进制的全部交付是明显的错误取舍。代价说在明处——
#   install-remote.sh 在「开关打开却没有 lego」时会明确报错并保持自签，不会静默。
#   （所以这里**不能**改成 `|| true` 就完事：那样连"没带上"这件事都没人说。）
#
# ★版本钉死：ACME profile 是 2025 年才进 lego 的（v4.21+），旧版本没有 `--profile`，
#   而缺了它 IP 证书压根签不下来。跟着 latest 走 = 某天构建机换了缓存就换了行为。
#
# ★与 baidi-ipsec / baidi-standby 那两个「无条件编译进包」的取舍**相反**：那两个各 3~6MB，
#   多带上的成本远小于「现场想开却发现产物里没有」；而 lego 剥完符号仍有 ~65MB
#   （它把几十家 DNS 服务商的 SDK 全静态链进去了），是整个交付包的两倍多，每次部署
#   都要 rsync 一遍。所以这一个跟着开关走：deploy.sh 把 config.env 里的
#   WITH_ACME_IP_CERT 显式传进来，只有真要用的部署才带。
#   单独跑 build.sh（CI / 手工）时默认不带——install-remote.sh 在「开关开着却没有 lego」
#   时会明确报错并保持自签，不会静默。
LEGO_VERSION=v4.35.2
if [ "${WITH_ACME_IP_CERT:-0}" = "1" ]; then
  echo "==> 交叉编译 ACME 客户端 lego ${LEGO_VERSION}（linux/amd64）"
  lego_tmp="$(mktemp -d)"
  if ( cd "$lego_tmp" \
       && "$GO" mod init baidi-lego-build >/dev/null 2>&1 \
       && "$GO" get "github.com/go-acme/lego/v4/cmd/lego@${LEGO_VERSION}" >/dev/null 2>&1 \
       && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
          "$GO" build -trimpath -ldflags='-s -w' -o "$OUT/bin/lego" github.com/go-acme/lego/v4/cmd/lego ); then
    echo "    ✓ 已携带 lego（$(wc -c < "$OUT/bin/lego" | tr -d ' ') 字节）"
  else
    echo "    ⚠ 取不到 github.com/go-acme/lego@${LEGO_VERSION}（构建机不通外网？），本次交付包**不含 lego**"
    echo "      → 装机时 install-remote.sh 会明确报错并保持自签证书，站点照常可用；"
    echo "        修法：在能访问 proxy.golang.org 的机器上重跑本脚本。"
    rm -f "$OUT/bin/lego"
  fi
  rm -rf "$lego_tmp"
else
  # 不打印成 ✗/⚠：这不是失败，是这次部署压根没要这个可选组件。
  echo "==> 不携带 ACME 客户端 lego（WITH_ACME_IP_CERT!=1）"
fi

echo "==> 携带部署脚本/模板"
# 隐身规则集脚本随包走（WITH_STEALTH=1 时 install-remote.sh 会装到 $BD_PREFIX/bin）。
# ★用仓库里那一份而不是在部署脚本里重抄一遍规则：抄一遍就有第二个真相来源，
#   而两份规则不一致时的症状是「网关页说 armed、实际保护的是别的端口」。
mkdir -p "$OUT/firewall"
cp "$ROOT/gateway/firewall/baidi-nft.sh" "$OUT/firewall/baidi-nft.sh"
# acme-renew.sh 是**模板**（占位由 install-remote.sh 渲染后装到 $BD_PREFIX/bin）：
# 与隐身规则集同一条理由——不在装机脚本里重抄一遍续期逻辑，那就有了第二个真相来源，
# 而两份不一致时的症状是「证书续着、nginx 用的是另一张」，正是这功能要消灭的那种。
cp -R "$HERE/systemd" "$HERE/nginx" "$HERE/install-remote.sh" "$HERE/wipe-remote.sh" \
      "$HERE/promote-standby.sh" "$HERE/acme-renew.sh" "$OUT/"

if [ -d "$HERE/artifacts/downloads" ]; then
  echo "==> 携带客户端安装包（deploy/artifacts/downloads）"
  cp -R "$HERE/artifacts/downloads" "$OUT/downloads"
fi

# 自检：交付 nginx 站点配置（限流指令 / 存活探测通路 / 烛龙共存契约 / 片段命名）。
#
# ★这批检查抽在 deploy/check-nginx.sh 里、这里只是**调用方之一**：
#   留在这里的话，它们唯一的触发方式是有人手工跑一遍全量 build（npm ci + 五个 Go 二进制，
#   几分钟起步），而改一行 nginx 配置的人不会为了几条 grep 去跑它；
#   `.github/workflows/server.yml` 的 paths 虽然含 deploy/**，但它的 job 一个都不读
#   deploy/nginx/ ——改 nginx 配置时 CI 只是空转一遍全绿。现在 server.yml 直接跑那个脚本，
#   本行则继续守住「交付件本身」这一侧（模板与产物之间隔着一次 cp）。
#
# ★检查内容为什么必须区分「zone 定义」与「限流应用点」，见 check-nginx.sh 顶部：
#   改造前这里是一句纯子串循环，五条判据里有四条被顶部那三行 zone 定义顶包，
#   实测删掉全部 5 个 limit_req 应用点仍然五条全绿。
"$HERE/check-nginx.sh" "$OUT/nginx"

# 自检：部署入参的转发白名单（config.env.example 的每一项 deploy.sh 都要真的带过去）。
#
# ★这一条查的是**仓库里的源文件**而不是产物：deploy.sh 压根不进交付包（它跑在运维本机上），
#   而漏转的后果落在装出来的机器上——config.env 里写了、部署报「✓ 部署完成」，那一项却根本
#   没生效。本仓已因此踩到三次（WITH_IPSEC / WITH_STEALTH / BAIDI_BACKUP_* 与 MTLS_PORT+GW_ID），
#   理由与豁免名单逐条写在 check-deploy-env.sh 里。CI 的 server.yml 也直接跑它。
"$HERE/check-deploy-env.sh"

echo "✓ 构建完成 → $OUT"
ls -la "$OUT" "$OUT/bin"
