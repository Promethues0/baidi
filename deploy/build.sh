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

echo "==> 携带部署脚本/模板"
# 隐身规则集脚本随包走（WITH_STEALTH=1 时 install-remote.sh 会装到 $BD_PREFIX/bin）。
# ★用仓库里那一份而不是在部署脚本里重抄一遍规则：抄一遍就有第二个真相来源，
#   而两份规则不一致时的症状是「网关页说 armed、实际保护的是别的端口」。
mkdir -p "$OUT/firewall"
cp "$ROOT/gateway/firewall/baidi-nft.sh" "$OUT/firewall/baidi-nft.sh"
cp -R "$HERE/systemd" "$HERE/nginx" "$HERE/install-remote.sh" "$HERE/wipe-remote.sh" \
      "$HERE/promote-standby.sh" "$OUT/"

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

echo "✓ 构建完成 → $OUT"
ls -la "$OUT" "$OUT/bin"
