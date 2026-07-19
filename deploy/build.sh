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

echo "==> 交叉编译数据面 baidi-gateway + baidi-gmca（linux/amd64）"
( cd "$ROOT/gateway" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -ldflags='-s -w' -o "$OUT/bin/baidi-gateway" ./cmd/baidi-gateway )
( cd "$ROOT/gateway" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -ldflags='-s -w' -o "$OUT/bin/baidi-gmca" ./cmd/baidi-gmca )

echo "==> 携带部署脚本/模板"
cp -R "$HERE/systemd" "$HERE/nginx" "$HERE/install-remote.sh" "$HERE/wipe-remote.sh" "$OUT/"

if [ -d "$HERE/artifacts/downloads" ]; then
  echo "==> 携带客户端安装包（deploy/artifacts/downloads）"
  cp -R "$HERE/artifacts/downloads" "$OUT/downloads"
fi

# 自检：交付 nginx 站点绝不得含 default_server（防旧模板混入毒化烛龙后续 reload）
if sed 's/#.*//' "$OUT/nginx/baidi.conf" | grep -q 'default_server'; then
  echo "✗ 交付 nginx/baidi.conf 含 default_server 指令，构建中止"; exit 1
fi

echo "✓ 构建完成 → $OUT"
ls -la "$OUT" "$OUT/bin"
