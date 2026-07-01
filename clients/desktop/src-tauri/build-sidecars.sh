#!/usr/bin/env bash
# 构建桌面客户端 Tauri sidecar 二进制（baidi-knock 敲门器 + baidi-tun 数据面引擎），
# 按当前 Rust host 三元组命名放到 binaries/，供 tauri.conf.json externalBin 打包。
# 用法：./build-sidecars.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW="$(cd "$HERE/../../../gateway" && pwd)"
TRIPLE="$(rustc -vV | sed -n 's/host: //p')"
echo "==> host 三元组：$TRIPLE"

# 解析 GOOS/GOARCH
case "$TRIPLE" in
  aarch64-apple-darwin) GOOS=darwin GOARCH=arm64 ;;
  x86_64-apple-darwin)  GOOS=darwin GOARCH=amd64 ;;
  x86_64-*linux*)       GOOS=linux  GOARCH=amd64 ;;
  aarch64-*linux*)      GOOS=linux  GOARCH=arm64 ;;
  *) echo "✗ 未适配的三元组 $TRIPLE，请手动设置 GOOS/GOARCH"; exit 1 ;;
esac

mkdir -p "$HERE/binaries"
echo "==> 编译 baidi-knock（$GOOS/$GOARCH）"
( cd "$GW" && CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' \
    -o "$HERE/binaries/baidi-knock-$TRIPLE" ./cmd/baidi-knock )
echo "==> 编译 baidi-tun（$GOOS/$GOARCH，utun 数据面引擎）"
( cd "$GW" && CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' \
    -o "$HERE/binaries/baidi-tun-$TRIPLE" ./cmd/baidi-tun )
chmod +x "$HERE/binaries/"*
echo "✓ sidecar 就绪："; ls -la "$HERE/binaries/"
