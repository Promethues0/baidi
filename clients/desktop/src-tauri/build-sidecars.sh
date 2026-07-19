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

# macOS 上顺带产出另一 darwin 架构，供 universal 打包（Tauri 按 <name>-<triple> 查找）
if [[ "$TRIPLE" == *apple-darwin ]]; then
  for OTHER in aarch64-apple-darwin x86_64-apple-darwin; do
    [ "$OTHER" = "$TRIPLE" ] && continue
    case "$OTHER" in
      aarch64-apple-darwin) OGOARCH=arm64 ;;
      x86_64-apple-darwin)  OGOARCH=amd64 ;;
    esac
    echo "==> 交叉编译 sidecar（darwin/$OGOARCH → $OTHER）"
    ( cd "$GW" && CGO_ENABLED=0 GOOS=darwin GOARCH=$OGOARCH go build -trimpath -ldflags='-s -w' \
        -o "$HERE/binaries/baidi-knock-$OTHER" ./cmd/baidi-knock )
    ( cd "$GW" && CGO_ENABLED=0 GOOS=darwin GOARCH=$OGOARCH go build -trimpath -ldflags='-s -w' \
        -o "$HERE/binaries/baidi-tun-$OTHER" ./cmd/baidi-tun )
  done
  chmod +x "$HERE/binaries/"*

  # Tauri 打包 --target universal-apple-darwin 时，externalBin 按 <name>-universal-apple-darwin
  # 精确查找资源文件——不会自动 lipo 两个单架构 sidecar，需要我们自己合成胖二进制
  for BIN in baidi-knock baidi-tun; do
    if [ -f "$HERE/binaries/$BIN-aarch64-apple-darwin" ] && [ -f "$HERE/binaries/$BIN-x86_64-apple-darwin" ]; then
      echo "==> lipo 合成 $BIN-universal-apple-darwin"
      lipo -create -output "$HERE/binaries/$BIN-universal-apple-darwin" \
        "$HERE/binaries/$BIN-aarch64-apple-darwin" "$HERE/binaries/$BIN-x86_64-apple-darwin"
    fi
  done
  chmod +x "$HERE/binaries/"*
fi

echo "✓ sidecar 就绪："; ls -la "$HERE/binaries/"
