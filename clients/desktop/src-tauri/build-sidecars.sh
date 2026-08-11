#!/usr/bin/env bash
# 构建桌面客户端 Tauri sidecar 二进制（baidi-knock 敲门器 + baidi-tun 数据面引擎），
# 按当前 Rust host 三元组命名放到 binaries/，供 tauri.conf.json externalBin 打包。
# 用法：./build-sidecars.sh
#
# 命名约定（Tauri v2 externalBin）：配置里写 "binaries/baidi-tun"，打包时**精确查找**
# `binaries/baidi-tun-<host 三元组><可执行后缀>`——Windows 上那个后缀是 `.exe`，
# 少了它 tauri build 直接报「找不到 sidecar」。运行期客户端找的也是同一批名字，
# 见 src/elevate.rs `sidecar_candidates`（那边同样要求 Windows 带 .exe），两处必须对得上。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW="$(cd "$HERE/../../../gateway" && pwd)"
# 防御性剥 CR：Windows 上若 rustc 的输出走了 CRLF，三元组尾巴会挂一个不可见的 \r，
# 产物名随之带上它——而 Tauri 报的错是「找不到 sidecar」，与把名字拼错完全同形。
TRIPLE="$(rustc -vV | sed -n 's/host: //p' | tr -d '\r')"
echo "==> host 三元组：$TRIPLE"

# 解析 GOOS/GOARCH/可执行后缀
EXT=""
case "$TRIPLE" in
  aarch64-apple-darwin) GOOS=darwin GOARCH=arm64 ;;
  x86_64-apple-darwin)  GOOS=darwin GOARCH=amd64 ;;
  x86_64-*linux*)       GOOS=linux  GOARCH=amd64 ;;
  aarch64-*linux*)      GOOS=linux  GOARCH=arm64 ;;
  x86_64-pc-windows-*)  GOOS=windows GOARCH=amd64 EXT=.exe ;;
  aarch64-pc-windows-*) GOOS=windows GOARCH=arm64 EXT=.exe ;;
  *) echo "✗ 未适配的三元组 $TRIPLE，请手动设置 GOOS/GOARCH"; exit 1 ;;
esac

mkdir -p "$HERE/binaries"
echo "==> 编译 baidi-knock（$GOOS/$GOARCH）"
( cd "$GW" && CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' \
    -o "$HERE/binaries/baidi-knock-$TRIPLE$EXT" ./cmd/baidi-knock )
echo "==> 编译 baidi-tun（$GOOS/$GOARCH，utun/tun/wintun 数据面引擎）"
( cd "$GW" && CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -trimpath -ldflags='-s -w' \
    -o "$HERE/binaries/baidi-tun-$TRIPLE$EXT" ./cmd/baidi-tun )
chmod +x "$HERE/binaries/"*

# Windows 上 baidi-tun 还需要 wintun.dll 才能建虚拟网卡。二进制**不入库**（第三方产物，
# 入库之后没人再核对来源），改为构建期从官方取件 + SHA-256 强校验，逻辑全在 fetch-wintun.sh。
# 这里只是把它接进 Windows 这条构建线；离线/内网构建、排障时那个脚本可以单独跑。
if [ "$GOOS" = "windows" ]; then
  echo "==> 取 wintun.dll（$GOARCH，官方 zip + 哈希强校验）"
  "$HERE/fetch-wintun.sh" --arch "$GOARCH"
  # ★取完立刻复核一次固定位的架构。看着像多余（上一行刚按 GOARCH 取的），但它拦的是
  #   "暂存区在此之前被手工动过"：取件脚本只在**单一架构**时才写固定位，别的路径
  #   （比如先跑过一次 --arch all）会留下与本次目标对不上的残留。判据是 wintun.dll.triple
  #   —— 那个文件此前只写不读，这里是它的第一个消费方。打包前还会再跑一次，
  #   见 tauri.conf.json 的 beforeBundleCommand。
  "$HERE/verify-wintun-stage.sh" --triple "$TRIPLE"
fi

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
