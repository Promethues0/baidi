#!/bin/bash
# iOS 壳的网段解析自检：编 RouteSpec.swift + routespec-test/main.swift 并跑断言。
# 不需要 Xcode 工程、不需要 Network Extension 授权——只要 mac 上有 swiftc（Xcode 或 Command Line Tools）。
# PacketTunnelProvider.swift 本身在这里编不了（要 Baidimobile.xcframework + iOS SDK），它只消费 Routes.parse。
set -euo pipefail
cd "$(dirname "$0")"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
xcrun swiftc -o "$OUT/routespec-test" RouteSpec.swift routespec-test/main.swift
"$OUT/routespec-test"
