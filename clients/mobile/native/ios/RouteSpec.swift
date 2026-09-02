// 白帝 iOS 数据面 · 受保护网段解析
// 纯 Swift、不依赖 NetworkExtension / Baidimobile：好让 `test-routespec.sh` 在任意一台 mac 上用 swiftc
// 编译并跑断言——PacketTunnelProvider 本身要 Xcode 工程 + Network Extension 授权才编得动，
// 而它的路由解析是最容易静默出错的一段。与安卓 `RouteSpec.kt` 同构、同一套拒绝口径。

import Foundation

/// 一条要接管进 utun 的网段：地址 + 前缀长度（0...32）。
struct RouteSpec: Equatable {
    let addr: String
    let prefix: Int
    /// CIDR 前缀长度 → 点分十进制子网掩码（NEIPv4Route 只收掩码不收前缀）。
    var mask: String { Routes.mask(prefix) }
}

enum RouteSpecError: Error, Equatable, CustomStringConvertible {
    case empty
    case malformed(entry: String, why: String)

    var description: String {
        switch self {
        case .empty: return "受保护网段为空"
        case let .malformed(entry, why): return "网段「\(entry)」\(why)"
        }
    }
}

enum Routes {
    /// 剖面拉不到时的回退网段（与安卓 `Routes.DEFAULT`、桌面 baidi-tun 同一默认值）。
    static let defaultSpec = "10.99.0.0/24"

    /// 解析逗号分隔的多网段 CIDR 串，如 `10.99.0.0/24,10.99.1.0/24`。
    /// 剖面 `routes` 由 vpn.ts 用 `join(',')` 拼成这一串下传——与桌面 `baidi-tun -route` 同一契约。
    ///
    /// ★任何一条不合法就整体抛错，并点名是哪一条。
    ///   改造前 `route.split(separator: "/", maxSplits: 1)`：两段以上时 `net[1]` 形如 `"24,10.99.1.0/24"` →
    ///   `Int(...)` 为 nil → **静默回落 24** → `includedRoutes` 只有第一段。剖面明明下发了两段，
    ///   第二段的应用直连不走隧道，两侧零报错。这里一律 fail-closed，拒绝要说得出是哪一条。
    static func parse(_ spec: String) throws -> [RouteSpec] {
        let entries = spec.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        if entries.isEmpty { throw RouteSpecError.empty }
        return try entries.map { entry in
            let parts = entry.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 2 else {
                throw RouteSpecError.malformed(entry: entry, why: "不是 地址/前缀 形式")
            }
            guard let prefix = Int(parts[1]) else {
                throw RouteSpecError.malformed(entry: entry, why: "的前缀长度不是整数")
            }
            guard (0...32).contains(prefix) else {
                throw RouteSpecError.malformed(entry: entry, why: "的前缀长度越界（须在 0...32）")
            }
            guard isIPv4(parts[0]) else {
                throw RouteSpecError.malformed(entry: entry, why: "的地址不是点分十进制 IPv4")
            }
            return RouteSpec(addr: parts[0], prefix: prefix)
        }
    }

    /// CIDR 前缀长度 → 点分十进制子网掩码。
    static func mask(_ p: Int) -> String {
        let bits: UInt32 = p >= 32 ? 0xFFFF_FFFF : (p <= 0 ? 0 : (0xFFFF_FFFF << (32 - UInt32(p))))
        return "\((bits >> 24) & 0xFF).\((bits >> 16) & 0xFF).\((bits >> 8) & 0xFF).\(bits & 0xFF)"
    }

    /// 四段 0...255 的点分十进制。刻意不走系统解析器：那会去做 DNS。
    private static func isIPv4(_ s: String) -> Bool {
        let octets = s.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return false }
        return octets.allSatisfy { o in
            !o.isEmpty && o.count <= 3 && o.allSatisfy { $0.isASCII && $0.isNumber } && (Int(o) ?? 256) <= 255
        }
    }
}
