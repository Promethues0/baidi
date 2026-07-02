// 白帝 iOS 数据面 · NEPacketTunnelProvider（Network Extension target）
// 依赖 gomobile bind 产出的 Baidimobile.xcframework（baidi.dev/gateway/mobile/baidimobile）。
//
// 角色：建立系统级 utun（受保护网段路由进来），把 utun fd 交给 Go 引擎做
//       SPA 敲门 + 国密 TLCP 隧道 + gVisor 引流。UI(WKWebView) 经 __BAIDI_NATIVE__ 桥触发。
// 注意：iOS Network Extension 需付费开发者账号 + Packet Tunnel entitlement，须真机/模拟器编译。

import NetworkExtension
import Baidimobile

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var session: BaidimobileSession?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // opts 由主应用透传（来自 UI 接入配置 __BAIDI_NATIVE__.startTunnel(token, cfg)）
        let opts = options ?? [:]
        let gateway  = (opts["gateway"] as? String)  ?? "gw.baidi.local"
        let spaPort  = (opts["spaPort"] as? String)  ?? "18201"
        let proxyPort = (opts["proxyPort"] as? String) ?? "18443"
        let vip      = (opts["ip"] as? String)       ?? "10.99.0.2"
        let route    = (opts["route"] as? String)    ?? "10.99.0.0/24"
        let gmOn     = (opts["gm"] as? NSNumber)?.boolValue ?? true
        let net = route.split(separator: "/", maxSplits: 1).map(String.init)
        let netAddr = net.first ?? "10.99.0.0"
        let prefix = net.count > 1 ? (Int(net[1]) ?? 24) : 24

        // 1) 配置 TUN：虚拟 IP + 把受保护网段（来自配置）路由进 utun（其余流量仍走系统默认）
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: gateway)
        let ipv4 = NEIPv4Settings(addresses: [vip], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: netAddr, subnetMask: Self.mask(prefix))]
        settings.ipv4Settings = ipv4
        settings.mtu = 1420

        setTunnelNetworkSettings(settings) { [weak self] err in
            guard let self = self else { return }
            if let err = err { completionHandler(err); return }
            guard let fd = self.tunnelFD() else {
                completionHandler(NSError(domain: "baidi", code: -1, userInfo: [NSLocalizedDescriptionKey: "取 utun fd 失败"]))
                return
            }

            // 2) 配置并启动 Go 引擎（fd 交给 baidimobile，扩展内不再碰包）
            let cfg = BaidimobileConfig()
            cfg.spaAddr    = "\(gateway):\(spaPort)"
            cfg.proxyAddr  = "\(gateway):\(proxyPort)"
            cfg.token      = (opts["token"] as? String)   ?? ""
            cfg.control    = (opts["control"] as? String) ?? ""   // 非空=短时效一次性令牌+保活
            cfg.gm         = gmOn
            cfg.caPEM      = (opts["caPEM"] as? String)   ?? ""
            cfg.serverName = "baidi-gateway"
            cfg.mtu        = 1420

            var startErr: NSError?
            self.session = BaidimobileStart(fd, cfg, &startErr)
            completionHandler(startErr)
        }
    }

    /// CIDR 前缀长度 → 点分十进制子网掩码。
    static func mask(_ p: Int) -> String {
        let bits: UInt32 = p >= 32 ? 0xFFFF_FFFF : (p <= 0 ? 0 : (0xFFFF_FFFF << (32 - UInt32(p))))
        return "\((bits >> 24) & 0xFF).\((bits >> 16) & 0xFF).\((bits >> 8) & 0xFF).\(bits & 0xFF)"
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        session?.stop()
        session = nil
        completionHandler()
    }

    /// 取 NEPacketTunnelProvider 持有的 utun fd（业界已知做法：从 packetFlow 反射取 socket fd）。
    private func tunnelFD() -> Int32? {
        return self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32
    }
}
