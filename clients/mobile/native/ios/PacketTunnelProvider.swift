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
        let opts = options ?? [:]

        // 1) 配置 TUN：虚拟 IP + 把受保护网段路由进 utun（其余流量仍走系统默认）
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.99.0.2"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "10.99.0.0", subnetMask: "255.255.255.0")]
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
            cfg.spaAddr    = (opts["spa"] as? String)     ?? "gw.baidi.local:18201"
            cfg.proxyAddr  = (opts["proxy"] as? String)   ?? "gw.baidi.local:18443"
            cfg.token      = (opts["token"] as? String)   ?? ""
            cfg.control    = (opts["control"] as? String) ?? ""   // 非空=短时效一次性令牌+保活
            cfg.gm         = true
            cfg.caPEM      = (opts["caPEM"] as? String)   ?? ""
            cfg.serverName = "baidi-gateway"
            cfg.mtu        = 1420

            var startErr: NSError?
            self.session = BaidimobileStart(fd, cfg, &startErr)
            completionHandler(startErr)
        }
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
