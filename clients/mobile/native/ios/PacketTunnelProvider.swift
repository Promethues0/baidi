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
        let route    = (opts["route"] as? String)    ?? Routes.defaultSpec
        let gmOn     = (opts["gm"] as? NSNumber)?.boolValue ?? true
        // ★多网段：剖面 routes 经 vpn.ts `join(',')` 下传成逗号串（与桌面 baidi-tun -route 同契约）。
        //   改造前 `split(separator: "/", maxSplits: 1)` 只认第一段，其余静默丢弃、前缀解析失败还回落 24：
        //   第二段的应用直连不走隧道而 UI 显示「已接入」。现在任一条不合法就整体失败并点名那一条
        //   （fail-closed，见 RouteSpec.swift；断言在 test-routespec.sh）。
        let routes: [RouteSpec]
        do {
            routes = try Routes.parse(route)
        } catch {
            completionHandler(NSError(domain: "baidi", code: -2, userInfo: [
                NSLocalizedDescriptionKey: "受保护网段配置无效：\(error)（下发原文：\(route)）"
            ]))
            return
        }

        // 1) 配置 TUN：虚拟 IP + 把受保护网段（来自配置，可多条）逐条路由进 utun（其余流量仍走系统默认）
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: gateway)
        let ipv4 = NEIPv4Settings(addresses: [vip], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = routes.map { NEIPv4Route(destinationAddress: $0.addr, subnetMask: $0.mask) }
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
            // ★钉扎指纹与资源映射：由控制面接入剖面下发。缺了它们，隧道对网关身份
            //   零校验、且每条连接都不发 CONNECT 前导（网关侧对无前导连接 fail-closed）。
            //   本文件目前没有 Xcode 工程（见 clients/BUILD.md 第九节），但必须与
            //   Android 侧保持同构——否则建工程那天会原样复现同一个洞。
            cfg.pin             = (opts["pin"] as? String)             ?? ""
            cfg.resmapJSON      = (opts["resmap"] as? String)          ?? ""
            cfg.defaultResource = (opts["defaultResource"] as? String) ?? ""

            var startErr: NSError?
            // ★fd 是 Int32（utun 的 socket fd），而 gomobile 头文件里 `BaidimobileStart(long tunFd, …)`
            //   在 Swift 侧是 Int——对着 xcframework -typecheck 直接报类型不匹配；没有 Xcode 工程就没有编译，
            //   这个错才能留到今天。显式转宽。
            self.session = BaidimobileStart(Int(fd), cfg, &startErr)
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
