// 白帝安卓数据面 · VpnService
// 依赖 gomobile bind 产出的 baidimobile.aar（baidi.dev/gateway/mobile/baidimobile）。
//
// 角色：VpnService.Builder 建立系统级 TUN（受保护网段路由进来），把 fd 交给 Go 引擎做
//       SPA 敲门 + 国密 TLCP 隧道 + gVisor 引流。UI(WebView) 经 __BAIDI_NATIVE__ 桥触发。
// 需 manifest 声明 BIND_VPN_SERVICE，并先 VpnService.prepare() 取用户授权。

package dev.baidi.mobile

import android.content.Intent
import android.net.VpnService
import baidimobile.Baidimobile
import baidimobile.Config
import baidimobile.Session
import org.json.JSONObject

class BaidiVpnService : VpnService() {
    private var session: Session? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val token = intent?.getStringExtra("token")
        if (token.isNullOrBlank()) {
            // ★每条失败路径都要把原因交给 TunnelState，否则 UI 只能靠猜。
            //   改造前这里是裸 `return START_NOT_STICKY`，而桥无条件回 ok:true。
            //   走到这里的形态是系统自己拉起服务（「始终开启」/ 进程被杀后重建）：那些 Intent 都不带
            //   token 与 cfg——令牌只活在 webview 的会话里，服务拿不到。manifest 已声明
            //   SUPPORTS_ALWAYS_ON=false 让那个开关不出现在系统设置里；这里把原因说全。
            TunnelState.markFailed("未收到身份令牌：令牌未随 Intent 下发（系统重建 / 始终开启路径尚不支持），请从应用内重新接入")
            return START_NOT_STICKY
        }
        // UI 下传的接入配置（gateway/spaPort/proxyPort/route/ip/gm/control）；缺省回退演示值
        val c = try { JSONObject(intent.getStringExtra("cfg") ?: "{}") } catch (e: Exception) { JSONObject() }
        val gateway = c.optString("gateway", "gw.baidi.local")
        val spaPort = c.optString("spaPort", "18201")
        val proxyPort = c.optString("proxyPort", "18443")
        val route = c.optString("route", Routes.DEFAULT)
        val vip = c.optString("ip", "10.99.0.2")
        val gmOn = c.optBoolean("gm", true)
        val ctl = c.optString("control", "")
        // ★钉扎指纹与资源映射：由控制面接入剖面下发，此前**整条链路上都没有它们**——
        //   隧道因此对网关身份零校验，且每条连接都不发 CONNECT 前导（网关侧那条
        //   回退路径完全跳过资源鉴权，wave9 已改 fail-closed）。
        val pinHex = c.optString("pin", "")
        val resmap = c.optString("resmap", "")
        val defRes = c.optString("defaultResource", "")
        // ★多网段：剖面 routes 经 vpn.ts `join(',')` 下传成逗号串（与桌面 baidi-tun -route 同契约）。
        //   改造前 `route.split("/")` 只切一次，两段以上时前缀解析成 null → 静默回落 24 → 只接管
        //   第一段的首地址；第二段的应用直连不走隧道，UI 却显示「已接入」。
        //   现在任何一条不合法就整体失败并点名那一条（fail-closed，见 Routes.parse）。
        val routes = try {
            Routes.parse(route)
        } catch (e: IllegalArgumentException) {
            TunnelState.markFailed("受保护网段配置无效：${e.message}（下发原文：$route）")
            return START_NOT_STICKY
        }

        // 1) 建立 TUN：虚拟 IP + 把受保护网段（来自配置，可多条）逐条路由进来
        val pfd = try {
            val b = Builder()
                .setSession("白帝安全接入")
                .setMtu(1420)
                .addAddress(vip, 32)
            for (r in routes) b.addRoute(r.addr, r.prefix)
            b.establish()
        } catch (e: Exception) {
            TunnelState.markFailed("建立系统 VPN 通道失败：${e.message ?: e.javaClass.simpleName}")
            return START_NOT_STICKY
        }
        if (pfd == null) {
            // establish() 返回 null 的常见成因就是用户没授权 / 授权被撤销——说清它，
            // 别让用户对着一个"已接入"的界面找不到问题。
            TunnelState.markFailed("系统未授予 VPN 权限，或授权已被撤销（请在弹出的系统对话框中允许）")
            return START_NOT_STICKY
        }

        // 2) 配置并启动 Go 引擎（fd 交给 baidimobile，Service 内不再碰包）
        val cfg = Config().apply {
            spaAddr = "$gateway:$spaPort"
            proxyAddr = "$gateway:$proxyPort"
            this.token = token
            control = ctl                 // 非空=短时效一次性令牌+保活
            gm = gmOn
            caPEM = intent.getStringExtra("caPEM") ?: ""
            serverName = "baidi-gateway"
            mtu = 1420L
            pin = pinHex              // 证书指纹钉扎（与桌面端同一份判据）
            resmapJSON = resmap       // 目的地址 → 资源 id，决定 CONNECT 前导发什么
            defaultResource = defRes
        }
        // detachFd()：把 fd 所有权交给 Go（引擎负责关闭）
        // ★Start 会同步返回错误（缺令牌/缺控制面/坏 resmap/建不出设备），必须接住并上报——
        //   丢掉它就回到了"UI 显示已接入而引擎根本没起来"的老形态。
        session = try {
            Baidimobile.start(pfd.detachFd().toLong(), cfg)
        } catch (e: Exception) {
            TunnelState.markFailed("数据面引擎启动失败：${e.message ?: e.javaClass.simpleName}")
            return START_NOT_STICKY
        }
        val s = session
        if (s == null) {
            TunnelState.markFailed("数据面引擎未能启动（未返回会话句柄）")
            return START_NOT_STICKY
        }
        TunnelState.markUp(s)
        return START_STICKY
    }

    /**
     * 另一 VPN 应用抢占、或用户在系统设置里断开本 VPN 时系统回调。
     * ★改造前未覆盖：默认实现只 stopSelf，TunnelState 不会翻成失败——TUN fd 已失效，而 Go 引擎
     *   只在读写报错时才退出，UI 于是继续显示「已接入」直到不知何时。先把原因写下，再停服务。
     */
    override fun onRevoke() {
        TunnelState.markFailed("VPN 被系统或其它应用撤销")
        stopSelf()
    }

    override fun onDestroy() {
        session?.stop()
        session = null
        // onRevoke → stopSelf → onDestroy 这条链里，这里若无条件 markStopped，「被撤销」的原因会在
        // webview 下一次读 tunnelStatus（vpn.ts startTunnelWatch，接入后每 2s）之前就被冲回 idle——
        // 那边就只能显示「服务已不在运行」而不是被谁撤销的。用户主动断开走 MainActivity.stopTunnel 的 markStopped。
        TunnelState.markStoppedUnlessFailed()
        super.onDestroy()
    }
}
