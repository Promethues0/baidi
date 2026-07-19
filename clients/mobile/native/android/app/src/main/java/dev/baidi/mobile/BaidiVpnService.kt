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
        val token = intent?.getStringExtra("token") ?: return START_NOT_STICKY
        // UI 下传的接入配置（gateway/spaPort/proxyPort/route/ip/gm/control）；缺省回退演示值
        val c = try { JSONObject(intent.getStringExtra("cfg") ?: "{}") } catch (e: Exception) { JSONObject() }
        val gateway = c.optString("gateway", "gw.baidi.local")
        val spaPort = c.optString("spaPort", "18201")
        val proxyPort = c.optString("proxyPort", "18443")
        val route = c.optString("route", "10.99.0.0/24")
        val vip = c.optString("ip", "10.99.0.2")
        val gmOn = c.optBoolean("gm", true)
        val ctl = c.optString("control", "")
        val net = route.split("/")
        val netAddr = net.getOrElse(0) { "10.99.0.0" }
        val prefix = net.getOrElse(1) { "24" }.toIntOrNull() ?: 24

        // 1) 建立 TUN：虚拟 IP + 把受保护网段（来自配置）路由进来
        val pfd = Builder()
            .setSession("白帝安全接入")
            .setMtu(1420)
            .addAddress(vip, 32)
            .addRoute(netAddr, prefix)
            .establish() ?: return START_NOT_STICKY

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
        }
        // detachFd()：把 fd 所有权交给 Go（引擎负责关闭）
        session = Baidimobile.start(pfd.detachFd().toLong(), cfg)
        return START_STICKY
    }

    override fun onDestroy() {
        session?.stop()
        session = null
        super.onDestroy()
    }
}
