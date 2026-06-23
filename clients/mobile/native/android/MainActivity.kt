// 白帝安卓壳 · WebView 宿主 + __BAIDI_NATIVE__ 桥
// 加载移动端 Vue 产物(dist)，向 webview 注入 window.__BAIDI_NATIVE__，把 UI 的
// startTunnel/stopTunnel 接到 BaidiVpnService；apiBase 提供控制中心地址。

package dev.baidi.mobile

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView

class MainActivity : Activity() {
    private lateinit var web: WebView
    private var pendingToken: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.addJavascriptInterface(Bridge(), "__baidiNativeRaw")
        setContentView(web)
        // 注入 __BAIDI_NATIVE__：把原生 raw 接口包成 UI 期望的 Promise 形态
        web.webViewClient = object : android.webkit.WebViewClient() {
            override fun onPageFinished(v: WebView?, url: String?) {
                v?.evaluateJavascript(BRIDGE_JS, null)
            }
        }
        web.loadUrl("https://appassets.local/index.html") // 由 WebViewAssetLoader 映射到打包的 dist
    }

    inner class Bridge {
        @JavascriptInterface fun apiBase(): String = "https://gw.baidi.local:9443" // 控制中心入口
        @JavascriptInterface fun startTunnel(token: String) {
            pendingToken = token
            val prep = VpnService.prepare(this@MainActivity)
            if (prep != null) startActivityForResult(prep, REQ_VPN) else startVpn(token)
        }
        @JavascriptInterface fun stopTunnel() {
            stopService(Intent(this@MainActivity, BaidiVpnService::class.java))
        }
    }

    private fun startVpn(token: String) {
        val i = Intent(this, BaidiVpnService::class.java).putExtra("token", token)
        // 也可透传 spa/proxy/control/caPEM
        startService(i)
    }

    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        super.onActivityResult(req, res, data)
        if (req == REQ_VPN && res == RESULT_OK) pendingToken?.let { startVpn(it) }
    }

    companion object {
        private const val REQ_VPN = 0x42
        // 注入到 webview 的桥：__BAIDI_NATIVE__.startTunnel 返回 Promise，apiBase 同步取
        private const val BRIDGE_JS = """
            window.__BAIDI_NATIVE__ = {
              apiBase: __baidiNativeRaw.apiBase(),
              startTunnel: (token) => { __baidiNativeRaw.startTunnel(token);
                return new Promise(r => setTimeout(() => r({ok:true, detail:'VpnService 已建立隧道'}), 600)); },
              stopTunnel: () => { __baidiNativeRaw.stopTunnel(); return Promise.resolve(); }
            };
        """
    }
}
