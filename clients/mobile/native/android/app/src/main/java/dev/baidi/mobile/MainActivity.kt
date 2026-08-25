// 白帝安卓壳 · WebView 宿主 + __BAIDI_NATIVE__ 桥
// 加载移动端 Vue 产物(dist)，向 webview 注入 window.__BAIDI_NATIVE__，把 UI 的
// startTunnel/stopTunnel 接到 BaidiVpnService；apiBase 提供控制中心地址。

package dev.baidi.mobile

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat

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
        // WebViewAssetLoader：https://appassets.local/ → app assets 根（dist 平铺其中）
        val assets = WebViewAssetLoader.Builder()
            .setDomain("appassets.local")
            .addPathHandler("/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()
        web.webViewClient = object : WebViewClientCompat() {
            override fun shouldInterceptRequest(v: WebView, req: WebResourceRequest): WebResourceResponse? =
                assets.shouldInterceptRequest(req.url)
            override fun onPageFinished(v: WebView?, url: String?) {
                v?.evaluateJavascript(BRIDGE_JS, null)
            }
        }
        web.loadUrl("https://appassets.local/index.html") // 由 WebViewAssetLoader 映射到打包的 dist
    }

    private var pendingCfg: String? = null

    inner class Bridge {
        @JavascriptInterface fun apiBase(): String = BuildConfig.BAIDI_API_BASE // 控制中心入口
        // cfgJson = UI 下传的接入配置（gateway/spaPort/proxyPort/route/ip/gm/control）
        @JavascriptInterface fun startTunnel(token: String, cfgJson: String) {
            pendingToken = token
            pendingCfg = cfgJson
            TunnelState.markStarting()
            val prep = VpnService.prepare(this@MainActivity)
            if (prep != null) startActivityForResult(prep, REQ_VPN) else startVpn(token, cfgJson)
        }
        @JavascriptInterface fun stopTunnel() {
            stopService(Intent(this@MainActivity, BaidiVpnService::class.java))
            TunnelState.markStopped()
        }
        /** 当前**真实**运行态，JSON：{"stage":"idle|starting|up|failed","reason":"..."}。
         *  UI 轮询它来判断接入是否成功——而不是像改造前那样在 600ms 后假定成功。 */
        @JavascriptInterface fun tunnelStatus(): String = TunnelState.snapshot()
    }

    // 把 UI 配置透传给 VpnService：路由/虚拟IP/网关/国密由 cfg 决定，不再在原生侧写死
    private fun startVpn(token: String, cfgJson: String?) {
        val i = Intent(this, BaidiVpnService::class.java)
            .putExtra("token", token)
            .putExtra("cfg", cfgJson)
        startService(i)
    }

    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        super.onActivityResult(req, res, data)
        if (req == REQ_VPN && res == RESULT_OK) pendingToken?.let { startVpn(it, pendingCfg) }
    }

    companion object {
        private const val REQ_VPN = 0x42
        // 注入到 webview 的桥：startTunnel(token, cfg) 把配置 JSON 化下传，返回 Promise；apiBase 同步取
        // ★startTunnel 不再"600ms 后无条件说成功"。@JavascriptInterface 返回 Unit，
        //   JS 侧结构上拿不到结果，所以改成：下发之后**轮询真实状态**（tunnelStatus），
        //   直到引擎确认在跑（up）、或明确失败（failed）、或超时。
        //   改造前那种写法会让「用户拒绝 VPN 授权 / TUN 建不出 / 引擎起不来 / 网关连不上」
        //   全都显示成「已接入企业内网」——移动端最严重的一处静默失效。
        private const val BRIDGE_JS = """
            window.__BAIDI_NATIVE__ = {
              apiBase: __baidiNativeRaw.apiBase(),
              tunnelStatus: () => { try { return JSON.parse(__baidiNativeRaw.tunnelStatus()); }
                                    catch (e) { return { stage: 'failed', reason: '读取隧道状态失败' }; } },
              startTunnel: (token, cfg) => {
                __baidiNativeRaw.startTunnel(token, JSON.stringify(cfg || {}));
                // 轮询真实状态：VPN 授权对话框要用户点，故给 30s；引擎起来即 up。
                return new Promise((resolve) => {
                  const t0 = Date.now();
                  const tick = () => {
                    const s = window.__BAIDI_NATIVE__.tunnelStatus();
                    if (s.stage === 'up') return resolve({ ok: true, detail: '数据面已就绪' });
                    if (s.stage === 'failed') return resolve({ ok: false, detail: s.reason || '接入失败' });
                    if (Date.now() - t0 > 30000)
                      return resolve({ ok: false, detail: '接入超时：系统未确认 VPN 已建立（是否未授予 VPN 权限？）' });
                    setTimeout(tick, 400);
                  };
                  tick();
                });
              },
              stopTunnel: () => { __baidiNativeRaw.stopTunnel(); return Promise.resolve(); }
            };
        """
    }
}
