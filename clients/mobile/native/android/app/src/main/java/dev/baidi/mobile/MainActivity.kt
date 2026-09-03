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
        /** 当前**真实**运行态，JSON：
         *  `{"stage":"idle|starting|up|failed","reason":"...", ready?, health*?}`。
         *  UI 轮询它来判断接入是否成功——而不是像改造前那样在 600ms 后假定成功。
         *
         *  ★stage 只回答「引擎在不在跑」，`ready` 才回答「门敲没敲开」；后者**整组键在
         *  不可判定时缺席**（键的完整清单与理由见 TunnelState.snapshot 的注释）。 */
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
        if (req != REQ_VPN) return
        if (res == RESULT_OK) {
            pendingToken?.let { startVpn(it, pendingCfg) }
        } else {
            // ★用户在系统 VPN 授权对话框点了「取消」（或对话框被系统关掉）：改造前这个分支什么都不做，
            //   UI 只能等桥 30s 超时后猜一句成因。现在立即写下真实原因。
            TunnelState.markFailed("用户拒绝了 VPN 授权（系统对话框未允许），请重新接入并在对话框中选择允许")
        }
    }

    companion object {
        private const val REQ_VPN = 0x42
        // 注入到 webview 的桥：startTunnel(token, cfg) 把配置 JSON 化下传，返回 Promise；apiBase 同步取
        // ★startTunnel 不再"600ms 后无条件说成功"。@JavascriptInterface 返回 Unit，
        //   JS 侧结构上拿不到结果，所以改成：下发之后**轮询真实状态**（tunnelStatus），
        //   直到引擎确认在跑（up）、或明确失败（failed）、或超时。
        //   改造前那种写法会让「用户拒绝 VPN 授权 / TUN 建不出 / 引擎起不来 / 网关连不上」
        //   全都显示成「已接入企业内网」——移动端最严重的一处静默失效。
        // ★wave10：成功的判据从 `stage === 'up'` 换成 `ready === true`。
        //   2026-09-03 安卓真机（OPPO PKU110 / Android 16）实测，同一时刻这里 resolve
        //   「数据面已就绪」，而 Go 健康行是 knock=false err="取敲门令牌失败：… x509:
        //   certificate signed by unknown authority"——**引擎起来了、门没敲开，界面显示已接入**。
        //   stage=='up' 只证明 netstack 装起来了，它对敲门一个字都没说。
        //   下面 `ready === undefined` 那一支是**旧壳回落**：健康态不可判定时（老 .aar /
        //   iOS / 鸿蒙壳）逐字保留旧判据，行为一字不变——不这么写的话，任何一版拿不到
        //   健康行的壳都会停在这里直到 30s 超时，而它们此前是能正常接入的。
        // ★tunnelStatus 解析不出来时回 **null（不可判定）**，绝不合成一个 stage=failed 的状态。
        //   改造前那句合成把「读不到状态」塌缩成「确定失败」，后果不是少显示一条信息而是**反向动作**：
        //   接入后 vpn.ts 每 2s 读一次同一个方法（startTunnelWatch），拿到 failed 就判成中断——
        //   翻 session.connected=false、写 dropReason、并主动 stopTunnel **把一条好好的隧道真的断掉**。
        //   而 tunnelwatch.ts 开篇声明的「读不到不下结论」那条分支，因为桥永远给得出 failed，从来走不到。
        //   （能读不出来的场景是真实存在的：reason 里拼了剖面下发的原文，含控制字符时曾产不出合法 JSON——
        //   jsonString() 已修，但"桥抛错/JS 接口被系统回收"这类仍会让这一轮读不到。）
        private const val BRIDGE_JS = """
            window.__BAIDI_NATIVE__ = {
              apiBase: __baidiNativeRaw.apiBase(),
              tunnelStatus: () => { try { return JSON.parse(__baidiNativeRaw.tunnelStatus()); }
                                    catch (e) { return null; } },
              startTunnel: (token, cfg) => {
                __baidiNativeRaw.startTunnel(token, JSON.stringify(cfg || {}));
                // 轮询真实状态：VPN 授权对话框要用户点，故给 30s；引擎起来即 up。
                return new Promise((resolve) => {
                  const t0 = Date.now();
                  let last = '';
                  let lastWhy = '';
                  const tick = () => {
                    const s = window.__BAIDI_NATIVE__.tunnelStatus();
                    // s 为 null = 这一轮读不到：**继续等**。授权对话框还开着时读不到状态是常态，
                    // 判成失败会让一次正常接入在用户点「允许」之前就被判死。
                    if (s) {
                      last = s.stage;
                      // 原生已知的未就绪原因（健康行原文，例如那句 x509）。只记不判：
                      // 门每 15s 自动重试，随时可能自愈，这一轮有原因不代表这次接入失败。
                      lastWhy = s.healthKnockErr || s.healthErr || '';  // knockErr 优先：挡住门的就是它那一格，与 notReadyReason 同序
                      if (s.ready === true) return resolve({ ok: true, detail: '数据面已就绪' });
                      // 旧壳回落：ready 键**缺席**才走旧判据。必须判 undefined 而不是 falsy——
                      // ready === false 是「引擎在跑、门没敲开」，它要继续等（等自愈或等超时把
                      // 原因带出去），当成"没有这个键"就又变回了改造前那句无依据的「已就绪」。
                      if (s.ready === undefined && s.stage === 'up')
                        return resolve({ ok: true, detail: '数据面已就绪' });
                      if (s.stage === 'failed') return resolve({ ok: false, detail: s.reason || '接入失败' });
                    }
                    // 超时只报**观测到的事实**，不猜成因：授权被拒现在由 onActivityResult 当场
                    // markFailed（上面 failed 分支即刻拿到真实原因），这里再猜一句「是否未授权」只会误导。
                    // ★带上 lastWhy 与这条纪律不冲突：**转述原生已经知道的原因 ≠ 替它猜一个成因**。
                    //   猜的是「大概是没授权吧」这种本地推断；lastWhy 是数据面自己写下的那句话
                    //   （「本机不信任控制中心的 HTTPS 证书…把根证书导入…」），而这一行就是它
                    //   **第一次能上到界面**——改造前它只活在 logcat 里，用户面前只有「接入超时」。
                    if (Date.now() - t0 > 30000)
                      return resolve({ ok: false, detail: last
                        ? '接入超时：30 秒内原生侧未确认数据面就绪（最后读到的阶段：' + last + '）'
                          + (lastWhy ? '；数据面报告：' + lastWhy : '')
                        : '接入超时：30 秒内读不到原生运行态（桥返回的状态无法解析）' });
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
