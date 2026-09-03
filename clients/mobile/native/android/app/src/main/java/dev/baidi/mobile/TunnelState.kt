// 白帝安卓数据面运行态 · 进程内单例
//
// ★为什么需要它：桥的 startTunnel 是 @JavascriptInterface，返回 Unit——JS 侧结构上
// 拿不到任何结果。改造前 BRIDGE_JS 因此写成「600ms 后无条件 resolve {ok:true,
// detail:'VpnService 已建立隧道'}」，于是：用户拒绝 VPN 授权、TUN 建不出来、
// 引擎起不来、网关连不上……UI 一律显示「已接入企业内网」。
//
// baidimobile.Session 早就提供了 Running()/Reason()（注释明写"供移动端 UI 轮询观察终态"），
// 只是**全仓零消费方**。这个单例就是把那份真状态接出来的地方。
//
// ★wave10 补的第二件事实（2026-09-03 安卓真机 OPPO PKU110 / Android 16 实测）：
// 同一时刻桥回 {"stage":"up"}、startTunnel 回「数据面已就绪」，而 Go 健康行是
// `knock=false tunnel=false err="取敲门令牌失败：… x509: certificate signed by unknown authority"`
// ——**引擎起来了、门没敲开，界面却显示已接入**。根因是这个文件只问了 Running()：
// 那一位说的是「netstack 装起来了没有」，它对「门敲没敲开」一个字都没说。
// 现在 snapshot() 额外下发一组并列的健康键（见下方 snapshot 注释）。
package dev.baidi.mobile

import baidimobile.Session

object TunnelState {
    /**
     * 阶段：idle=未接入 / starting=已下发但尚未确认 / up=**引擎在跑** / failed=起不来或已中断。
     *
     * ★up 的语义在 wave10 收紧为「引擎在跑，**不代表门已敲开**」。真正的可用性由并列的
     *   `ready` 表达（见 snapshot）——中间态就是 {stage:"up", ready:false}。
     *
     * ★**值域一字不改**（idle|starting|up|failed）。给它加第五个值（如 unready）会让三处立刻误判：
     *   ① clients/mobile/src/lib/tunnelwatch.ts 的 judgeTunnelStatus 走 default 虽不误伤，但只要
     *      有人图省事把新值并进 failed/idle，vpn.ts 就会去 stopTunnel，把一条**每 15s 自动重试、
     *      随时可能自愈**的隧道真的断掉（自愈性证据：gateway/internal/dataplane 的 knockOne 对非
     *      403 失败只 slog.Warn + markKnockFail 后 return false，Run 继续阻塞，reknock ticker 每 15s 重试）；
     *   ② vpn.ts 的 adoptRunningTunnel 只认 'up'，新值会掉进「什么都不做」，webview 重建后
     *      一条在跑的 VPN 无人监视；
     *   ③ MainActivity 的桥 BRIDGE_JS 判 `s.stage === 'up'` 才算接入成功，新值会一路等到 30s 超时。
     *   这份四态字典被 tunnelwatch.ts 与 MainActivity.kt 逐字引用，**三处同步**。
     */
    @Volatile var stage: String = "idle"
        private set

    /** 失败或中断的原因（可直接显示给用户）；运行中为空。 */
    @Volatile var reason: String = ""
        private set

    /** 数据面引擎句柄。经 [EngineHandle] 而不是直接握 baidimobile.Session——理由见 EngineHandle.kt 文件头。 */
    @Volatile private var engine: EngineHandle? = null

    @Synchronized fun markStarting() {
        stage = "starting"; reason = ""; engine = null
    }

    /**
     * **引擎已起**（Baidimobile.start 返回了会话句柄）。
     *
     * ★改造前这个方法叫 markUp，名字读起来像「接入成功了」，而它能证明的只有
     *   「netstack 装起来了」。BaidiVpnService 在 start 返回后立刻调它、桥再据 stage=='up'
     *   回「数据面已就绪」——真机上那句 x509 敲门失败就是这样一路被盖成绿色的。
     *   改名不是洁癖：这个方法只有一个调用点（BaidiVpnService），名字是它唯一的说明书。
     */
    @Synchronized fun markEngineUp(s: Session) = markEngineUp(SessionHandle(s))

    /** 同上；单测用（生产调用点一律走上面那个 Session 重载）。 */
    @Synchronized internal fun markEngineUp(h: EngineHandle) {
        engine = h; stage = "up"; reason = ""
    }

    /** 起不来（VPN 未授权 / TUN 建不出 / 引擎启动报错）。why 必须是人能照着做的一句话。 */
    @Synchronized fun markFailed(why: String) {
        engine = null; stage = "failed"; reason = why
    }

    @Synchronized fun markStopped() {
        engine?.stop(); engine = null; stage = "idle"; reason = ""
    }

    /**
     * 服务销毁时调：**只有没有待展示的失败原因时**才回 idle。
     * BaidiVpnService.onRevoke → stopSelf → onDestroy 这条链里，若 onDestroy 无条件 markStopped，
     * 「VPN 被系统或其它应用撤销」会在 webview 下一次读 tunnelStatus 之前就被冲成 idle——
     * 读端是 vpn.ts 的 startTunnelWatch（接入后每 2s 一次；启动期是桥里 400ms 的那个轮询），
     * 它只把 failed 的 reason 原样显示；冲成 idle 后它只能说「服务已不在运行」而说不出为什么。
     * 用户主动断开走 MainActivity.stopTunnel 的 markStopped。
     */
    @Synchronized fun markStoppedUnlessFailed() {
        if (stage == "failed") { engine?.stop(); engine = null; return }
        // ★wave10 补的第二种"带着原因被销毁"：引擎在跑、门一直没敲开（真机上那句 x509），
        //   此时被系统回收 / 用户切走。回 idle 的话，**全链路上唯一那句能指导补救的原文**
        //   （「本机不信任控制中心的 HTTPS 证书…把根证书导入…」）就此消失，用户只拿到
        //   一句「服务已不在运行」，然后去重启手机、重装应用——它与"被系统回收"完全同形。
        //   与上面那条 failed 分支是同一条纪律：销毁不该吃掉已经知道的原因。
        val e = engine
        if (stage == "up" && e != null) {
            val h = e.health()
            val why = notReadyReasonOf(h)
            // ★两个条件缺一不可：
            //   · ready 判假——ready 为真时 err 必空，但 tunnelErr 是粘性的**可能非空**
            //     （敲通了、某次拨隧道失败过），只看 why 会把一条好好的隧道说成失败；
            //   · why 非空——observed=false（引擎刚起还没写出健康行）不是失败，
            //     那种情况照旧回 idle，别拿"还没来得及"当故障报给用户。
            if (judgeReady(e.running(), h) == false && why.isNotEmpty()) {
                e.stop(); engine = null
                stage = "failed"
                reason = "数据面未就绪即被停止：$why"
                return
            }
        }
        markStopped()
    }

    /**
     * 当前真实状态，JSON。**每次都问引擎**，不缓存——引擎因强制下线 / 账号禁用 /
     * 终端合规阻断而停机时，stage 必须跟着翻，否则 UI 会一直显示「已接入」而隧道早就断了。
     *
     * 产出的键（**扁平，不嵌套**，三轨逐字一致的跨语言契约，读端是
     * clients/mobile/src/lib/tunnelwatch.ts 的 TunnelStatus）：
     *   {"stage":"up","reason":"","ready":false,
     *    "healthObserved":true,"healthKnock":false,"healthTunnel":false,
     *    "healthKnockErr":"…","healthTunnelErr":"","healthErr":"…"}
     *
     * ★`ready` 与六个 `health*` 在**健康态不可判定时整体缺席**（不是 false、不是空串）：
     *   「读不到」与「确定没问题」的处置相反——前者让桥回落到旧判据（老 .aar / 没有健康载体的
     *   会话照旧能接入），后者要把失败原文顶到界面上。塌成同形是本仓反复批判的形态。
     *   键缺席这个表达方式是扁平 JSON 天然给的；嵌套成 "health":{...} 还要再约定一次
     *   「对象存在但里面全空」算什么，而且 JVM 单测里 org.json 用不了（android.jar 是桩，
     *   JSONObject 一调就抛「Method … not mocked」），手写解析器认扁平键最省事。
     *
     * ★`running()` 与 `health()` **在同一次调用里一起取**，各取一次。分两次读（比如判 stage
     *   时读一次、拼 JSON 时再读一次）会撕裂：knock 位已经翻新、err 还是上一轮的旧值，
     *   于是界面上出现「已就绪」配着一句陈年错误，或者反过来——而这种错在界面上完全看不出来。
     */
    @Synchronized fun snapshot(): String {
        val e = engine
        // 一次调用，两项事实同源。顺序无所谓，"只读一次"才是要点。
        val running = e?.running()
        val health = e?.health()

        if (stage == "up" && e != null && running == false) {
            // 引擎自己停了：Reason() 带出可显示的原因（区别于用户主动断开）
            val r = e.reason()
            engine = null
            stage = "failed"
            reason = if (r.isBlank()) "隧道已中断（原因未知）" else r
        }

        val sb = StringBuilder()
        sb.append("""{"stage":${jsonString(stage)},"reason":${jsonString(reason)}""")
        // judgeReady 回 null 就是"不可判定"，此时整组键一个都不发（见上）。
        // health != null 是 ready != null 的充要条件（见 judgeReady），这里两个都判是为了
        // 让"整组同进同退"在结构上成立，而不是靠读者去推。
        val ready = if (running != null) judgeReady(running, health) else null
        if (ready != null && health != null) {
            sb.append(""","ready":$ready""")
            sb.append(""","healthObserved":${health.observed}""")
            sb.append(""","healthKnock":${health.knock}""")
            sb.append(""","healthTunnel":${health.tunnel}""")
            sb.append(""","healthKnockErr":${jsonString(health.knockErr)}""")
            sb.append(""","healthTunnelErr":${jsonString(health.tunnelErr)}""")
            sb.append(""","healthErr":${jsonString(health.err)}""")
        }
        return sb.append('}').toString()
    }
}

/**
 * 把任意字符串编成 JSON 字符串字面量（含两侧引号）。纯 Kotlin，不依赖 org.json——
 * JVM 单测里 android.jar 是打桩的，`JSONObject` 一调就抛「Method … not mocked」。
 *
 * ★改造前 snapshot() 只转义双引号。reason 里的自由文本是会带别的字符的：
 *   「受保护网段配置无效：…（下发原文：$route）」把剖面下发的原文整段拼进来，原文含反斜杠、
 *   换行或控制字符时产出的就不是合法 JSON，桥里 `JSON.parse` 抛错 → 兜底成
 *   「读取隧道状态失败」——点名了是哪一条网段不合法的那句话，恰好在最需要它的时候被吞掉。
 *   健康行里的 err/knockErr 是同一类自由文本（Go 侧原样透传的第三方错误串），同此纪律。
 * 规则按 RFC 8259 §7：`\` `"` 必转，\n \r \t 用短转义，其余 <0x20 控制字符一律 \uXXXX。
 */
internal fun jsonString(s: String): String {
    val sb = StringBuilder(s.length + 2).append('"')
    for (ch in s) {
        when {
            ch == '\\' -> sb.append("\\\\")
            ch == '"' -> sb.append("\\\"")
            ch == '\n' -> sb.append("\\n")
            ch == '\r' -> sb.append("\\r")
            ch == '\t' -> sb.append("\\t")
            ch < ' ' -> sb.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
            else -> sb.append(ch)
        }
    }
    return sb.append('"').toString()
}
