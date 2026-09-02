// 白帝安卓数据面运行态 · 进程内单例
//
// ★为什么需要它：桥的 startTunnel 是 @JavascriptInterface，返回 Unit——JS 侧结构上
// 拿不到任何结果。改造前 BRIDGE_JS 因此写成「600ms 后无条件 resolve {ok:true,
// detail:'VpnService 已建立隧道'}」，于是：用户拒绝 VPN 授权、TUN 建不出来、
// 引擎起不来、网关连不上……UI 一律显示「已接入企业内网」。
//
// baidimobile.Session 早就提供了 Running()/Reason()（注释明写"供移动端 UI 轮询观察终态"），
// 只是**全仓零消费方**。这个单例就是把那份真状态接出来的地方。
package dev.baidi.mobile

import baidimobile.Session

object TunnelState {
    /** 阶段：idle=未接入 / starting=已下发但尚未确认 / up=引擎在跑 / failed=起不来或已中断 */
    @Volatile var stage: String = "idle"
        private set

    /** 失败或中断的原因（可直接显示给用户）；运行中为空。 */
    @Volatile var reason: String = ""
        private set

    @Volatile private var session: Session? = null

    @Synchronized fun markStarting() {
        stage = "starting"; reason = ""; session = null
    }

    @Synchronized fun markUp(s: Session) {
        session = s; stage = "up"; reason = ""
    }

    /** 起不来（VPN 未授权 / TUN 建不出 / 引擎启动报错）。why 必须是人能照着做的一句话。 */
    @Synchronized fun markFailed(why: String) {
        session = null; stage = "failed"; reason = why
    }

    @Synchronized fun markStopped() {
        session?.stop(); session = null; stage = "idle"; reason = ""
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
        if (stage == "failed") { session?.stop(); session = null; return }
        markStopped()
    }

    /**
     * 当前真实状态。**每次都问引擎**（Session.Running()），不缓存——
     * 引擎因强制下线 / 账号禁用 / 终端合规阻断而停机时，stage 必须跟着翻，
     * 否则 UI 会一直显示「已接入」而隧道早就断了。
     */
    @Synchronized fun snapshot(): String {
        val s = session
        if (stage == "up" && s != null && !s.running()) {
            // 引擎自己停了：Reason() 带出可显示的原因（区别于用户主动断开）
            val r = s.reason()
            session = null
            stage = "failed"
            reason = if (r.isNullOrBlank()) "隧道已中断（原因未知）" else r
        }
        return """{"stage":${jsonString(stage)},"reason":${jsonString(reason)}}"""
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
