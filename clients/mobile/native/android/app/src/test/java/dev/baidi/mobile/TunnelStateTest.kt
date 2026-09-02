// TunnelState 运行态的 JVM 单测：守「onRevoke 写下的原因被 onDestroy 冲回 idle」与
// 「snapshot() 对自由文本 reason 必须产出合法 JSON」两条。

package dev.baidi.mobile

import org.junit.Assert.assertEquals
import org.junit.Test

class TunnelStateTest {
    @Test fun revokedReasonSurvivesServiceDestroy() {
        // BaidiVpnService.onRevoke → stopSelf → onDestroy 这条链
        TunnelState.markStarting()
        TunnelState.markFailed("VPN 被系统或其它应用撤销")
        TunnelState.markStoppedUnlessFailed()
        assertEquals("""{"stage":"failed","reason":"VPN 被系统或其它应用撤销"}""", TunnelState.snapshot())
    }

    @Test fun plainDestroyGoesIdle() {
        TunnelState.markStarting()
        TunnelState.markStoppedUnlessFailed()
        assertEquals("""{"stage":"idle","reason":""}""", TunnelState.snapshot())
    }

    @Test fun explicitStopClearsEvenAFailure() {
        // 用户主动断开（MainActivity.stopTunnel）仍是无条件回 idle：下一次接入从干净状态开始
        TunnelState.markFailed("x")
        TunnelState.markStopped()
        assertEquals("""{"stage":"idle","reason":""}""", TunnelState.snapshot())
    }

    @Test fun reasonWithBackslashNewlineQuoteStaysValidJson() {
        // BaidiVpnService 把剖面下发的 route 原文整段拼进 reason：「受保护网段配置无效：…（下发原文：$route）」。
        // 改造前只转义双引号，原文含 \ 或换行时桥侧 JSON.parse 抛错，点名的原因被吞成「读取隧道状态失败」。
        val why = "受保护网段配置无效：网段「a\\b」不是 地址/前缀 形式（下发原文：a\\b\n\"c\"\t\u0001）"
        TunnelState.markFailed(why)
        val raw = TunnelState.snapshot()
        // 1) 转义后的字面量逐字符可预期（\n \r \t 短转义，其余控制字符 \uXXXX）
        assertEquals(
            "\"受保护网段配置无效：网段「a\\\\b」不是 地址/前缀 形式（下发原文：a\\\\b\\n\\\"c\\\"\\t\\u0001）\"",
            jsonString(why)
        )
        // 2) 整份 snapshot 是合法 JSON 且解析回同一串（android.jar 在 JVM 单测里是桩，org.json 不可用，故手写最小解析）
        val obj = parseFlatJsonObject(raw)
        assertEquals("failed", obj["stage"])
        assertEquals(why, obj["reason"])
        TunnelState.markStopped()
    }

    /**
     * 最小 JSON 解析器：只认 `{"k":"v",...}` 这种扁平字符串对象，任何偏差即抛——
     * 它比 org.json 更严（不接受尾逗号 / 单引号 / 未转义控制字符），正好用来断言「合法」。
     */
    private fun parseFlatJsonObject(s: String): Map<String, String> {
        var i = 0
        fun expect(c: Char) { if (i >= s.length || s[i] != c) throw AssertionError("位置 $i 期望 '$c'：$s"); i++ }
        fun str(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                if (i >= s.length) throw AssertionError("字符串未闭合：$s")
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (i >= s.length) throw AssertionError("转义截断：$s")
                        when (val e = s[i++]) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'n' -> sb.append('\n'); 'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000C')
                            'u' -> { sb.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                            else -> throw AssertionError("非法转义 \\$e：$s")
                        }
                    }
                    c < ' ' -> throw AssertionError("字符串里出现未转义控制字符 U+%04X：$s".format(c.code))
                    else -> sb.append(c)
                }
            }
        }
        val out = LinkedHashMap<String, String>()
        expect('{')
        if (s[i] == '}') { i++; return out }
        while (true) {
            val k = str(); expect(':'); out[k] = str()
            if (s[i] == ',') { i++; continue }
            expect('}'); break
        }
        if (i != s.length) throw AssertionError("对象后有多余内容：$s")
        return out
    }
}
