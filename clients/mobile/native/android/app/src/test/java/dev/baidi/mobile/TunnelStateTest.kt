// TunnelState 运行态的 JVM 单测。守四条：
//   ① 「onRevoke 写下的原因被 onDestroy 冲回 idle」；
//   ② 「snapshot() 对自由文本 reason 必须产出合法 JSON」；
//   ③ 【wave10】接入态判据是 ready（引擎在跑 ∧ 敲门成功 ∧ err 空），不是 stage=='up'；
//   ④ 【wave10】健康态不可判定时 ready 与六个 health* 键**整体缺席**，而不是 false/空串。
//
// ★这些用例能存在，靠的是 EngineHandle 这一层：baidimobile.Session 是 gobind 产出的
//   final + native 类，JVM 单测里造不出来也桩不掉——改造前 4 条用例**没有一条调用过 markUp**，
//   本波的判定若直接写进 snapshot()，会整段落进测不到的地方。理由详见 EngineHandle.kt 文件头。

package dev.baidi.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class TunnelStateTest {
    /** TunnelState 是进程内单例，用例之间会互相污染——每条用例从干净的 idle 开始。 */
    @Before fun reset() { TunnelState.markStopped() }

    // ──────────────────────────────────────────────────────────────────────
    // 既有四条：失败原因的留存与 JSON 合法性
    // ──────────────────────────────────────────────────────────────────────

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

    // ──────────────────────────────────────────────────────────────────────
    // wave10：ready 判据
    // ──────────────────────────────────────────────────────────────────────

    @Test fun engineUpButNeverKnockedIsNotReady() {
        // ★本次真机 bug 的回归钉之一：引擎刚起、还没敲过第一次门（observed=false）。
        //   改造前 BaidiVpnService 在 Baidimobile.start 返回后立刻 markUp("up")，桥据 stage=='up'
        //   回「数据面已就绪」——而此刻数据面连一次敲门都还没做过。
        //   observed=false 既不是"没问题"也不是"失败"，是"还没敲过第一次门"，处置是继续等。
        TunnelState.markEngineUp(FakeEngine(snap = health(observed = false)))
        val o = parseFlatJsonObject(TunnelState.snapshot())
        assertEquals("up", o["stage"])
        assertEquals(false, o["ready"])
        assertEquals(false, o["healthObserved"])
    }

    @Test fun realDeviceShape_engineUpKnockFailedWithX509() {
        // ★2026-09-03 OPPO PKU110 / Android 16 真机形态，逐字复现：
        //   桥回 {"stage":"up"}、startTunnel 回「数据面已就绪」，而 Go 健康行是
        //   knock=false tunnel=false err="取敲门令牌失败：… x509: certificate signed by unknown authority"。
        //   改造后 stage 仍是 up（引擎确实在跑、每 15s 自动重试，判成中断会把它真的断掉），
        //   但 ready=false，且**原文一个字不改**地随 healthErr 上到界面。
        //   原文里的反斜杠是有意的：Go 侧原样透传第三方错误串，转义漏了整份 JSON 就废了。
        val why = "取敲门令牌失败：Get \"https://ctl\\svc/knock-token\": x509: certificate signed by unknown authority"
        TunnelState.markEngineUp(FakeEngine(snap = health(observed = true, knockErr = why, err = why)))
        val raw = TunnelState.snapshot()
        val o = parseFlatJsonObject(raw)
        assertEquals("up", o["stage"])
        assertEquals(false, o["ready"])
        assertEquals(true, o["healthObserved"])
        assertEquals(false, o["healthKnock"])
        assertEquals(why, o["healthErr"])
        assertEquals(why, o["healthKnockErr"])
        assertEquals("", o["healthTunnelErr"])
    }

    @Test fun tunnelBitDoesNotGateReadiness() {
        // ★tunnel 位不参与判据的钉子：它是粘性位，Go 侧只在第一条业务流真拨通时置位，
        //   用户打开第一个应用之前恒 false。当必要条件的话接入会死锁在「接入中」——
        //   界面不让访问应用 → 永远产生不出第一条流 → 这一位永远不翻真（桌面端踩过）。
        //   连 tunnelErr 非空（曾拨号失败、后来敲门保活成功把 err 清了）也不该拦住就绪。
        TunnelState.markEngineUp(
            FakeEngine(snap = health(observed = true, knock = true, tunnel = false, tunnelErr = "落点拨不通", err = ""))
        )
        val o = parseFlatJsonObject(TunnelState.snapshot())
        assertEquals(true, o["ready"])
        assertEquals(false, o["healthTunnel"])
        assertEquals("落点拨不通", o["healthTunnelErr"])
    }

    @Test fun persistentTunnelFailureDoesNotFlipReadiness() {
        // ★判据用 knockErr 而不是合并后的 err（与桌面端 parseTunStatus 唯一的、刻意的分歧）。
        //   健康行的 err 是「最近一次被触碰的那一类的当前错误」：一次**隧道类**拨号失败会把它
        //   设上、下一次 15s 保活敲门又把它清掉。拿 err 当就绪判据，隧道类的持续故障
        //   （指纹不匹配 / 网关装了规则集却没带 -pf / gm 开关不一致）会让接入态以 15s 为周期
        //   反复翻，而每翻一次界面就弹一句「已接入企业内网」——正是本波要消灭的那类
        //   无根据断言换了个触发条件。手机上 WiFi↔LTE 一切就会命中这条路径。
        //   门确实敲开了，就该显示已接入；隧道拨不通另立一条常驻横幅（healthTunnelErr）。
        val dial = "隧道落点拨不通：dial tcp 10.0.0.9:18443: network is unreachable"
        TunnelState.markEngineUp(
            FakeEngine(snap = health(observed = true, knock = true, tunnel = false,
                tunnelErr = dial, err = dial))   // lastClass=tunnel → err 被隧道类占住
        )
        val o = parseFlatJsonObject(TunnelState.snapshot())
        assertEquals(true, o["ready"])
        assertEquals(dial, o["healthErr"])
        assertEquals(dial, o["healthTunnelErr"])
        // 敲门那一格干净 = 门是开着的，这才是就绪的判据
        assertEquals("", o["healthKnockErr"])
    }

    @Test fun notReadyReasonPrefersKnockClass() {
        // ★未就绪按定义就是敲门类那一格没过，原因就必须取那一格。先取 err 的话，一次与就绪
        //   判定无关的隧道类失败会把 err 占住 → 界面上「未就绪」的原因写着一条拨号错误，
        //   而真正挡住门的那句 x509 被压在后面看不见。归因指向哪儿，人就往哪儿查一轮。
        val knockWhy = "取敲门令牌失败：本机不信任控制中心的 HTTPS 证书"
        val h = health(observed = true, knock = false, tunnel = false,
            knockErr = knockWhy, tunnelErr = "落点拨不通", err = "落点拨不通")
        assertEquals(knockWhy, notReadyReasonOf(h))
    }

    @Test fun judgeReadyIsNullWhenHealthUndecidable() {
        // ★不可判定必须与"确定为假"分得开：h==null 回 null，绝不回 false。
        //   塌成 false 的话，任何一版拿不到健康行的壳（老 .aar / iOS / 鸿蒙）都会永远停在
        //   「接入中」直到 30s 超时，而它们此前是能正常接入的。
        assertNull(judgeReady(true, null))
        assertNull(judgeReady(false, null))
        assertEquals(true, judgeReady(true, health(observed = true, knock = true)))
        assertEquals(false, judgeReady(true, health(observed = true, knock = false)))
    }

    @Test fun undecidableHealthOmitsTheWholeGroup() {
        // 引擎在跑、但 Session.health() 回 null（Go 侧无健康载体 / 老 .aar）：
        // ★ready 与六个 health* **整体缺席**，不是 false、不是空串——桥据「键缺席」回落到
        //   旧判据 stage=='up'，行为与改造前逐字一致。发一个 ready:false 出去的话，
        //   那些壳会被自己这一版的新键判死在「接入中」。
        TunnelState.markEngineUp(FakeEngine(snap = null))
        val raw = TunnelState.snapshot()
        assertEquals("""{"stage":"up","reason":""}""", raw)
        assertEquals(setOf("stage", "reason"), parseFlatJsonObject(raw).keys)
    }

    @Test fun noEngineOmitsTheWholeGroupAndStaysValidJson() {
        // 无 session（idle / starting）：同样整体缺席，且 JSON 仍合法（严格解析器认这一点）。
        TunnelState.markStarting()
        val raw = TunnelState.snapshot()
        assertEquals("""{"stage":"starting","reason":""}""", raw)
        assertEquals(setOf("stage", "reason"), parseFlatJsonObject(raw).keys)
    }

    @Test fun stoppedEngineIsNeverReadyEvenThoughKnockBitIsSticky() {
        // ★running 必须参与判据：健康位是粘性的，引擎停机后那份快照仍报 knock=true、err 空。
        //   只看健康位会把一条已经断掉的隧道判成「已就绪」——正是本波要消灭的方向。
        TunnelState.markEngineUp(
            FakeEngine(alive = false, stopReason = "接入被拒：账号已禁用",
                snap = health(observed = true, knock = true, err = ""))
        )
        val o = parseFlatJsonObject(TunnelState.snapshot())
        assertEquals("failed", o["stage"])
        assertEquals("接入被拒：账号已禁用", o["reason"])
        assertEquals(false, o["ready"])
    }

    @Test fun snapshotReadsRunningAndHealthExactlyOnce() {
        // ★一次调用同时取 running() 与 health()，各一次。分两次读会撕裂：判 stage 时读到的
        //   knock 位与拼 JSON 时读到的 err 来自不同瞬间，界面上会出现「已就绪」配着一句陈年
        //   错误（或反过来），而这种错在界面上完全看不出来。
        val e = FakeEngine(snap = health(observed = true, knock = true))
        TunnelState.markEngineUp(e)
        TunnelState.snapshot()
        assertEquals(1, e.runningReads)
        assertEquals(1, e.healthReads)
    }

    // ──────────────────────────────────────────────────────────────────────
    // wave10：销毁时不得吃掉已经知道的未就绪原因
    // ──────────────────────────────────────────────────────────────────────

    @Test fun destroyWhileUnreadyKeepsTheKnockFailureReason() {
        // ★引擎在跑、门一直没敲开，此时被系统回收：回 idle 的话，全链路上唯一那句能指导补救的
        //   原文就此消失，用户只拿到「服务已不在运行」——它与"被系统回收"完全同形，
        //   人会去重启手机、重装应用。
        val why = "本机不信任控制中心的 HTTPS 证书（按部署脚本装出来的控制面用的是自签证书）"
        TunnelState.markEngineUp(FakeEngine(snap = health(observed = true, knockErr = why, err = why)))
        TunnelState.markStoppedUnlessFailed()
        val o = parseFlatJsonObject(TunnelState.snapshot())
        assertEquals("failed", o["stage"])
        assertTrue("原因必须原文带出：${o["reason"]}", (o["reason"] as String).contains(why))
    }

    @Test fun destroyBeforeFirstHealthLineStillGoesIdle() {
        // ★observed=false（引擎刚起、健康行还没写出来）不是失败：照旧回 idle。
        //   拿"还没来得及"当故障报给用户，与凭空编一个成因没有区别。
        TunnelState.markEngineUp(FakeEngine(snap = health(observed = false)))
        TunnelState.markStoppedUnlessFailed()
        assertEquals("""{"stage":"idle","reason":""}""", TunnelState.snapshot())
    }

    @Test fun destroyWhileReadyGoesIdleEvenWithStickyTunnelError() {
        // ★守 markStoppedUnlessFailed 里「ready 判假」那半个条件：tunnelErr 是粘性的，
        //   一条敲通了、只是某次拨隧道失败过的健康接入，被用户断开时必须回 idle，
        //   不能凭那条陈年 tunnelErr 报成「数据面未就绪即被停止」。
        TunnelState.markEngineUp(
            FakeEngine(snap = health(observed = true, knock = true, tunnelErr = "落点拨不通", err = ""))
        )
        TunnelState.markStoppedUnlessFailed()
        assertEquals("""{"stage":"idle","reason":""}""", TunnelState.snapshot())
    }

    // ──────────────────────────────────────────────────────────────────────
    // 辅助
    // ──────────────────────────────────────────────────────────────────────

    /** 只填关心的那几项，其余取「健康、无错」的默认值——让每条用例的断言点一眼可见。 */
    private fun health(
        observed: Boolean = true,
        knock: Boolean = false,
        tunnel: Boolean = false,
        knockErr: String = "",
        tunnelErr: String = "",
        err: String = ""
    ) = HealthLite(observed, knock, tunnel, knockErr, tunnelErr, err)

    /** 内存假引擎。顺带记下读取次数，用来钉「一次调用只读一次」。 */
    private class FakeEngine(
        var alive: Boolean = true,
        var stopReason: String = "",
        var snap: HealthLite? = null
    ) : EngineHandle {
        var runningReads = 0
        var healthReads = 0
        var stopped = false
        override fun running(): Boolean { runningReads++; return alive }
        override fun reason(): String = stopReason
        override fun health(): HealthLite? { healthReads++; return snap }
        override fun stop() { stopped = true }
    }

    /**
     * 最小 JSON 解析器：只认 `{"k":<字符串|true|false>,...}` 这种扁平对象，任何偏差即抛——
     * 它比 org.json 更严（不接受尾逗号 / 单引号 / 未转义控制字符），正好用来断言「合法」。
     * ★wave10 加了布尔值：ready 与三个 health 布尔位是真布尔，编成 `"false"` 的话
     *   webview 侧 `typeof s.ready === 'boolean'` 那道闸会判成不可判定，整组键等于白发。
     */
    private fun parseFlatJsonObject(s: String): Map<String, Any> {
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
        fun value(): Any {
            if (i < s.length && s[i] == '"') return str()
            if (s.startsWith("true", i)) { i += 4; return true }
            if (s.startsWith("false", i)) { i += 5; return false }
            throw AssertionError("位置 $i 处既不是字符串也不是布尔（本契约只有这两种）：$s")
        }
        val out = LinkedHashMap<String, Any>()
        expect('{')
        if (s[i] == '}') { i++; return out }
        while (true) {
            val k = str(); expect(':'); out[k] = value()
            if (s[i] == ',') { i++; continue }
            expect('}'); break
        }
        if (i != s.length) throw AssertionError("对象后有多余内容：$s")
        return out
    }
}
