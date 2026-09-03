// 白帝安卓壳 · 数据面引擎的可测抽象 + 「就绪」判据
//
// ★为什么要在 TunnelState 与 gomobile 生成的 Session 之间插一层：
//   `baidimobile.Session` 是 gobind 产出的 `public final class`，构造函数只接一个 refnum、
//   每个方法都是 `native`——JVM 单测里既造不出来也桩不掉（android.jar 是打桩的，JNI 更没得跑）。
//   现有 TunnelStateTest 的 4 条用例**没有一条调用过 markUp**，正是因为入参造不出来。
//   本波要加的判定（引擎在跑 ∧ 敲门成功 ∧ err 空）如果直接写在 snapshot() 里，会整段落进
//   测不到的地方——那正是「新逻辑没有任何执行方能验」的老形态。
//   同 clients/desktop/src-tauri/src/posture.rs 把采集逻辑抽在 Env trait 后面那条纪律
//   （见 CLAUDE.md「采集三态」：只活在 #[cfg] 里的分支在 mac 上连语法都验不到）。
package dev.baidi.mobile

import baidimobile.HealthReport
import baidimobile.Session

/**
 * 数据面引擎在壳这一侧需要的**全部**能力。生产实现是 [SessionHandle]（包 gomobile 的 Session），
 * 单测实现是内存假件。刻意只有四个方法——多暴露一个就多一处单测覆盖不到的分支。
 */
internal interface EngineHandle {
    /** 引擎进程/协程还在不在跑。注意：**它对「门敲没敲开」一个字都没说**。 */
    fun running(): Boolean

    /** 引擎自行停机时的原因（区别于用户主动断开）。 */
    fun reason(): String

    /**
     * 数据面健康快照；**null = 不可判定**（这份会话根本没有健康状态载体，
     * 例如老 .aar 或 Go 侧 Session.health 为 nil）。
     * 绝不能用一个"全 false 的 HealthLite"顶替：那会让「读不到」与「读到了、确实没敲开」同形，
     * 而两者的处置相反（前者不下结论，后者要把 x509 那句原文顶到界面上）。
     */
    fun health(): HealthLite?

    fun stop()
}

/**
 * [HealthReport] 的纯 Kotlin 影子。**存在的唯一理由是可测**——HealthReport 同样是 final +
 * native，单测里造不出实例。字段与 Go 侧 `dataplane.HealthSnapshot` 逐项同名同序。
 *
 * ★不放「落点 i/n」之类的字段：移动端至今单落点（Baidimobile.Start 只填 SpaAddr/ProxyAddr/
 *   TunnelPin，不填 Endpoints），放上去恒等于 1/1，是一条永远为真的假信息。
 */
internal data class HealthLite(
    /** 引擎到底有没有观察到过任何真实事件。**false 既不是"没问题"也不是"失败"，是"还没敲过第一次门"**。 */
    val observed: Boolean,
    /** 是否**曾**成功发出过 SPA 敲门包（粘性位）。 */
    val knock: Boolean,
    /** 是否**曾**拨通过隧道（粘性位）。见 [judgeReady] 里为什么它不当判据。 */
    val tunnel: Boolean,
    /** 最近一次敲门类失败（取令牌 / SPA 拨号）。空 = 该类当前无失败。 */
    val knockErr: String,
    /** 最近一次隧道类失败（等同桌面健康行的 `terr=`）。 */
    val tunnelErr: String,
    /** 最近一次被触碰的那一类的当前错误（等同桌面健康行的 `err=`）：任何一次成功都会清空它。 */
    val err: String
)

/** 生产实现：把 gomobile 的 Session 包成 [EngineHandle]。这个类里**不许有任何判定逻辑**——
 *  它是唯一一段单测覆盖不到的代码，逻辑放进来就等于放弃验证。 */
internal class SessionHandle(private val s: Session) : EngineHandle {
    override fun running(): Boolean = s.running()
    override fun reason(): String = s.reason() ?: ""
    override fun health(): HealthLite? {
        // Session.health() 是平台类型 HealthReport!：Go 侧返回 nil 时经 seq 的 NullRefNum
        // 到 Java 就是 null（bind/gengo.go 的 genToRefNum 写死 nil→NullRefNum）。**必须判 null**，
        // 否则不可判定会以 NPE 的形态出现在一条完全不相干的调用栈上。
        // ★下面这个 `: HealthReport?` 显式标注是承重的，别当噪声删掉：Kotlin 对平台类型
        //   （`HealthReport!`）不做空安全检查，去掉标注后 `h.observed()` 照样编译通过——
        //   变异实测过（去掉标注与判断，compileDebugKotlin 依然 BUILD SUCCESSFUL）。
        //   这一段是全文件唯一 JVM 单测覆盖不到的代码（要持有一个真的 baidimobile.Session），
        //   编译器也不拦，所以纪律只剩注释与"这个类里不放判定逻辑"这条约定。
        val h: HealthReport? = s.health()
        if (h == null) return null
        return HealthLite(
            observed = h.observed(), knock = h.knock(), tunnel = h.tunnel(),
            knockErr = h.knockErr() ?: "", tunnelErr = h.tunnelErr() ?: "", err = h.err() ?: ""
        )
    }
    override fun stop() { s.stop() }
}

/**
 * 「数据面是不是真的可用」。三态：true / false / **null = 不可判定**。
 *
 *   `ready = running && h.knock && h.knockErr.isEmpty()`
 *
 * ★**判据用 knockErr 而不是合并后的 err——这是与桌面端 parseTunStatus 唯一的、刻意的分歧。**
 *   健康行的 `err` 按契约是「最近一次被触碰的那一类的当前错误」：任何一次成功（含每 15s 的
 *   保活敲门）清空它，任何一次**隧道类**拨号失败（每一条被 TUN 捕获的 TCP 流拨不通都会触发）
 *   设上它。拿它当就绪判据，隧道类的持续故障（orphan-ruleset / 指纹不匹配 / gm 开关不一致）
 *   会让接入态以约 15s 为周期反复翻：未就绪 → 保活敲门清 err → 已就绪 → 下一条流又拨不通 →
 *   未就绪……而每翻一次界面就对用户做一次「已接入企业内网」的无根据断言，正是本波要消灭的
 *   那类断言换了个触发条件。手机上 WiFi↔LTE 切换会让这条路径变成常态而非异常。
 *   桌面端能用 `err` 是因为它另有一套粘性提示状态机（tunnel.ts 的 nextDataplaneNotice 按
 *   `terr` 判隧道类失败是否真恢复）把震荡吸收掉了，移动端没有那套东西；而 `err` 之所以合并
 *   两类，是为了让**旧** TS 读新健康行时语义不变（见 dataplane.go 里 healthPrefix 上方的契约），
 *   那是日志行的向后兼容约束，对这条 wave10 新开的类型化通道不成立。
 *   隧道类失败不因此被吞掉：它由 [HealthLite.tunnelErr] 单独承载，界面上另立一条**常驻**横幅
 *   （与桌面端 terr 那条同源），只是不再参与「门敲没敲开」的判定。
 *   本波要抓的那个 bug 不受影响：x509 走 markKnockFail，`knock=false` 且 `knockErr` 非空，
 *   两个条件都不成立。
 *
 * ★**不要求 [HealthLite.tunnel]**：那是「曾拨通」的粘性位，Go 侧只在第一条业务流真拨号时置位。
 *   把它当必要条件的话，接入会死锁在「接入中」——界面因未就绪不让访问应用 → 永远产生不出
 *   第一条业务流 → 这一位永远不翻真。桌面端踩过这个坑，见 tunnel.ts 里 TunView.tunnel 那段
 *   注释与 docs/ARCHITECTURE.md 第七节「桌面端接入态判据」边界①。
 *
 * ★**h == null 回 null 而不是 false**：读不到健康态与"读到了、确实没就绪"的处置相反——
 *   前者要让桥回落到旧判据（老 .aar / iOS / 鸿蒙壳照旧能接入），后者要把失败原文顶到界面上。
 *   塌成 false 的话，任何一版拿不到健康行的壳都会永远停在「接入中」直到 30s 超时。
 *
 * ★[running] 参与判据：健康位是粘性的（knock 成功过就一直为真），引擎已停机时那份快照仍会
 *   报 knock=true——只看健康位会把一条已经断掉的隧道判成就绪。
 */
internal fun judgeReady(running: Boolean, h: HealthLite?): Boolean? {
    if (h == null) return null
    return running && h.knock && h.knockErr.isEmpty()
}

/**
 * 未就绪时那句给人看的话：**优先健康行的原文，一个字都不改写**。
 * 「x509: certificate signed by unknown authority」指得动管理员去装 CA，
 * 换成一句自编的「网络异常」只会把人支去重启手机。
 *
 * ★取值顺序 knockErr → err → tunnelErr，**knockErr 必须排第一**：未就绪按定义就是敲门类
 *   那一格没过（见上面的 judgeReady），先取 `err` 的话，一次与就绪判定无关的隧道类失败
 *   会把 `err` 占住，于是界面上「未就绪」的原因写着一条拨号错误，而真正挡住门的那句
 *   x509 被压在后面看不见——归因指向哪儿，人就往哪儿查。
 *   与 webview 侧 `clients/mobile/src/lib/tunnelwatch.ts` 的 notReadyReason 同序。
 *
 * 返回空串 = 健康行里没有任何错误原文（例如 observed=false，引擎刚起还没写出健康行）——
 * 那不是失败，调用方不该拿它当失败原因用。
 */
internal fun notReadyReasonOf(h: HealthLite?): String {
    if (h == null) return ""
    for (v in listOf(h.knockErr, h.err, h.tunnelErr)) {
        val t = v.trim()
        if (t.isNotEmpty()) return t
    }
    return ""
}
