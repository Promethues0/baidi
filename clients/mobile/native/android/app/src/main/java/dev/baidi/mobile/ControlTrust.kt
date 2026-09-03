// 白帝安卓壳 · 控制中心 HTTPS 信任锚的读取与自证
//
// 材料由 build.gradle.kts 在构建期从 -PbaidiControlCa 生成，**只存在一处**：
// res/raw/baidi_control_ca.pem。它同时喂给两条互不相干的链路——
//   · WebView（登录 / 拉剖面 / api.ts 的每一次 fetch）经 res/xml/network_security_config.xml；
//   · Go 数据面（取敲门令牌）经 baidimobile.Config.controlCaPEM。
// 两半只解决一半，就会造出「网页登录得进去而隧道连不上」（或反过来）这种两边都不报错的形态。

package dev.baidi.mobile

import android.content.Context
import java.security.MessageDigest

/** 读取结果。三态：[pem] 非空 = 有锚；空 + [why] 空 = 本包**没配**锚（如实姿态）；空 + [why] 非空 = 出错。 */
internal data class ControlAnchor(val pem: String, val why: String)

/**
 * 读出本包内置的控制中心信任锚，并与构建期算好的 SHA-256 **逐字节比对**。
 *
 * ★为什么要比对：BuildConfig 里刻意只放摘要、不放 PEM 正文，为的就是让「NSC 用的那份」与
 *   「Go 用的那份」是否同源成为一件**可执行**的事。对不上说明包被改过（res 被替换、
 *   合并了别的 res 源），此时**必须 fail-closed**：拿一份来路不明的锚去信任控制面，
 *   比不信任更坏——它会让一个中间人变成"受信任的控制中心"。
 *
 * ★未配置锚不是错误，是一种姿态：回空 pem + 空 why，数据面据此走系统信任库
 *   （baidimobile.Config.controlCaPEM 空值语义就是"系统信任库"，不是跳过校验）。
 */
internal fun readControlAnchor(ctx: Context): ControlAnchor {
    val want = BuildConfig.BAIDI_CONTROL_CA_SHA256
    if (want.isEmpty()) return ControlAnchor("", "")   // 本包没配锚
    val pem = try {
        ctx.resources.openRawResource(R.raw.baidi_control_ca).use { it.readBytes() }
    } catch (e: Exception) {
        return ControlAnchor("", "读不到内置的控制中心信任锚（res/raw/baidi_control_ca.pem）：" +
            (e.message ?: e.javaClass.simpleName))
    }
    return verifyControlAnchor(pem, want)
}

/**
 * [readControlAnchor] 的**纯函数**部分：比对摘要并给出三态结果。
 *
 * ★为什么要抽出来：上面那个函数要 android Context + R.raw，而 JVM 单测里 android.jar 是打桩的，
 *   `openRawResource` 一调就抛「Method … not mocked」——判定逻辑留在里面就整段测不到。
 *   同 TunnelState 与 EngineHandle 那条纪律（也同 posture.rs 的 Env trait）。
 */
internal fun verifyControlAnchor(pem: ByteArray, wantSha: String): ControlAnchor {
    if (wantSha.isEmpty()) return ControlAnchor("", "")
    val got = MessageDigest.getInstance("SHA-256").digest(pem)
        .joinToString("") { "%02x".format(it) }
    if (got != wantSha) {
        return ControlAnchor("", "内置的控制中心信任锚与构建期记录的指纹不一致" +
            "（构建期 ${wantSha.take(16)}… / 实得 ${got.take(16)}…）。这个包被改过，拒绝接入——" +
            "拿一份来路不明的锚去信任控制面比不信任更坏，它会把一个中间人变成「受信任的控制中心」。")
    }
    return ControlAnchor(String(pem, Charsets.UTF_8), "")
}
