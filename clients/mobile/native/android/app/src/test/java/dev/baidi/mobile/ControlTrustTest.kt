package dev.baidi.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * 控制中心信任锚的自证逻辑。三态与 fail-closed 各一条钉子。
 *
 * 真机 A/B 已验（2026-09-03 OPPO PKU110 / 演示站 101.43.125.131）：带锚的包 WebView 登录成功、
 * 数据面取到敲门令牌、隧道拉起业务流（healthTunnel=true）；同一套代码不带锚构建，
 * 同一次 fetch 在 TLS 那步失败。这几条用例守的是那条链上"包被改过"的分支——真机上验不到。
 */
class ControlTrustTest {
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
        .joinToString("") { "%02x".format(it) }

    @Test fun noAnchorConfiguredIsNotAnError() {
        // ★"本包没配锚"是一种**姿态**不是错误：数据面据此走系统信任库
        //   （baidimobile.Config.controlCaPEM 空值语义就是系统信任库，不是跳过校验）。
        //   把它当错误会让所有面向受信证书部署的包一律起不来。
        val a = verifyControlAnchor("whatever".toByteArray(), "")
        assertEquals("", a.pem)
        assertEquals("", a.why)
    }

    @Test fun matchingDigestYieldsThePem() {
        val pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".toByteArray()
        val a = verifyControlAnchor(pem, sha(pem))
        assertEquals(String(pem), a.pem)
        assertEquals("", a.why)
    }

    @Test fun tamperedAnchorFailsClosedAndSaysWhy() {
        // ★对不上**必须** fail-closed：拿一份来路不明的锚去信任控制面比不信任更坏——
        //   它会把一个中间人变成"受信任的控制中心"，而界面上一切正常。
        val pem = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n".toByteArray()
        val a = verifyControlAnchor(pem, sha("别的东西".toByteArray()))
        assertEquals("对不上时绝不能把 pem 交出去", "", a.pem)
        assertTrue("必须说清为什么拒绝：$a", a.why.contains("指纹不一致"))
        assertTrue("要给出可比对的两个值", a.why.contains("构建期") && a.why.contains("实得"))
    }

    @Test fun oneByteDifferenceIsEnough() {
        val a = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".toByteArray()
        val b = "-----BEGIN CERTIFICATE-----\nAAAB\n-----END CERTIFICATE-----\n".toByteArray()
        assertTrue(verifyControlAnchor(b, sha(a)).why.isNotEmpty())
    }
}
