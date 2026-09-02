// TunnelState 运行态的 JVM 单测：守「onRevoke 写下的原因被 onDestroy 冲回 idle」这条。

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
}
