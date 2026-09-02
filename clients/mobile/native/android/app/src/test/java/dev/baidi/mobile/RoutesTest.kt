// 受保护网段解析的 JVM 单测（不需要模拟器；CI `./gradlew testDebugUnitTest` 跑）。
// 守的是「多网段只切一次 → 静默回落 24 → 只接管第一段」这条静默失效。

package dev.baidi.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class RoutesTest {
    @Test fun defaultIsSingleRoute() {
        assertEquals(listOf(RouteSpec("10.99.0.0", 24)), Routes.parse(Routes.DEFAULT))
    }

    @Test fun multipleRoutesParsedOneByOne() {
        // 改造前 "10.99.0.0/24,10.99.1.0/24".split("/") → ["10.99.0.0", "24,10.99.1.0", "24"]：
        // 前缀 "24,10.99.1.0" 解析失败静默回落 24，第二段整段丢失且不报错。
        assertEquals(
            listOf(RouteSpec("10.99.0.0", 24), RouteSpec("10.99.1.0", 24), RouteSpec("172.16.8.0", 22)),
            Routes.parse("10.99.0.0/24, 10.99.1.0/24 ,172.16.8.0/22")
        )
    }

    @Test fun anyBadEntryRejectsWholeSpecAndNamesIt() {
        val cases = listOf(
            "10.99.0.0/24,10.99.1.0/33" to "10.99.1.0/33",   // 前缀越界
            "10.99.0.0/24,10.99.1.0/-1" to "10.99.1.0/-1",   // 前缀越界（负）
            "10.99.0.0/24,10.99.1.0/abc" to "10.99.1.0/abc", // 前缀非整数（改造前正是这一档回落 24）
            "10.99.0.0/24,10.99.1.0" to "10.99.1.0",         // 缺前缀
            "10.99.0.0/24,300.1.1.0/24" to "300.1.1.0/24",   // 地址非 IPv4
        )
        for ((spec, want) in cases) {
            try {
                Routes.parse(spec)
                fail("应整体拒绝：$spec")
            } catch (e: IllegalArgumentException) {
                assertTrue("拒绝原因要点名那一条「$want」：${e.message}", e.message!!.contains(want))
            }
        }
    }

    @Test fun emptySpecRejected() {
        try {
            Routes.parse(" , ")
            fail("空串应拒绝")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("为空"))
        }
    }
}
