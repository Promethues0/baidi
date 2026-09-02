// 白帝安卓数据面 · 受保护网段解析
// 纯 Kotlin、不依赖任何 Android 类：好让 JVM 单测（app/src/test）在没有模拟器的机器上也跑得动——
// BaidiVpnService 本身要 android.jar + baidimobile.aar 才编得过，而它的路由解析是最容易静默出错的一段。

package dev.baidi.mobile

/** 一条要接管进 TUN 的网段：地址 + 前缀长度（0..32）。 */
data class RouteSpec(val addr: String, val prefix: Int)

object Routes {
    /** 剖面拉不到时的回退网段（与 iOS `Routes.defaultSpec`、桌面 baidi-tun 同一默认值）。 */
    const val DEFAULT = "10.99.0.0/24"

    /**
     * 解析逗号分隔的多网段 CIDR 串，如 `10.99.0.0/24,10.99.1.0/24`。
     * 剖面 `routes` 由 vpn.ts 用 `join(',')` 拼成这一串下传——与桌面 `baidi-tun -route` 同一契约。
     *
     * ★任何一条不合法就整体抛 [IllegalArgumentException]，并点名是哪一条。
     *   改造前用 `route.split("/")` 只切一次：两段以上时 `net[1]` 形如 `"24,10.99.1.0"` →
     *   `toIntOrNull()` 为 null → **静默回落 24** → 只接管了第一段的首地址。剖面明明下发了两段，
     *   UI 显示「已接入」，第二段的应用直连不走隧道，两侧零报错。
     *   回落到某个"看起来合理"的值正是本项目历史上最迷惑人的失败形态（见 CLAUDE.md
     *   「baidi-tun -route 支持逗号分隔多网段」那条），这里一律 fail-closed、拒绝要说得出是哪一条。
     */
    fun parse(spec: String): List<RouteSpec> {
        val entries = spec.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        if (entries.isEmpty()) throw IllegalArgumentException("受保护网段为空")
        return entries.map { entry ->
            val parts = entry.split('/')
            if (parts.size != 2) throw IllegalArgumentException("网段「$entry」不是 地址/前缀 形式")
            // 越界与非整数合并成一句：管理员照着「0..32 内的整数」一次就能改对，
            // 分两句的话「不是整数」会让人先改成整数再撞一次「越界」。
            val prefix = parts[1].toIntOrNull()?.takeIf { it in 0..32 }
                ?: throw IllegalArgumentException("网段「$entry」的前缀长度不是 0..32 内的整数")
            if (!isIPv4(parts[0])) throw IllegalArgumentException("网段「$entry」的地址不是点分十进制 IPv4")
            RouteSpec(parts[0], prefix)
        }
    }

    /** 四段 0..255 的点分十进制。刻意不用 InetAddress：它会去做 DNS 解析。 */
    private fun isIPv4(s: String): Boolean {
        val octets = s.split('.')
        if (octets.size != 4) return false
        return octets.all { o -> o.isNotEmpty() && o.length <= 3 && o.all { it in '0'..'9' } && o.toInt() <= 255 }
    }
}
