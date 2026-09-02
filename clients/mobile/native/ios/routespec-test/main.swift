// RouteSpec 的断言（不依赖 XCTest / Xcode 工程）：`../test-routespec.sh` 编译并跑它，非零退出即红。
// 放在子目录里且文件名叫 main.swift，是为了将来建 Xcode 工程时不会被当成扩展 target 的源码误收。

import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    if ok { print("✓ \(what)") } else { failures += 1; print("✗ \(what)") }
}
func rejects(_ spec: String, naming entry: String) {
    do {
        let r = try Routes.parse(spec)
        check(false, "应整体拒绝 \(spec)，却解析成 \(r)")
    } catch let e as RouteSpecError {
        check("\(e)".contains(entry), "拒绝 \(spec) 且点名「\(entry)」：\(e)")
    } catch {
        check(false, "拒绝 \(spec) 抛了别的错误：\(error)")
    }
}

check((try? Routes.parse(Routes.defaultSpec)) == [RouteSpec(addr: "10.99.0.0", prefix: 24)], "默认值是单网段")
check(
    (try? Routes.parse("10.99.0.0/24, 10.99.1.0/24 ,172.16.8.0/22"))
        == [RouteSpec(addr: "10.99.0.0", prefix: 24), RouteSpec(addr: "10.99.1.0", prefix: 24), RouteSpec(addr: "172.16.8.0", prefix: 22)],
    "多网段逐条解析（改造前 maxSplits:1 只认第一段、其余静默丢弃）"
)
rejects("10.99.0.0/24,10.99.1.0/33", naming: "10.99.1.0/33")    // 前缀越界
rejects("10.99.0.0/24,10.99.1.0/-1", naming: "10.99.1.0/-1")    // 前缀越界（负）
rejects("10.99.0.0/24,10.99.1.0/abc", naming: "10.99.1.0/abc")  // 前缀非整数（改造前正是这一档回落 24）
rejects("10.99.0.0/24,10.99.1.0", naming: "10.99.1.0")          // 缺前缀
rejects("10.99.0.0/24,300.1.1.0/24", naming: "300.1.1.0/24")    // 地址非 IPv4
check((try? Routes.parse(" , ")) == nil, "空串拒绝")
check(Routes.mask(24) == "255.255.255.0" && Routes.mask(22) == "255.255.252.0"
      && Routes.mask(32) == "255.255.255.255" && Routes.mask(0) == "0.0.0.0", "前缀 → 掩码")
check(RouteSpec(addr: "10.0.0.0", prefix: 8).mask == "255.0.0.0", "RouteSpec.mask")

if failures > 0 { print("✗ \(failures) 条断言失败"); exit(1) }
print("✓ RouteSpec 全部断言通过")
