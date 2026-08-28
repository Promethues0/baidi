//go:build race

package sysstat

// raceEnabled 在 -race 构建下为真。
//
// ★唯一消费方是 darwin 的 readNetCounters：它经 syscall.ParseRoutingMessage 取
// 接口计数，而那个 API 已被标准库 Deprecated，且**在 checkptr（随 -race 启用）下
// 会因未对齐指针转换直接 fatal**——不是测试失败，是整个测试进程崩掉。
// 后果不是少一个指标，是 **macOS 上跑不了 `go test -race ./...`**，
// 而 race 检测是发现并发缺陷的主要手段；本项目 CI 只在 ubuntu-latest 上跑 race，
// darwin 特有的并发问题因此没有任何人能查。
//
// 替代方案已实测排除：golang.org/x/net/route（官方推荐的后继）的
// InterfaceMetrics 只有 Type 与 MTU，**拿不到 Ibytes/Obytes**。
//
// 于是在 race 构建下让这个指标走「不可判定」。方向与本包一贯的三态纪律一致
// ——采不到就如实报不可判定，绝不补 0（补 0 会画出一条完全虚构的平线）。
// 生产二进制不开 checkptr，行为一字未变。
const raceEnabled = true
