package store

// Memory 内存实现（首版演示数据）。线程安全由调用方在 HTTP 层天然串行化的读场景下保证；
// 写入能力将随模块落地补充锁与持久化。
//
// ★它是 SQLiteStore 的**嵌入基类**，这既是它还活着的理由，也是本项目审计根因 #1：
// 嵌入不是接口实现，SQLiteStore 少写一个方法不会报错，只会静默落回这里的种子。
// 两道守卫盯着这件事：
//   - coverage_guard_test.go —— Store 接口方法有没有 SQLite 实现；
//   - memory_fallback_guard_test.go —— 实现了、但方法体里还在拿 s.Memory.<同名方法>
//     打底（那样"没被覆盖到的字段"仍是种子，接口层面完全看不出来）。
//
// 现在这里只剩**建库播种真正需要的那几份**（apps / users / resources / objects /
// auth_policies / baselines / ipsec / audit），页面读取路径一份都不吃。
// Overview 的种子版本已删除：态势总览逐字段由真实数据构造（overview_sqlite.go），
// 留着一份"看起来很像真的"的态势数据，只会在某天有人删掉 SQLite 实现时无声接管首页。
type Memory struct{}

// NewMemory 构造内存 store。
func NewMemory() *Memory { return &Memory{} }
