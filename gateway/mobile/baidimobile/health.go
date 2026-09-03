package baidimobile

import "baidi.dev/gateway/internal/dataplane"

// HealthReport 是数据面健康状态在某一瞬间的只读快照，供原生壳判定**真实**接入态。
//
// ★它存在的理由（2026-09-03 安卓真机 OPPO PKU110 / Android 16 实测）：
// 同一时刻桥的 tunnelStatus() 回 {"stage":"up"}、startTunnel 回「数据面已就绪」，
// 而 Go 健康行是 knock=false tunnel=false err="取敲门令牌失败：… x509: certificate signed by
// unknown authority"——**引擎起来了、门没敲开，界面却显示已接入**。原因是原生壳只能看到
// 「Baidimobile.start 返回了没有」，而那只说明 netstack 装起来了。桌面端 wave10 已把接入态
// 改判数据面健康行（tunnel.ts 的 parseHealth），移动端此前拿不到这份状态。
//
// ★类型名刻意叫 HealthReport 而不是 Health：同包里若同时存在类型 `Health` 与方法
// `Session.Health()`，Java 侧不冲突，但 ObjC/Swift 侧的绑定命名在本机（无 Xcode）验不了、
// 也没有任何编译闸会挡住——名字错开的代价是零，撞上的代价是 iOS 那条腿出包时才炸。
//
// ★刻意**没有**「落点 i/n」这类字段：移动端至今是单落点（Start 只填 SpaAddr/ProxyAddr/
// TunnelPin，不填 Endpoints），放上去恒等于 1/1，是一条永远为真的假信息。
// 桌面端那个 `endpoint=i/n` 是因为它真有多落点故障转移。
//
// ★字段全部不导出、只留方法：gomobile 会给导出字段生成 getter+**setter**，
// 而这是一份快照——让原生侧能写回来，等于在界面上留了一条能伪造健康态的路。
type HealthReport struct {
	observed  bool
	knock     bool
	tunnel    bool
	knockErr  string
	tunnelErr string
	err       string
}

// Observed 报告「引擎到底有没有观察到任何真实事件」。
//
// **false 既不是"没问题"也不是"失败"，而是"还没敲过第一次门"**——它对应的处置是继续等，
// 与"敲过了、没问题"（就绪）和"敲了、失败了"（报错）都不同。三态塌成一个布尔，
// 正是本波要消灭的那个形态。
func (h *HealthReport) Observed() bool { return h.observed }

// Knock 报告是否**曾**成功发出过 SPA 敲门包（粘性位，成功过就一直为真）。
func (h *HealthReport) Knock() bool { return h.knock }

// Tunnel 报告是否**曾**拨通过隧道（粘性位）。
//
// ★**不得**拿它当就绪判据：隧道只在有业务流真拨号时才拨，用户打开第一个应用之前它恒为假。
// 当必要条件的话，接入会死锁在「接入中」——界面不让访问应用 → 永远产生不出第一条流
// → 这一位永远不翻真（桌面端踩过，见 tunnel.ts 里 TunView.tunnel 那段注释与
// docs/ARCHITECTURE.md 第七节「桌面端接入态判据」边界①）。
func (h *HealthReport) Tunnel() bool { return h.tunnel }

// KnockErr 最近一次**敲门类**失败（取令牌 / SPA 拨号）。空 = 该类当前无失败。
func (h *HealthReport) KnockErr() string { return h.knockErr }

// TunnelErr 最近一次**隧道类**失败（落点拨不通 / 握手失败 / 指纹不匹配…），
// 等同桌面健康行的 `terr=`：只被隧道真拨通清掉，一次保活敲门成功碰不到它——
// 持续性的「疑似中间人」告警要靠它才能稳定停在界面上。
func (h *HealthReport) TunnelErr() string { return h.tunnelErr }

// Err 最近一次被触碰的那一类的当前错误，等同桌面健康行的 `err=`：
// 任何一次失败把它设成该原因，任何一次成功（含每 15s 的保活敲门）把它清空。
//
// ★**别拿它当就绪判据**（安卓壳 EngineHandle.judgeReady 用的是 KnockErr）：它合并了两类，
// 而隧道类失败在每一条业务流拨不通时都会写它、又被每 15s 的保活敲门擦掉——
// 用它判就绪会让接入态以 15s 为周期反复翻。它合并两类是为了让**旧** TS 读新健康行时
// 语义不变（见 dataplane.go 里 healthPrefix 上方的契约），那是日志行的向后兼容约束，
// 对这条类型化通道不成立。这里保留它，是因为界面上要如实展示健康行的每一格。
func (h *HealthReport) Err() string { return h.err }

// Health 返回当前健康快照；**返回 nil 表示不可判定**（这份会话根本没有健康状态载体）。
//
// ★nil 是唯一能表达"读不到"的手段：gomobile 的类型闸只认 bool / 有符号整数 / string /
// []byte / error / 本包具名类型的**指针**（见 x/mobile bind/gen.go 的 isSupported——
// `*types.Pointer` 那一支只接受指向 Named 类型的指针，`*bool`/`*string` 一律不支持）。
// 而 Go 侧的 nil 结构体指针经 seq 的 NullRefNum(41) 过去，在 Java 侧就是 null
// （bind/gengo.go genToRefNum 写死了 nil→NullRefNum，bind/java/seq_android.c.support 的
// go_seq_from_refnum 对 NullRefNum 直接 return NULL）——这是生成器的既定行为，不是巧合。
// 于是"不可判定"与"确定为假"在原生侧结构性地分得开：null vs. Observed()==false。
// 把它们合成一个零值 report 的话，一台**从没起过引擎**的会话会与一台**刚起步还没敲门**的
// 会话完全同形，而前者是壳的 bug、后者是正常的接入中。
func (s *Session) Health() *HealthReport {
	if s == nil || s.health == nil {
		return nil
	}
	snap := s.health.Snapshot()
	return newHealthReport(snap)
}

// newHealthReport 是 dataplane.HealthSnapshot → 绑定层类型的**唯一**转换点。
// 逐项照搬、不做任何推导：绑定层不判"就绪"，那是原生壳的事（判据写在壳与 TS 侧，
// 三轨共用同一份契约）——在这里再算一遍就是第二个真相来源。
func newHealthReport(s dataplane.HealthSnapshot) *HealthReport {
	return &HealthReport{
		observed: s.Observed, knock: s.Knock, tunnel: s.Tunnel,
		knockErr: s.KnockErr, tunnelErr: s.TunnelErr, err: s.Err,
	}
}
