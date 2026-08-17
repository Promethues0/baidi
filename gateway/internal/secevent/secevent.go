// Package secevent 数据面访问事件上报器（wave7 行动 5：FR-MON-05 + FR-AUDIT-02；
// wave8 行动 8 扩出**放行**语义：FR-AUDIT-01/02/05 + FR-MON-04）。
//
// 网关的每一次拒绝（SPA 敲门 / L4 代理 / L7 Web 代理）此前只落本机 slog——
// 网关一重启痕迹即灭失，控制面的 180 天审计留存对数据面事件是空话。而 SPA 隐身是
// 第一卖点，「谁在敲门」正是隐身在挡攻击的唯一可见证据。本包把拒绝事件按
// (类别, 源IP) 节流后交给心跳队列（cplane.QueueSecEvent），随心跳带给控制面落审计。
//
// ★节流是这条管道能存在的前提，不是优化：SPA 收的是任意 UDP，一次洪泛每秒可产生
// 数千次"拒绝"。不节流的话，事件队列（64 条上界）瞬间被冲翻，审计里全是噪声，
// 真正该看见的第一现场反而被挤掉。纪律与控制面 auditGrayObserved 相同：5 分钟窗口。
//
// 语义：每个 (类别, 源IP) 键，窗口内**第一次**拒绝立即上报（第一现场最有价值），
// 窗口内后续拒绝只累计；窗口到期后由 Flush（或下一次 Report）把累计数补报一条。
// 计数不丢，只是聚合——「1.2.3.4 五分钟内敲门重放 4093 次」比 4093 条流水更有用。
//
// ★内存有界：键表上限 maxKeys。SPA 是 UDP，源地址可伪造，一次伪造源洪泛能造出
// 无限多的 (类别, IP) 键——超限后新来源折叠进该类别的「多源」聚合键，
// 单键节流照旧，表大小被钉死。
//
// ── 放行事件（wave8 行动 8）──
//
// 本包最初只管拒绝，理由是「拒绝比放行更需要留痕」。**那是排序不是排除**：
// 审计里只有拒绝没有放行，「某账号何时经哪台网关访问了哪个资源」在中心侧根本查不到，
// 而网关一重启本机 slog 即灭失；外送给 SIEM 的证据链只有半边。对照最刺眼的是——
// 过同一道账号闸的 B/S 路径**签票时是落审计的**，C/S 这条主路径反而不落。
//
// 放行走 ReportAllow，与拒绝共用同一套节流与内存上界，两点不同：
//   - 事件 Kind 是 sec-allow（控制面据此落 verdict=allow，且**不**计入攻击源统计）；
//   - **节流键由调用方给**。拒绝按 (类别,源IP) 聚合是对的（洪泛来自同一个 IP）；
//     放行必须按 (账号,资源) 聚合——同一个人从同一个 IP 访问三个资源是三件事，
//     按源 IP 折叠会把其中两件抹掉，而那正是 FR-AUDIT-05 要查的维度。
package secevent

import (
	"fmt"
	"sync"
	"time"
)

// Window 同 (类别, 源IP) 两次上报的最小间隔（与控制面 auditGrayObserved 同款 5min 纪律）。
const Window = 5 * time.Minute

// maxKeys 键表上限。4096 个活跃 (类别,IP) 键 ≈ 正常部署永远到不了、
// 伪造源洪泛很快到的量级；到顶后折叠聚合，内存不再增长。
const maxKeys = 4096

// overflowSrc 键表满后新来源的聚合标识（控制面攻击源统计里如实显示为聚合行）。
const overflowSrc = "（多源聚合）"

type entry struct {
	windowStart time.Time
	pending     int    // 窗口内被抑制的次数（不含已立即上报的第一次）
	lastDetail  string // 最近一次的事实描述（补报时带上）
	allow       bool   // 这个键记的是放行还是拒绝（Flush 补报时要照原样回）
	// cat/src 上报用的类别与源标识。★必须存下来，不能像以前那样从 key 反解：
	// 放行的键是 "+类别|账号|资源"，反解出的"源"会是账号而不是 IP，
	// 补报出去的那条审计就会把源地址写成一个账号名。
	cat string
	src string
}

// aggSuffix 聚合补报的后缀。放行与拒绝分开措辞——审计里写「拒绝被聚合」
// 而实际是放行，比不写更坏。
func aggSuffix(allow bool, n int) string {
	if allow {
		return fmt.Sprintf("（窗口内另有 %d 次同类放行被聚合）", n)
	}
	return fmt.Sprintf("（窗口内另有 %d 次同类拒绝被聚合）", n)
}

// Reporter 节流上报器。零值不可用，须经 New 构造；sink 为 nil 时整体空转
// （网关未配 -control 就没有心跳通道，拒绝仍照常落本机日志）。
type Reporter struct {
	now func() time.Time // 可注入时钟（测试用）

	mu   sync.Mutex
	sink Sink // 经 mu 保护：装配序上晚于各监听的构造（见 Bind）
	ent  map[string]*entry
}

// Sink 事件出口（通常是 cplane.Client.QueueSecEvent）。
// allow=true 表示这是一次**放行**留痕，控制面据此落 verdict=allow 且不计攻击源。
type Sink func(cat, src, detail string, count int, allow bool)

// New 构造上报器。sink 通常是 cplane.Client.QueueSecEvent；
// 允许先传 nil、稍后 Bind——主装配里各监听的构造早于控制面客户端。
func New(sink Sink) *Reporter {
	return &Reporter{sink: sink, now: time.Now, ent: map[string]*entry{}}
}

// Bind 晚绑定 sink（未配 -control 时永不调用，Reporter 保持空转）。
func (r *Reporter) Bind(sink Sink) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.sink = sink
	r.mu.Unlock()
}

// snap 在锁内取当前 sink 快照（nil = 空转）。
func (r *Reporter) snap() Sink {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sink
}

// Report 登记一次拒绝。detail 是网关侧已在打日志的那句事实描述（中文短句）。
// 节流键 = (类别, 源IP)：洪泛来自同一个 IP，按它聚合正确。
func (r *Reporter) Report(cat, src, detail string) { r.report(cat, src, src, detail, false) }

// ReportAllow 登记一次**放行**（wave8 行动 8）。
//
// throttleKey 由调用方给，通常是 "账号|资源"——放行按 (账号,资源) 聚合而不是按源 IP：
// 同一个人从同一个 IP 访问三个资源是三件事，按 IP 折叠会把其中两件抹掉，
// 而那正是 FR-AUDIT-05 要查的维度。
func (r *Reporter) ReportAllow(cat, src, throttleKey, detail string) {
	r.report(cat, src, throttleKey, detail, true)
}

// report 节流 + 上报的核心。热路径上只做一次 map 操作与可能的一次 sink 调用，锁粒度极小。
func (r *Reporter) report(cat, src, throttleKey, detail string, allow bool) {
	if r == nil {
		return
	}
	sink := r.snap()
	if sink == nil {
		return
	}
	r.mu.Lock()
	// ★键里带 allow：同一 (类别,键) 的放行与拒绝各自独立节流。共用一个键的话，
	// 一条放行会把紧随其后的拒绝压掉五分钟——而那正是最该立刻可见的一条。
	key := cat + "|" + throttleKey
	if allow {
		key = "+" + key
	}
	e, ok := r.ent[key]
	if !ok {
		if len(r.ent) >= maxKeys {
			// 键表满：折叠进类别聚合键。聚合键自身也可能是新键，但每类只多一个，
			// 类别是代码里的有限枚举，表大小仍有界。
			src = overflowSrc
			key = cat + "|" + src
			if allow {
				key = "+" + key
			}
			e, ok = r.ent[key]
		}
		if !ok {
			r.ent[key] = &entry{windowStart: r.now(), allow: allow, cat: cat, src: src}
			r.mu.Unlock()
			sink(cat, src, detail, 1, allow) // 第一现场立即上报
			return
		}
	}
	now := r.now()
	if now.Sub(e.windowStart) >= Window {
		// 窗口已过：先补报窗口内积累，再为本次开新窗口并立即上报。
		pending, pdetail := e.pending, e.lastDetail
		e.windowStart, e.pending, e.lastDetail = now, 0, ""
		r.mu.Unlock()
		if pending > 0 {
			sink(cat, src, pdetail+aggSuffix(allow, pending), pending, allow)
		}
		sink(cat, src, detail, 1, allow)
		return
	}
	e.pending++
	e.lastDetail, e.src = detail, src
	r.mu.Unlock()
}

// Flush 把窗口已到期、还压着积累计数的条目补报出去，并清掉长期无活动的死键。
// 由 StartFlusher 周期调用；不调它也不丢账（下一次同键 Report 会补报），
// 只是"洪泛后归于沉寂"的尾巴要等到 Flush 才可见。
func (r *Reporter) Flush() {
	if r == nil {
		return
	}
	sink := r.snap()
	if sink == nil {
		return
	}
	type out struct {
		cat, src string
		allow    bool
		detail   string
		count    int
	}
	var outs []out
	r.mu.Lock()
	now := r.now()
	for key, e := range r.ent {
		if now.Sub(e.windowStart) < Window {
			continue
		}
		if e.pending > 0 {
			outs = append(outs, out{e.cat, e.src, e.allow,
				e.lastDetail + aggSuffix(e.allow, e.pending), e.pending})
		}
		delete(r.ent, key) // 到期且已结清：删键，安静来源不再占表
	}
	r.mu.Unlock()
	for _, o := range outs {
		sink(o.cat, o.src, o.detail, o.count, o.allow)
	}
}

// StartFlusher 启动周期补报（网关进程生命期运行，无需停止句柄）。
func (r *Reporter) StartFlusher(interval time.Duration) {
	if r == nil {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			r.Flush()
		}
	}()
}
