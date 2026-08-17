package secevent

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type rec struct {
	cat, src, detail string
	count            int
	allow            bool
}

type sinkRec struct {
	mu   sync.Mutex
	recs []rec
}

func (s *sinkRec) fn(cat, src, detail string, count int, allow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, rec{cat, src, detail, count, allow})
}

func (s *sinkRec) list() []rec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rec{}, s.recs...)
}

func newTestReporter() (*Reporter, *sinkRec, *time.Time) {
	s := &sinkRec{}
	now := time.Unix(1_700_000_000, 0)
	r := New(s.fn)
	r.now = func() time.Time { return now }
	return r, s, &now
}

// 第一次立即上报，窗口内后续只累计，窗口过后补报聚合数并重新立即上报。
func TestThrottleWindow(t *testing.T) {
	r, s, now := newTestReporter()
	r.Report("knock-token", "1.2.3.4", "SPA 敲门拒绝（令牌无效）")
	for i := 0; i < 99; i++ {
		r.Report("knock-token", "1.2.3.4", "SPA 敲门拒绝（令牌无效）")
	}
	if got := s.list(); len(got) != 1 || got[0].count != 1 {
		t.Fatalf("窗口内应只上报第一次，实得 %v", got)
	}
	*now = now.Add(Window + time.Second)
	r.Report("knock-token", "1.2.3.4", "SPA 敲门拒绝（令牌无效）")
	got := s.list()
	if len(got) != 3 {
		t.Fatalf("窗口过后应补报聚合 + 新窗口首报，实得 %v", got)
	}
	if got[1].count != 99 || !strings.Contains(got[1].detail, "99 次") {
		t.Fatalf("聚合补报应带累计数，实得 %+v", got[1])
	}
	if got[2].count != 1 {
		t.Fatalf("新窗口首报 count=1，实得 %+v", got[2])
	}
}

// 不同 (类别, IP) 键互不抑制。
func TestKeysIndependent(t *testing.T) {
	r, s, _ := newTestReporter()
	r.Report("knock-token", "1.2.3.4", "a")
	r.Report("knock-token", "5.6.7.8", "b")
	r.Report("proxy-authz", "1.2.3.4", "c")
	if got := s.list(); len(got) != 3 {
		t.Fatalf("三个不同键应各自立即上报，实得 %v", got)
	}
}

// Flush 补报到期窗口的积累，并删掉安静键（表不只增不减）。
func TestFlush(t *testing.T) {
	r, s, now := newTestReporter()
	r.Report("web-ticket", "9.9.9.9", "L7 入口拒绝（票据无效）")
	r.Report("web-ticket", "9.9.9.9", "L7 入口拒绝（票据无效）")
	*now = now.Add(Window + time.Second)
	r.Flush()
	got := s.list()
	if len(got) != 2 || got[1].count != 1 || !strings.Contains(got[1].detail, "1 次") {
		t.Fatalf("Flush 应补报积累 1 次，实得 %v", got)
	}
	if len(r.ent) != 0 {
		t.Fatalf("结清后键应被删除，实得 %d 个", len(r.ent))
	}
	r.Flush() // 幂等
	if len(s.list()) != 2 {
		t.Fatal("空表 Flush 不应产生上报")
	}
}

// 键表满后新来源折叠进「多源聚合」，内存有界。
func TestOverflowFoldsToAggregate(t *testing.T) {
	r, s, _ := newTestReporter()
	for i := 0; i < maxKeys; i++ {
		r.Report("knock-envelope", fmt.Sprintf("10.0.%d.%d", i/256, i%256), "x")
	}
	before := len(s.list())
	// 表已满：三个新来源都折叠进同一个聚合键，只有第一次立即上报
	r.Report("knock-envelope", "203.0.113.1", "y")
	r.Report("knock-envelope", "203.0.113.2", "y")
	r.Report("knock-envelope", "203.0.113.3", "y")
	got := s.list()
	if len(got) != before+1 {
		t.Fatalf("溢出来源应折叠聚合（只多 1 条首报），实得 %d→%d", before, len(got))
	}
	if got[len(got)-1].src != overflowSrc {
		t.Fatalf("聚合行的来源应为 %q，实得 %q", overflowSrc, got[len(got)-1].src)
	}
	if len(r.ent) > maxKeys+1 {
		t.Fatalf("键表应有界（≤%d+聚合键），实得 %d", maxKeys, len(r.ent))
	}
}

// nil sink（未配 -control）：全部空转不崩。
func TestNilSinkNoop(t *testing.T) {
	r := New(nil)
	r.Report("knock-token", "1.2.3.4", "x")
	r.Flush()
	var rp *Reporter
	rp.Report("a", "b", "c") // nil Reporter 也安全（调用方无需判空）
	rp.Flush()
}

// ── wave8 行动 8：放行留痕 ──

// TestReportAllowMarksAllow 放行事件必须带 allow 标记：控制面据此落 verdict=allow
// 且**不**计入攻击源统计。丢了这个标记，一次正常访问会被数进「攻击源 TOP」。
func TestReportAllowMarksAllow(t *testing.T) {
	r, sk, _ := newTestReporter()
	r.ReportAllow("tunnel-allow", "10.0.0.9", "zhang|res-1", "隧道放行：账号 zhang 访问 res-1")
	r.Report("proxy-unauth", "10.0.0.9", "未敲门直连")
	got := sk.list()
	if len(got) != 2 {
		t.Fatalf("应上报 2 条，得到 %d", len(got))
	}
	if !got[0].allow {
		t.Error("放行事件的 allow 标记丢了——控制面会把它当拒绝，计进攻击源 TOP")
	}
	if got[1].allow {
		t.Error("拒绝事件不该带 allow 标记")
	}
}

// TestAllowThrottledByAccountAndResource 放行按 (账号,资源) 节流，**不是**按源 IP。
//
// ★同一个人从同一个 IP 访问三个资源是三件事。按源 IP 折叠会把其中两件抹掉，
// 而那正是 FR-AUDIT-05 要查的维度（「某账号访问了哪个资源」）。
func TestAllowThrottledByAccountAndResource(t *testing.T) {
	r, sk, _ := newTestReporter()
	for _, res := range []string{"res-1", "res-2", "res-3"} {
		r.ReportAllow("tunnel-allow", "10.0.0.9", "zhang|"+res, "隧道放行：zhang → "+res)
	}
	// 同一 (账号,资源) 再来一次：这次要被节流。
	r.ReportAllow("tunnel-allow", "10.0.0.9", "zhang|res-1", "隧道放行：zhang → res-1")

	got := sk.list()
	if len(got) != 3 {
		t.Fatalf("三个资源应各上报一条、重复的那条被节流，得到 %d 条：%+v", len(got), got)
	}
	for i, want := range []string{"res-1", "res-2", "res-3"} {
		if !strings.Contains(got[i].detail, want) {
			t.Errorf("第 %d 条应是 %s，得到 %q", i, want, got[i].detail)
		}
	}
}

// TestAllowAndDenyThrottleIndependently 同一 (类别,键) 的放行与拒绝各自独立节流。
//
// ★共用一个键的话，一条放行会把紧随其后的拒绝压掉五分钟——而那正是最该
// 立刻可见的一条（「这个人刚还能进，现在被拒了」）。
func TestAllowAndDenyThrottleIndependently(t *testing.T) {
	r, sk, _ := newTestReporter()
	r.ReportAllow("x", "1.2.3.4", "1.2.3.4", "放行")
	r.Report("x", "1.2.3.4", "拒绝")
	got := sk.list()
	if len(got) != 2 {
		t.Fatalf("放行与拒绝应各上报一条，得到 %d 条：%+v", len(got), got)
	}
	if !got[0].allow || got[1].allow {
		t.Fatalf("顺序或标记不对：%+v", got)
	}
}

// TestAllowAggregateSuffixSaysAllow 聚合补报的措辞要分放行/拒绝。
// 审计里写「拒绝被聚合」而实际是放行，比不写更坏。
func TestAllowAggregateSuffixSaysAllow(t *testing.T) {
	r, sk, now := newTestReporter()
	r.ReportAllow("tunnel-allow", "10.0.0.9", "zhang|res-1", "放行 1")
	for i := 0; i < 4; i++ {
		r.ReportAllow("tunnel-allow", "10.0.0.9", "zhang|res-1", "放行 N")
	}
	*now = now.Add(Window + time.Second)
	r.Flush()

	got := sk.list()
	if len(got) != 2 {
		t.Fatalf("首条 + 补报共 2 条，得到 %d：%+v", len(got), got)
	}
	agg := got[1]
	if !agg.allow {
		t.Error("补报也必须带 allow 标记")
	}
	if !strings.Contains(agg.detail, "同类放行被聚合") {
		t.Errorf("补报措辞应说「放行」，得到 %q", agg.detail)
	}
	if agg.count != 4 {
		t.Errorf("聚合计数应为 4，得到 %d", agg.count)
	}
	// ★源必须是 IP，不是节流键里的账号。此前 Flush 从 key 反解 src，
	// 而放行的键是 "+类别|账号|资源"，反解出来的"源"会是账号名。
	if agg.src != "10.0.0.9" {
		t.Errorf("补报的源应是 IP 而不是节流键的一段，得到 %q", agg.src)
	}
}
