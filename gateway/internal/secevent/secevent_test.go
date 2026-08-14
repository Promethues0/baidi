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
}

type sinkRec struct {
	mu   sync.Mutex
	recs []rec
}

func (s *sinkRec) fn(cat, src, detail string, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, rec{cat, src, detail, count})
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
