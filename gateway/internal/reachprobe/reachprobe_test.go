package reachprobe

import (
	"net"
	"testing"
	"time"
)

// 真实拨测：本机监听可达（带耗时）、无人监听的端口不可达（带原因）。
func TestRunOnceRealDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	// 找一个必然没人听的端口：开一个监听立刻关掉
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	p := New(func() ([]string, []string) {
		return []string{"res-ok", "res-dead"}, []string{ln.Addr().String(), deadAddr}
	})
	p.gap = 0
	p.timeout = 2 * time.Second
	p.RunOnce()

	got := map[string]Result{}
	for _, r := range p.Snapshot() {
		got[r.ID] = r
	}
	if !got["res-ok"].OK || got["res-ok"].TS == 0 {
		t.Fatalf("本机监听应可达，实得 %+v", got["res-ok"])
	}
	if got["res-dead"].OK || got["res-dead"].Err == "" {
		t.Fatalf("死端口应不可达且带原因，实得 %+v", got["res-dead"])
	}
}

// 结果整轮替换：删掉的资源不留陈旧行；新增资源在下一轮出现。
func TestRunOnceReplacesWholeMap(t *testing.T) {
	ids := []string{"a"}
	p := New(func() ([]string, []string) {
		bks := make([]string, len(ids))
		for i := range ids {
			bks[i] = "10.255.255.1:1"
		}
		return append([]string{}, ids...), bks
	})
	p.gap = 0
	p.dial = func(string, time.Duration) error { return nil } // 桩：全部可达
	p.RunOnce()
	if len(p.Snapshot()) != 1 {
		t.Fatal("首轮应有 1 条")
	}
	ids = []string{"b", "c"}
	p.RunOnce()
	snap := p.Snapshot()
	if len(snap) != 2 || snap[0].ID != "b" || snap[1].ID != "c" {
		t.Fatalf("整轮替换后应只剩 b/c（排序稳定），实得 %v", snap)
	}
}

// 错误原因截取：净掉 dial 前缀，留下人能读的那半句。
func TestTrimErr(t *testing.T) {
	if got := trimErr("dial tcp 127.0.0.1:9999: connect: connection refused"); got != "connection refused" {
		t.Fatalf("实得 %q", got)
	}
	if got := trimErr("plain message"); got != "plain message" {
		t.Fatalf("无前缀应原样，实得 %q", got)
	}
}
