package proxy

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/resource"
	"baidi.dev/gateway/internal/secevent"
	"baidi.dev/gateway/internal/spa"
)

// ── wave8 行动 8：隧道放行留痕的**接线**断言 ──
//
// ★这条用例存在的唯一理由是接线：secevent 包自己测得很全，控制面消费侧也测了，
// 但 proxy.go 里那行 rep.ReportAllow 被删掉的话，上述两组照样全绿——
// 而「隧道路由命中」正是 FR-AUDIT-05 唯一的数据源。
// （wave8 行动 2 的教训：只测纯函数时，把接线删掉纯函数用例一条都不会红。）

type capture struct {
	mu   sync.Mutex
	recs []struct {
		cat, src, detail string
		allow            bool
	}
}

func (c *capture) sink(cat, src, detail string, count int, allow bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, struct {
		cat, src, detail string
		allow            bool
	}{cat, src, detail, allow})
}

func (c *capture) allowRecs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, r := range c.recs {
		if r.allow {
			out = append(out, r.cat+"|"+r.detail)
		}
	}
	return out
}

// tcpPair 起一个真 TCP 监听并接一条连接，返回 (客户端侧, 服务端侧)。
//
// ★不能用 net.Pipe：它的 RemoteAddr 是 "pipe"，而 handle 首行就拿它查放行窗口
// （hostOf(c.RemoteAddr())），于是永远命中不了 127.0.0.1 那条授权。
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起监听失败：%v", err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败：%v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("接受失败：%v", r.err)
	}
	t.Cleanup(func() { cli.Close(); r.c.Close() })
	return cli, r.c
}

// TestTunnelRouteHitReportsAllow 走通一次「已敲门 + 有授权」的隧道连接，
// 断言它经 secevent 上报了一条放行。
func TestTunnelRouteHitReportsAllow(t *testing.T) {
	// 真后端：收到连接就回一个字节，让 handle 能走完拨号那一步。
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起后端失败：%v", err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("ok"))
			_ = c.Close()
		}
	}()

	reg := resource.New("")
	reg.Replace([]resource.Resource{{
		ID: "res-git", Backend: backend.Addr().String(),
		AllowUsers: []string{"zhang.wei"},
	}})

	al := spa.NewAllowlist()
	al.Allow("127.0.0.1", "zhang.wei", "user", time.Minute)

	cap := &capture{}
	rep := secevent.New(cap.sink)

	cli, srv := tcpPair(t)
	done := make(chan struct{})
	go func() { handle(srv, reg, al, rep); close(done) }()

	// 前导：CONNECT <资源 id>\n
	_ = cli.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := cli.Write([]byte("CONNECT res-git\n")); err != nil {
		t.Fatalf("写前导失败：%v", err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	_, _ = cli.Read(buf) // 后端那个 "ok"（读不到也不影响本用例的断言）
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle 没有返回")
	}

	got := cap.allowRecs()
	if len(got) == 0 {
		t.Fatal("隧道路由命中没有上报放行——那行 ReportAllow 是 FR-AUDIT-05 唯一的数据源，" +
			"删掉它 secevent 与控制面两组用例照样全绿")
	}
	rec := got[0]
	if !strings.HasPrefix(rec, "tunnel-allow|") {
		t.Errorf("类别应是 tunnel-allow，得到 %q", rec)
	}
	for _, want := range []string{"zhang.wei", "res-git"} {
		if !strings.Contains(rec, want) {
			t.Errorf("放行留痕要点名账号与资源，缺 %q：%s", want, rec)
		}
	}
}

// TestUnauthorizedTunnelReportsDenyNotAllow 未敲门直连只报拒绝，不报放行。
func TestUnauthorizedTunnelReportsDenyNotAllow(t *testing.T) {
	reg := resource.New("")
	al := spa.NewAllowlist() // 谁都没敲过门
	cap := &capture{}
	rep := secevent.New(cap.sink)

	cli, srv := tcpPair(t)
	done := make(chan struct{})
	go func() { handle(srv, reg, al, rep); close(done) }()
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = cli.Read(make([]byte, 1))
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handle 没有返回")
	}

	if got := cap.allowRecs(); len(got) != 0 {
		t.Fatalf("未敲门直连绝不该产生放行留痕：%v", got)
	}
	cap.mu.Lock()
	n := len(cap.recs)
	cap.mu.Unlock()
	if n == 0 {
		t.Fatal("未敲门直连应上报一条拒绝")
	}
}
