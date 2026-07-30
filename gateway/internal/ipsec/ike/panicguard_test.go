package ike

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// IKE 是网关上第一个「非暗」的对外端口：它必须监听 UDP 500/4500，且在任何认证之前
// 就解析对端报文。因此「一个畸形包能不能打掉整个进程」是安全属性，不是健壮性偏好。
//
// 这两条测试守的是 engine.handle / runTimersGuarded 的 panic 兜底。没有它们，
// 将来有人"顺手清理掉看起来多余的 recover"时不会有任何信号——而回归的表现是
// 远程 DoS，不是测试变红。

// pgTransport 是一个可注入报文的假 Transport：Recv 依次吐出预置报文，
// 吐完后阻塞到 ctx 结束（模拟静默的网络，而不是返回错误让引擎退出）。
type pgTransport struct {
	mu   sync.Mutex
	q    [][]byte
	done chan struct{}
	sent int
}

func newPGTransport(pkts ...[]byte) *pgTransport {
	return &pgTransport{q: pkts, done: make(chan struct{})}
}

func (t *pgTransport) Recv() (ipsec.Datagram, error) {
	t.mu.Lock()
	if len(t.q) > 0 {
		p := t.q[0]
		t.q = t.q[1:]
		t.mu.Unlock()
		return ipsec.Datagram{
			Kind:    ipsec.KindIKE,
			Local:   netip.MustParseAddrPort("127.0.0.1:15500"),
			Remote:  netip.MustParseAddrPort("127.0.0.1:15501"),
			Payload: p,
		}, nil
	}
	t.mu.Unlock()
	<-t.done
	return ipsec.Datagram{}, ipsec.ErrClosed
}

func (t *pgTransport) Send(d ipsec.Datagram) error {
	t.mu.Lock()
	t.sent++
	t.mu.Unlock()
	return nil
}

func (t *pgTransport) Close() error {
	close(t.done)
	return nil
}

// pgCapture 收集 Error 级别日志，供断言「兜底触发了且报得够响」。
type pgCapture struct {
	mu   sync.Mutex
	msgs []string
}

func (c *pgCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *pgCapture) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		c.mu.Lock()
		c.msgs = append(c.msgs, r.Message)
		c.mu.Unlock()
	}
	return nil
}

func (c *pgCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *pgCapture) WithGroup(string) slog.Handler      { return c }

func (c *pgCapture) contains(sub string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// 收包路径 panic 时：必须丢包并继续运行，绝不能让整个进程随一个畸形包一起消失。
//
// 用 OnESP 回调注入 panic 是刻意的——它是引擎里少数由外部实现填充的钩子，
// 能在不破坏引擎内部状态的前提下，真实走一遍「handle 内部炸了」的路径。
func TestHandlePanicIsContainedAndLogged(t *testing.T) {
	cap := &pgCapture{}
	tr := newPGTransport()

	e := NewEngine(EngineOptions{
		Transport: tr,
		Log:       slog.New(cap),
		Tick:      10 * time.Millisecond,
		OnESP: func(ipsec.Datagram) {
			panic("测试注入：模拟收包路径上的实现缺陷")
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()

	// 直接投一个 ESP 报文进 handle，触发 OnESP 里的 panic。
	e.handle(ipsec.Datagram{
		Kind:    ipsec.KindESP,
		Remote:  netip.MustParseAddrPort("127.0.0.1:15501"),
		Payload: []byte{0xde, 0xad, 0xbe, 0xef},
	})

	if !cap.contains("panic") {
		t.Fatal("收包路径 panic 必须被兜底并以 Error 级别记录——" +
			"兜底不是用来掩盖 panic 的，是让进程活着把 panic 报出来")
	}

	// 关键断言：引擎仍然活着。再投一个包不应 panic，Run 也不应已经退出。
	e.handle(ipsec.Datagram{
		Kind:    ipsec.KindESP,
		Remote:  netip.MustParseAddrPort("127.0.0.1:15501"),
		Payload: []byte{0x01, 0x02, 0x03, 0x04},
	})

	select {
	case err := <-done:
		t.Fatalf("引擎在 panic 后退出了（err=%v）——一个畸形包就能打掉整个站点组网", err)
	case <-time.After(50 * time.Millisecond):
		// 期望：仍在运行
	}

	cancel()
	tr.Close()
	<-done
}

// 定时器路径 panic 时：跳过本轮但进程继续。
//
// 定时器是自驱动的，一次 panic 若打掉进程，表现为「隧道好好的，过一会儿进程没了」，
// 比收包路径更难归因——所以这条兜底同样不能被重构掉。
func TestRunTimersPanicIsContained(t *testing.T) {
	cap := &pgCapture{}
	// ★注入必须在构造**之后**才生效：NewEngine 自己就会取一次当前时间
	// （cookie jar 的 secret 轮换需要），构造期 panic 测的是另一回事。
	var armed bool
	e := NewEngine(EngineOptions{
		Transport: newPGTransport(),
		Log:       slog.New(cap),
		Tick:      10 * time.Millisecond,
		// Now 是定时器路径每轮必经的调用点，是最贴近真实「定时器内部炸了」的注入位置。
		Now: func() time.Time {
			if armed {
				panic("测试注入：模拟定时器路径上的实现缺陷")
			}
			return time.Now()
		},
	})
	armed = true

	// 不经 Run，直接调被保护的入口——断言它自己就吞得住。
	e.runTimersGuarded()

	if !cap.contains("panic") {
		t.Fatal("定时器 panic 必须被兜底并以 Error 级别记录")
	}

	// 再来一轮仍不应炸穿。
	e.runTimersGuarded()
}
