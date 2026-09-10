package dataplane

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── wave11 行动 11-②：敲门包「没发出去」必须有执行方 ──
//
// ★改造前 knockOne 的收尾是 `if sealed, e := Seal(); e == nil { if _, werr := Write(); werr == nil
// { markKnock() } }`——两个错误**整个被吞**：不打日志、不写 knockErr、也不动 knockOK。
// 于是发不出去的那一轮在健康行上与「什么都没发生」完全同形，界面停在上一次成功的
// `knock=true err=-`（绿色「已接入」），而用户看到的是隧道莫名不通、客户端一言不发。
//
// ★「UDP 的 Write 不会失败」是错觉：这是 net.Dial 出来的**已连接** socket，内核会把上一次
// 发包收到的 ICMP 端口不可达/主机不可达挂回来，下一次 Write 直接 ECONNREFUSED；
// 本机路由不通时当场 "no route to host"。这两种恰恰是最该说出来的形态
// （网关没在听 SPA 口 / 路由到不了那台落点）。
//
// ★用例注入 dialSPA 而不是真开一个 UDP 口：ICMP 挂回来是 OS 相关且时序相关的行为，
// 真端口写出来的用例必然间歇红——那样的用例挡不住任何一次回退。

// errConn 是一个 Write 恒失败的 net.Conn（其余方法不被调用）。
type errConn struct {
	net.Conn
	err error
}

func (c *errConn) Write([]byte) (int, error) { return 0, c.err }
func (c *errConn) Close() error              { return nil }

// grantControl 造一个正常签发敲门令牌的假控制面。
func grantControl(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"a.b.c","tunnelTicket":"t.t.t"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestKnockWriteFailureSurfaces 敲门包发不出去时：不得置 knock 位，且必须留下敲门类失败原因。
//
// ★变异实测：把 knockOne 的 Write 错误分支改回 `if _, err := uc.Write(sealed); err == nil
// { t.markKnock() }`（即吞掉错误），本用例三条断言全红。
func TestKnockWriteFailureSurfaces(t *testing.T) {
	control := grantControl(t)
	tn := newTunneler(&Config{Control: control.URL, Token: "sess",
		SpaAddr: "10.0.0.1:18201", ProxyAddr: "127.0.0.1:1"})
	tn.dialSPA = func(string) (net.Conn, error) {
		return &errConn{err: errors.New("write udp 10.0.0.1:18201: connect: connection refused")}, nil
	}
	tn.knock()

	s := tn.Snapshot()
	if s.Knock {
		t.Fatal("包根本没发出去，knock 位不得置真——界面会据此显示「已接入」")
	}
	if s.KnockErr == "" {
		t.Fatal("敲门包发送失败被吞掉了：健康行上与「什么都没发生」完全同形")
	}
	if !strings.Contains(s.KnockErr, "connection refused") {
		t.Fatalf("必须原样带出内核给的原因（那是「网关没在听 SPA 口」的唯一线索），得 %q", s.KnockErr)
	}
	// 前缀是跨轨契约：桌面端 tunnel.ts 的 classifyFail 按它判「敲门类 / 隧道类」，
	// 分错类会让一条持续失败被一次无关的成功擦掉（或反过来永远粘住）。
	if !strings.HasPrefix(s.KnockErr, "SPA 敲门包发送失败：") {
		t.Fatalf("敲门类失败必须带约定前缀，得 %q", s.KnockErr)
	}
}

// TestKnockWriteFailureThenSuccessRecovers 发送恢复之后失败原因要清掉——
// 留着会让一次早已恢复的瞬时失败永远挂在界面上。
func TestKnockWriteFailureThenSuccessRecovers(t *testing.T) {
	control := grantControl(t)
	spa, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer spa.Close()

	tn := newTunneler(&Config{Control: control.URL, Token: "sess",
		SpaAddr: spa.LocalAddr().String(), ProxyAddr: "127.0.0.1:1"})
	fail := errors.New("write udp: connect: connection refused")
	tn.dialSPA = func(string) (net.Conn, error) { return &errConn{err: fail}, nil }
	tn.knock()
	if tn.Snapshot().KnockErr == "" {
		t.Fatal("首轮应记下失败")
	}

	tn.dialSPA = func(addr string) (net.Conn, error) { return net.Dial("udp", addr) }
	tn.knock()
	s := tn.Snapshot()
	if !s.Knock || s.KnockErr != "" {
		t.Fatalf("下一轮真发出去之后应清掉敲门类失败，得 %+v", s)
	}
	// 包确实到了对面（不是只把状态改绿）。
	_ = spa.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := spa.ReadFrom(make([]byte, 2048)); err != nil {
		t.Fatalf("SPA 口应收到敲门包：%v", err)
	}
}
