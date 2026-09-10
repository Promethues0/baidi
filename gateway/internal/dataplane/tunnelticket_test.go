package dataplane

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── wave11 行动 3：客户端把隧道身份票据挂到前导上 ──
//
// ★这条是**接线**用例。knock 包自己测了 FetchGrant 的解析，proxy 包测了票据校验，
// 但 dataplane 里那一行「preamble += " " + ticket」被删掉的话，上述两组照样全绿——
// 而现场后果是每条业务流在严格网关上被拒（"隧道时通时不通"，与网络问题同形）。
// 同一条教训在 wave8 行动 2 与 wave10 的桥接层各出现过一次。

// preambleCatcher 起一个假网关隧道口：只读第一行前导，交给调用方断言。
func preambleCatcher(t *testing.T) (addr string, lines chan string) {
	t.Helper()
	cert, _ := selfSigned(t, "baidi-gateway")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	t.Cleanup(func() { ln.Close() })
	lines = make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				line, _ := bufio.NewReader(c).ReadString('\n')
				lines <- line
			}()
		}
	}()
	return ln.Addr().String(), lines
}

// fakeControl 返回一个只回 knock-token 的控制面。tunnelTicket 为空即模拟**尚未升级**的控制面。
func fakeControl(t *testing.T, ticket string) *httptest.Server {
	t.Helper()
	body := `{"token":"tok-1"}`
	if ticket != "" {
		body = `{"token":"tok-1","tunnelTicket":"` + ticket + `","tunnelTicketExpiresIn":300}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runPreamble 敲一轮门（取回 Grant）后拨一条业务流，返回网关收到的前导行。
func runPreamble(t *testing.T, ticket string) string {
	t.Helper()
	control := fakeControl(t, ticket)
	proxyAddr, lines := preambleCatcher(t)
	spa, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { spa.Close() })

	tl := newTunneler(&Config{
		Control: control.URL, Token: "sess",
		Resmap:    map[string]string{"10.9.0.1:443": "res-oa"},
		Endpoints: []Endpoint{{ID: "gw-a", SPAAddr: spa.LocalAddr().String(), ProxyAddr: proxyAddr}},
	})
	tl.knock() // 取 Grant：票据在这一步进 tunneler

	local, peer := net.Pipe()
	defer peer.Close()
	go tl.tunnel(local, "10.9.0.1:443")
	select {
	case line := <-lines:
		return line
	case <-time.After(5 * time.Second):
		t.Fatal("网关没有收到前导")
		return ""
	}
}

// TestPreambleCarriesTunnelTicket 取到票据后，每条业务流的前导都必须带上它。
func TestPreambleCarriesTunnelTicket(t *testing.T) {
	got := strings.TrimRight(runPreamble(t, "tk-abc123"), "\n")
	if got != "CONNECT res-oa tk-abc123" {
		t.Fatalf("★前导必须带上隧道身份票据，实得 %q；"+
			"少了它，严格网关会拒掉每一条业务流，而症状与网络抖动完全同形", got)
	}
}

// TestPreambleStaysTwoFieldsWhenControlHasNoTicket 控制面还没升级时，退回两段的老格式。
//
// ★在客户端这里 fail-closed 是错的方向：「控制面还没发票据」与「这条连接没有身份」
// 是两件事，该由网关按它自己的严格姿态去拒（它知道 BAIDI_GW_TUNNEL_ID_STRICT 是什么，
// 客户端不知道）。客户端在这里编一个值或塞敲门令牌顶替，只会把前者伪装成"票据无效"。
func TestPreambleStaysTwoFieldsWhenControlHasNoTicket(t *testing.T) {
	got := strings.TrimRight(runPreamble(t, ""), "\n")
	if got != "CONNECT res-oa" {
		t.Fatalf("控制面没下发票据时应退回两段的老格式，实得 %q", got)
	}
}

// TestTicketNotClearedByAFailedRefresh 一次取票失败不得把手里能用的那张抹掉。
//
// ★多落点是并发敲门的，其中一台的取令牌请求偶发失败（或对上了一个还没升级的副本）
// 若把票据清空，下一条业务流就退回无票据形态——在严格网关上表现为"隧道时通时不通"。
func TestTicketNotClearedByAFailedRefresh(t *testing.T) {
	tl := newTunneler(&Config{})
	tl.setTicket("tk-good")
	tl.setTicket("") // 模拟一次没带回票据的刷新
	if got := tl.currentTicket(); got != "tk-good" {
		t.Fatalf("空票据不得覆盖已有的那张，实得 %q", got)
	}
	tl.setTicket("tk-newer")
	if got := tl.currentTicket(); got != "tk-newer" {
		t.Fatalf("新票据应覆盖旧的，实得 %q", got)
	}
}
