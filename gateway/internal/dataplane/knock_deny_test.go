package dataplane

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"baidi.dev/gateway/internal/knock"
)

// knock() 遇 control 定性拒绝（403）应向 deny 通道上报一次 ErrDenied，
// 且不再向 SPA 端口发敲门包（被封禁客户端不该继续空转）。
func TestKnockSignalsDenyOn403(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"账号已被禁用，无法接入"}}`))
	}))
	defer control.Close()

	// 一个真实 UDP 监听，用来观察是否收到敲门包（应当收不到）。
	spa, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer spa.Close()

	tn := &tunneler{
		cfg:  &Config{Control: control.URL, Token: "sess", SpaAddr: spa.LocalAddr().String()},
		deny: make(chan error, 1),
	}
	tn.knock()

	select {
	case derr := <-tn.deny:
		if !errors.Is(derr, knock.ErrDenied) {
			t.Fatalf("deny 通道应收到 ErrDenied，得到 %v", derr)
		}
	default:
		t.Fatal("403 后 deny 通道无上报")
	}

	// 确认没有敲门包被发出。
	_ = spa.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 512)
	if n, _, err := spa.ReadFrom(buf); err == nil {
		t.Fatalf("被拒后不应发敲门包，却收到 %d 字节", n)
	}
}

// denyOnce：多次 knock() 只上报一次，不阻塞（deny 通道容量 1）。
func TestKnockDenyReportedOnce(t *testing.T) {
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer control.Close()

	tn := &tunneler{
		cfg:  &Config{Control: control.URL, Token: "sess", SpaAddr: "127.0.0.1:1"},
		deny: make(chan error, 1),
	}
	done := make(chan struct{})
	go func() {
		tn.knock()
		tn.knock() // 第二次不得阻塞（若重复写满容量-1 通道会死锁）
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("重复 knock 阻塞：denyOnce 未生效")
	}
	if len(tn.deny) != 1 {
		t.Fatalf("deny 应恰好上报一次，通道内 %d 条", len(tn.deny))
	}
}
