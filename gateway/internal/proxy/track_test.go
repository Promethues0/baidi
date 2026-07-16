package proxy

import (
	"net"
	"testing"
	"time"
)

func TestKillUser(t *testing.T) {
	c1a, c1b := net.Pipe()
	c2a, c2b := net.Pipe()
	c3a, _ := net.Pipe()
	defer c1b.Close()
	defer c2b.Close()
	defer c3a.Close()

	track("li.fang", c1a)
	track("li.fang", c2a)
	track("ext.zhou", c3a)

	if n := KillUser("li.fang"); n != 2 {
		t.Fatalf("应切断 li.fang 的 2 条隧道，实际 %d", n)
	}
	// 被切断的连接对端应立刻读到错误（隧道真实断开）
	for _, peer := range []net.Conn{c1b, c2b} {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("KillUser 后对端读取应报错（连接已关闭）")
		}
	}
	if n := KillUser("li.fang"); n != 0 {
		t.Fatalf("重复切断应为 0，实际 %d", n)
	}
	if n := KillUser("ext.zhou"); n != 1 {
		t.Fatalf("其他用户隧道不应被殃及且仍可切断，实际 %d", n)
	}
}

func TestUntrack(t *testing.T) {
	ca, cb := net.Pipe()
	defer cb.Close()
	track("li.fang", ca)
	untrack("li.fang", ca)
	if n := KillUser("li.fang"); n != 0 {
		t.Fatalf("untrack 后不应再有可切断连接，实际 %d", n)
	}
	_ = ca.Close()
}
