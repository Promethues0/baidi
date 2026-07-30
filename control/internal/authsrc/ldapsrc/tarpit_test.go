package ldapsrc

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"baidi.dev/control/internal/authsrc"
)

// tarpit 起一个只接 TCP、永不回任何字节的监听器（内核完成三次握手，应用层装死）。
//
// ★这是最难查的一类目录故障：TCP 层完全正常，所以拨号超时永远不触发；
// 卡死的是 LDAP 层的等响应。真实成因是目录守护进程卡死、或中间有会 ACK 的
// tarpit/状态防火墙。
func tarpit(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// 收下连接就什么都不做：不回 LDAP 响应，也不关闭。
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

// StartTLS 必须受 RequestTimeout 约束。
//
// ★go-ldap 的 requestTimeout 初值为 0 = **不挂任何定时器**，所以 SetTimeout 若排在
// StartTLS 之后，那次扩展操作会无限阻塞：每次登录挂死一个 handler goroutine + 一个
// fd + go-ldap 的两个内部协程，全程零日志，反复重试即可耗光控制面的 fd。
// 这个用例失败的形态是**超时**（测试挂住），不是断言不通过——所以给它单独的
// 时间上限，而不是靠 go test 的全局超时。
func TestDial_StartTLS对着装死的目录必须超时而不是挂死(t *testing.T) {
	c := Config{
		Kind: authsrc.KindLDAP, Host: "127.0.0.1", Port: tarpit(t),
		TLS: TLSModeStartTLS, BaseDN: baseDN,
		ConnectTimeout: 3 * time.Second,
		RequestTimeout: 500 * time.Millisecond,
		Logger:         discardLogger(),
	}
	p := newProvider(t, c)

	done := make(chan error, 1)
	go func() {
		_, err := p.Authenticate(context.Background(), "alice", "任意口令")
		done <- err
	}()

	select {
	case err := <-done:
		// ★必须归为「认证源不可用」而不是「密码错误」：后者会让运维去查用户，
		// 而问题在目录服务器上。
		if !errors.Is(err, authsrc.ErrSourceUnavailable) {
			t.Fatalf("目录装死应报「认证源不可用」，实得: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StartTLS 对着装死的目录挂死了——RequestTimeout 没有覆盖握手阶段")
	}
}
