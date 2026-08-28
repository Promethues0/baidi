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

// ctx 预算必须真的封住**整条**认证的墙上时间，而不是被逐请求超时乘上去。
//
// ★RequestTimeout 是**每个请求**的：一次口令认证要走两次拨号 + StartTLS
// + 服务账号 bind + search + 用户 bind。改造前 conn.SetTimeout 取的是静态配置值，
// 于是调用方给的整体预算完全管不住它——10s 的配置在 StartTLS 模式下最坏能挂到
// 约 60s。这正是「给 handler 挂个 deadline 就以为有超时了」的假象来源：
// go-ldap 的拨号与请求都不吃 ctx，ctx 只有被本包折算进超时字段才有效。
//
// 用例把 RequestTimeout 设得比预算**大得多**：若折算没生效，第一步 StartTLS
// 就会自己吃掉 5s，整体必然超出 2s 预算。
func TestAuthenticate_ctx预算封住整条认证而不是被逐请求超时乘上去(t *testing.T) {
	c := Config{
		Kind: authsrc.KindLDAP, Host: "127.0.0.1", Port: tarpit(t),
		TLS: TLSModeStartTLS, BaseDN: baseDN,
		ConnectTimeout: 3 * time.Second,
		RequestTimeout: 5 * time.Second, // 刻意远大于下面的预算
		Logger:         discardLogger(),
	}
	p := newProvider(t, c)

	const budget = 800 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_, err := p.Authenticate(ctx, "alice", "任意口令")
		if !errors.Is(err, authsrc.ErrSourceUnavailable) {
			t.Errorf("装死目录应归为认证源不可用，实得 %v", err)
		}
		done <- time.Since(start)
	}()

	select {
	case el := <-done:
		// 给一倍余量：折算是逐请求做的，最后一个请求可能刚好在预算边界上起步。
		if el > 2*budget {
			t.Fatalf("整条认证耗时 %v，远超 %v 的预算——ctx 没有被折算进逐请求超时，"+
				"调用方给的预算是假的", el, budget)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("认证在预算到期后仍然挂着——ctx 预算对 go-ldap 完全没有生效")
	}
}

// ctx 已过期时，折算出的请求超时**不得**是 0 或负数。
//
// ★go-ldap 的 conn.SetTimeout 对非正值不做任何 clamp，而它内部是
// `if requestTimeout > 0` 才起定时器——非正值不是快速失败，是**不挂定时器 = 无限阻塞**。
// 与 dialTimeout 那个坑、以及 timeLimitSeconds 向下取整到 0 变成「不限时」是同一族。
func TestRequestTimeout_ctx已过期时不会退化成永不超时(t *testing.T) {
	p := newProvider(t, Config{
		Kind: authsrc.KindLDAP, Host: "127.0.0.1", Port: 389, BaseDN: baseDN,
		RequestTimeout: 5 * time.Second, Logger: discardLogger(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), -time.Second) // 已过期
	defer cancel()
	if d := p.requestTimeout(ctx); d <= 0 {
		t.Fatalf("ctx 已过期时折算出 %v —— go-ldap 会据此不挂定时器，变成永不超时", d)
	}
}

// 没有 deadline 的 ctx 原样取配置值（不能因为「没 deadline」就退化成 1ms）。
func TestRequestTimeout_无deadline时取配置值(t *testing.T) {
	p := newProvider(t, Config{
		Kind: authsrc.KindLDAP, Host: "127.0.0.1", Port: 389, BaseDN: baseDN,
		RequestTimeout: 5 * time.Second, Logger: discardLogger(),
	})
	if d := p.requestTimeout(context.Background()); d != 5*time.Second {
		t.Fatalf("无 deadline 应取配置值 5s，实得 %v", d)
	}
}
