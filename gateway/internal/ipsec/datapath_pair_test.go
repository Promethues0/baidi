package ipsec

import (
	"bytes"
	"testing"
	"time"
)

// 辅助一律加 dpt 前缀（datapath test）。

func dptRead(t *testing.T, d Datapath, bufLen int) []byte {
	t.Helper()
	type res struct {
		n   int
		err error
		buf []byte
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, bufLen)
		n, err := d.ReadOutbound(buf)
		ch <- res{n, err, buf}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("读出向包失败：%v", r.err)
		}
		return r.buf[:r.n]
	case <-time.After(2 * time.Second):
		t.Fatalf("读出向包超时")
		return nil
	}
}

// 方向必须是交叉的：一端写进去的入向包，从**另一端**作为出向包出来。
// 写成自环（自己写自己读）的话，两条泵接上去会各自对着空气跑，
// 而测试照样绿——这是这个测试替身最容易写反的地方。
func TestPairDatapathCrossConnected(t *testing.T) {
	a, host := NewPairDatapath(1400)
	defer a.Close()

	up := []byte("内网主机发出的包 → 应当被 a 当作出向包读走")
	if err := host.WriteInbound(up); err != nil {
		t.Fatalf("写入失败：%v", err)
	}
	if got := dptRead(t, a, 4096); !bytes.Equal(got, up) {
		t.Errorf("a 侧出向包不符：期望 %q，实得 %q", up, got)
	}

	down := []byte("隧道解封出来的包 → 应当被 host 读到")
	if err := a.WriteInbound(down); err != nil {
		t.Fatalf("写入失败：%v", err)
	}
	if got := dptRead(t, host, 4096); !bytes.Equal(got, down) {
		t.Errorf("host 侧出向包不符：期望 %q，实得 %q", down, got)
	}
}

// ★投递必须是拷贝。泵的解封缓冲下一轮就会被复用，
// 不拷贝的话对端读到的是一段随时会变的内存——这类 bug 只在高并发下现形，
// 而现形时的样子是"偶尔收到一个内容错乱的包"，几乎不可能追到根因。
func TestPairDatapathCopiesPayload(t *testing.T) {
	a, host := NewPairDatapath(1400)
	defer a.Close()

	buf := []byte("原始内容")
	if err := host.WriteInbound(buf); err != nil {
		t.Fatalf("写入失败：%v", err)
	}
	copy(buf, []byte("污染内容")) // 调用方复用了缓冲
	got := dptRead(t, a, 128)
	if !bytes.Equal(got, []byte("原始内容")) {
		t.Errorf("投递没有拷贝，读到了被复用的缓冲：实得 %q", got)
	}
}

// ★缓冲不够时必须报错，不能截断。
// 截断出来的半个 IP 包会被正常加密、被对端正常解密、再交给协议栈，
// 然后表现为"连接莫名挂住"——离根因十万八千里。
func TestPairDatapathRefusesToTruncate(t *testing.T) {
	a, host := NewPairDatapath(1400)
	defer a.Close()

	big := bytes.Repeat([]byte{0xAB}, 200)
	if err := host.WriteInbound(big); err != nil {
		t.Fatalf("写入失败：%v", err)
	}
	small := make([]byte, 100)
	n, err := a.ReadOutbound(small)
	if err == nil {
		t.Fatalf("缓冲不足时应当报错，实际返回了 %d 字节（发生了截断）", n)
	}
	// 报错要能指导排障：得说清"多大的包、多大的缓冲"。
	for _, want := range []string{"200", "100"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("错误信息里缺少 %q，无法据以排障：%v", want, err)
		}
	}
}

// 队列满了报错而不是静默丢弃：这是测试替身，
// 悄悄丢包会把"泵卡住了"这种真 bug 伪装成"偶尔少几个包"的抖动。
func TestPairDatapathReportsQueueFull(t *testing.T) {
	a, host := NewPairDatapath(1400)
	defer a.Close()

	var lastErr error
	for i := 0; i < pairQueueLen+10; i++ {
		if err := host.WriteInbound([]byte{byte(i)}); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Fatalf("队列写满了却没有报错")
	}
}

func TestPairDatapathCloseIsSharedAndIdempotent(t *testing.T) {
	a, host := NewPairDatapath(0)
	if a.MTU() != DefaultTunnelMTU {
		t.Errorf("mtu<=0 应当取默认值 %d，实得 %d", DefaultTunnelMTU, a.MTU())
	}

	done := make(chan error, 1)
	go func() {
		_, err := host.ReadOutbound(make([]byte, 64))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)

	// 剪断一头，另一头也该失效——它就是一根网线。
	if err := a.Close(); err != nil {
		t.Fatalf("Close 失败：%v", err)
	}
	select {
	case err := <-done:
		if err != ErrClosed {
			t.Errorf("Close 后 ReadOutbound 应返回 ErrClosed，实得 %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Close 没能唤醒阻塞中的 ReadOutbound")
	}
	if err := host.WriteInbound([]byte{1}); err != ErrClosed {
		t.Errorf("Close 后 WriteInbound 应返回 ErrClosed，实得 %v", err)
	}
	if err := host.Close(); err != nil {
		t.Errorf("重复 Close 应当无害，实得 %v", err)
	}
}
