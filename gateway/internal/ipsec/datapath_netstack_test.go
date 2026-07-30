package ipsec

import (
	"context"
	"io"

	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// 本文件证明的是一件事：**netstack 数据面上能跑真的 TCP**。
//
// 为什么这条测试的分量比它的行数大得多：整套 IPSec 的验证链里，
// 「内存管道里的字节过去了」这种断言对"加密其实是恒等变换""流量其实走了旁路"
// 几乎没有分辨力。只有让一端真的 http.Get、另一端真的 net.Listener 应答，
// 中途任何一环（IP 头、校验和、分段、路由、MTU）写错都会直接表现为连不上。
//
// 这里先把 netstack 这一环单独夹出来验（两端直连、不过 ESP），
// 目的是让"隧道不通"时能立刻排除掉数据面本身的问题——
// 否则 e2e 一红，怀疑对象是十几个环节。
//
// 辅助一律加 nst 前缀（netstack test）。

// nstRelay 把 a 的出向包直接投给 b（模拟一条零丢包、零延迟的理想链路）。
func nstRelay(t *testing.T, a, b Datapath) {
	t.Helper()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := a.ReadOutbound(buf)
			if err != nil {
				return
			}
			if err := b.WriteInbound(buf[:n]); err != nil {
				return
			}
		}
	}()
}

func TestNetstackDatapathRealTCP(t *testing.T) {
	client, err := NewNetstackDatapath(netip.MustParsePrefix("10.60.0.1/24"), 1400)
	if err != nil {
		t.Fatalf("建客户端协议栈失败：%v", err)
	}
	defer client.Close()
	server, err := NewNetstackDatapath(netip.MustParsePrefix("10.60.0.9/24"), 1400)
	if err != nil {
		t.Fatalf("建服务端协议栈失败：%v", err)
	}
	defer server.Close()

	nstRelay(t, client, server)
	nstRelay(t, server, client)

	ln, err := server.ListenTCP(80)
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	defer ln.Close()

	const body = "白帝 IPSec netstack 数据面自检"
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	hc := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DialContext: client.DialContext},
	}
	resp, err := hc.Get("http://10.60.0.9/")
	if err != nil {
		t.Fatalf("HTTP 请求失败（说明数据面这一环本身就不通，与 ESP 无关）：%v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读响应体失败：%v", err)
	}
	if string(got) != body {
		t.Errorf("响应体不符：期望 %q，实得 %q", body, got)
	}
}

// 出向包必须是**完整的 IP 包**（含 IP 头），否则 ESP 隧道模式的 NextHeader=4
// 就名不副实了：对端解封后交给协议栈的会是一段 TCP 分段，表现为"解密成功但什么都收不到"。
func TestNetstackDatapathEmitsFullIPPackets(t *testing.T) {
	d, err := NewNetstackDatapath(netip.MustParsePrefix("10.61.0.1/24"), 1400)
	if err != nil {
		t.Fatalf("建协议栈失败：%v", err)
	}
	defer d.Close()

	// 往一个没人应答的地址拨，拨号本身会失败，但 SYN 一定会被发出来。
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go func() {
		c, err := d.DialTCP(ctx, netip.MustParseAddrPort("10.61.0.9:80"))
		if err == nil {
			_ = c.Close()
		}
	}()

	type res struct {
		pkt []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, 65535)
		n, err := d.ReadOutbound(buf)
		ch <- res{buf[:n], err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("读出向包失败：%v", r.err)
		}
		if len(r.pkt) < 20 {
			t.Fatalf("出向包只有 %d 字节，连一个 IPv4 头都不够", len(r.pkt))
		}
		if v := r.pkt[0] >> 4; v != 4 {
			t.Fatalf("出向包首字节高 4 位应为 4（IPv4 版本号），实得 %d —— 说明吐出来的不是完整 IP 包", v)
		}
		src := netip.AddrFrom4([4]byte(r.pkt[12:16]))
		dst := netip.AddrFrom4([4]byte(r.pkt[16:20]))
		if src != netip.MustParseAddr("10.61.0.1") || dst != netip.MustParseAddr("10.61.0.9") {
			t.Errorf("源/目的地址不符：实得 %s → %s", src, dst)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("协议栈没有吐出任何出向包")
	}
}

func TestNetstackDatapathRejectsBadInbound(t *testing.T) {
	d, err := NewNetstackDatapath(netip.MustParsePrefix("10.62.0.1/24"), 0)
	if err != nil {
		t.Fatalf("建协议栈失败：%v", err)
	}
	defer d.Close()

	if d.MTU() != DefaultTunnelMTU {
		t.Errorf("mtu<=0 应取默认值 %d，实得 %d", DefaultTunnelMTU, d.MTU())
	}
	if err := d.WriteInbound(nil); err == nil {
		t.Errorf("空包应当被拒绝")
	}
	// 非 IP 报文（首字节高 4 位既不是 4 也不是 6）：多半是 ESP 解密出了问题，
	// 这里必须拒绝而不是把垃圾喂给协议栈。
	if err := d.WriteInbound([]byte{0x20, 0x00, 0x00}); err == nil {
		t.Errorf("非 IP 报文应当被拒绝")
	} else if !strings.Contains(err.Error(), "0x20") {
		t.Errorf("错误信息应带上实际首字节以便排障，实得：%v", err)
	}
}

func TestNetstackDatapathCloseUnblocksRead(t *testing.T) {
	d, err := NewNetstackDatapath(netip.MustParsePrefix("10.63.0.1/24"), 1400)
	if err != nil {
		t.Fatalf("建协议栈失败：%v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, e := d.ReadOutbound(make([]byte, 2048))
		done <- e
	}()
	time.Sleep(20 * time.Millisecond)
	if err := d.Close(); err != nil {
		t.Fatalf("Close 失败：%v", err)
	}
	select {
	case e := <-done:
		if e != ErrClosed {
			t.Errorf("Close 后 ReadOutbound 应返回 ErrClosed，实得 %v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Close 没能唤醒阻塞中的 ReadOutbound")
	}
	if err := d.Close(); err != nil {
		t.Errorf("重复 Close 应当无害，实得 %v", err)
	}
}

func TestNetstackDatapathInvalidLocal(t *testing.T) {
	if _, err := NewNetstackDatapath(netip.Prefix{}, 1400); err == nil {
		t.Errorf("无效的本机网段应当被拒绝")
	}
}

// DialContext 只接 TCP，且没有 DNS——把域名传进来必须明确报错，
// 否则调用方会得到一个含糊的"拨号失败"，然后去查网络而不是查自己传错了参数。
func TestNetstackDatapathDialContextGuards(t *testing.T) {
	d, err := NewNetstackDatapath(netip.MustParsePrefix("10.64.0.1/24"), 1400)
	if err != nil {
		t.Fatalf("建协议栈失败：%v", err)
	}
	defer d.Close()

	if _, err := d.DialContext(context.Background(), "udp", "10.64.0.9:80"); err == nil {
		t.Errorf("UDP 应当被明确拒绝")
	}
	_, err = d.DialContext(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Errorf("域名应当被明确拒绝（本栈没有 DNS）")
	} else if !strings.Contains(err.Error(), "DNS") {
		t.Errorf("错误信息应说明本栈没有 DNS，实得：%v", err)
	}
}
