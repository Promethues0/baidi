package ipsec

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
)

// 本文件盯的是 UDP 通道上最容易写错、且写错以后**只在 NAT 路径炸**的那几处：
// non-ESP marker 的加减、4500 上的三分流、以及"哪类报文只能从哪个端口出去"。
//
// 为什么要用一个裸 net.UDPConn 当对端而不是两个 UDPTransport 对拨：
// 两个自己人对拨只能证明"我发的我自己收得回来"，对「marker 加了没有」这种
// 线格式问题完全没有分辨力——两端犯同一个错时测试照样全绿。
// 只有拿裸 socket 去读**线上的原始字节**，才算真的验了线格式。
//
// 辅助一律加 utt 前缀（udp transport test）。

func uttTransport(t *testing.T) *UDPTransport {
	t.Helper()
	tr, err := NewUDPTransport(netip.MustParseAddr("127.0.0.1"), 0, 0)
	if err != nil {
		t.Fatalf("绑定 UDP 端口失败：%v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr.(*UDPTransport)
}

// uttPeer 一个裸 UDP 端点，用来读线上的原始字节 / 灌入构造好的报文。
func uttPeer(t *testing.T) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("裸 UDP 端点绑定失败：%v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// uttFakeIKE 造一段长度合法的假 IKE 报文（内容不重要，只要够一个头）。
func uttFakeIKE(marker byte) []byte {
	b := make([]byte, ikeHeaderLen+8)
	for i := range b {
		b[i] = marker
	}
	return b
}

func uttRecv(t *testing.T, tr *UDPTransport) Datagram {
	t.Helper()
	ch := make(chan Datagram, 1)
	go func() {
		d, err := tr.Recv()
		if err == nil {
			ch <- d
		}
	}()
	select {
	case d := <-ch:
		return d
	case <-time.After(2 * time.Second):
		t.Fatalf("等待收包超时")
		return Datagram{}
	}
}

// ★核心断言：从 4500 发出的 IKE 报文，线上必须有 4 字节全零 marker；
// 从 500 发出的**不能有**。
//
// 写错的后果特别隐蔽：AUTH 的签名字节串规定从 SPIi 第一字节开始、不含 marker。
// 一旦上层拿到的是带 marker 的报文并拿去签名，非 NAT 路径全绿，
// 只有走 4500 的 NAT 路径认证失败——而报错还是那句「认证失败」。
func TestUDPTransportMarkerOnWire(t *testing.T) {
	tr := uttTransport(t)
	peer, peerAddr := uttPeer(t)
	payload := uttFakeIKE(0xA5)

	// 从 4500 侧发：线上应当是 marker ‖ payload
	if err := tr.Send(Datagram{Kind: KindIKE, Local: tr.LocalNAT(), Remote: peerAddr, Payload: payload}); err != nil {
		t.Fatalf("从 4500 发 IKE 失败：%v", err)
	}
	buf := make([]byte, 2048)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("裸端点收包失败：%v", err)
	}
	got := buf[:n]
	if len(got) != 4+len(payload) {
		t.Fatalf("4500 上的 IKE 报文长度应为 4(marker)+%d=%d，实得 %d", len(payload), 4+len(payload), len(got))
	}
	if !bytes.Equal(got[:4], []byte{0, 0, 0, 0}) {
		t.Errorf("4500 上的 IKE 报文缺少 non-ESP marker：前 4 字节 = % x", got[:4])
	}
	if !bytes.Equal(got[4:], payload) {
		t.Errorf("marker 之后的字节被改动了：期望 % x，实得 % x", payload, got[4:])
	}

	// 从 500 侧发：线上必须是裸报文，一个字节都不能多。
	if err := tr.Send(Datagram{Kind: KindIKE, Local: tr.LocalIKE(), Remote: peerAddr, Payload: payload}); err != nil {
		t.Fatalf("从 500 发 IKE 失败：%v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("裸端点收包失败：%v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("500 上的 IKE 报文不该带 marker：期望 % x，实得 % x", payload, buf[:n])
	}
}

// 4500 上的三分流：marker+IKE / ESP / keepalive 三类必须被正确区分，
// 且 IKE 那一类交到上层时 marker 必须已经被剥掉。
func TestUDPTransportClassifyOn4500(t *testing.T) {
	tr := uttTransport(t)
	peer, _ := uttPeer(t)
	dst := net.UDPAddrFromAddrPort(tr.LocalNAT())

	// ① marker + IKE
	ike := uttFakeIKE(0x5A)
	if _, err := peer.WriteToUDP(append([]byte{0, 0, 0, 0}, ike...), dst); err != nil {
		t.Fatalf("发送失败：%v", err)
	}
	d := uttRecv(t, tr)
	if d.Kind != KindIKE {
		t.Errorf("带 marker 的报文应判为 KindIKE，实得 %d", d.Kind)
	}
	if !bytes.Equal(d.Payload, ike) {
		t.Errorf("marker 未被剥掉或载荷被改动：期望 % x，实得 % x", ike, d.Payload)
	}

	// ② ESP（首 4 字节是非零 SPI）
	esp := []byte{0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1, 0xde, 0xad}
	if _, err := peer.WriteToUDP(esp, dst); err != nil {
		t.Fatalf("发送失败：%v", err)
	}
	d = uttRecv(t, tr)
	if d.Kind != KindESP {
		t.Errorf("非零 SPI 开头的报文应判为 KindESP，实得 %d", d.Kind)
	}
	if !bytes.Equal(d.Payload, esp) {
		t.Errorf("ESP 载荷必须原样上交（含 SPI）：期望 % x，实得 % x", esp, d.Payload)
	}

	// ③ NAT keepalive（单字节 0xFF）
	if _, err := peer.WriteToUDP([]byte{0xFF}, dst); err != nil {
		t.Fatalf("发送失败：%v", err)
	}
	d = uttRecv(t, tr)
	if d.Kind != KindKeepalive {
		t.Errorf("单字节 0xFF 应判为 KindKeepalive，实得 %d", d.Kind)
	}
	if _, _, ka := tr.Stats(); ka != 1 {
		t.Errorf("keepalive 计数应为 1，实得 %d", ka)
	}
}

// 畸形包必须被静默丢弃（不回任何东西，免得把自己变成反射放大器），但要计数。
//
// 断言方式刻意不用超时：先灌畸形包、再灌一个合法包，如果第一个收到的就是合法包，
// 就证明畸形包确实被丢了——这比"等 2 秒没收到"稳定得多，也快得多。
func TestUDPTransportDropsMalformed(t *testing.T) {
	tr := uttTransport(t)
	peer, _ := uttPeer(t)
	dst := net.UDPAddrFromAddrPort(tr.LocalNAT())

	for _, bad := range [][]byte{
		{},           // 空包
		{0x01, 0x02}, // 短到不可能是任何一类
		{0, 0, 0, 0}, // 只有 marker，其后一个字节都没有
		append([]byte{0, 0, 0, 0}, make([]byte, ikeHeaderLen-1)...), // marker 后不足一个 IKE 头
	} {
		if _, err := peer.WriteToUDP(bad, dst); err != nil {
			t.Fatalf("发送失败：%v", err)
		}
	}
	good := []byte{0x11, 0x22, 0x33, 0x44, 0, 0, 0, 9}
	if _, err := peer.WriteToUDP(good, dst); err != nil {
		t.Fatalf("发送失败：%v", err)
	}

	d := uttRecv(t, tr)
	if !bytes.Equal(d.Payload, good) {
		t.Fatalf("畸形包没有被丢弃：第一个收到的应当是那个合法 ESP 包，实得 % x", d.Payload)
	}
	short, badMarker, _ := tr.Stats()
	if short == 0 || badMarker == 0 {
		t.Errorf("丢弃必须计数（静默且不计数等于给自己蒙眼）：short=%d badMarker=%d", short, badMarker)
	}
}

// 500 端口上不存在 marker，短包同样丢弃。
func TestUDPTransportOn500NoMarker(t *testing.T) {
	tr := uttTransport(t)
	peer, _ := uttPeer(t)
	dst := net.UDPAddrFromAddrPort(tr.LocalIKE())

	if _, err := peer.WriteToUDP([]byte{1, 2, 3}, dst); err != nil { // 太短
		t.Fatalf("发送失败：%v", err)
	}
	ike := uttFakeIKE(0x77)
	if _, err := peer.WriteToUDP(ike, dst); err != nil {
		t.Fatalf("发送失败：%v", err)
	}
	d := uttRecv(t, tr)
	if d.Kind != KindIKE || !bytes.Equal(d.Payload, ike) {
		t.Fatalf("500 上应原样收到裸 IKE 报文：kind=%d payload=% x", d.Kind, d.Payload)
	}
	if d.Local != tr.LocalIKE() {
		t.Errorf("Local 应当是实际收包的那个端口：期望 %s，实得 %s", tr.LocalIKE(), d.Local)
	}
}

// ESP / keepalive 只能从 4500 出去。裸 ESP（IP 协议号 50）本实现不支持，
// 若允许从 500 发 ESP，等于悄悄开了一条根本不存在的路径。
func TestUDPTransportRefusesESPOn500(t *testing.T) {
	tr := uttTransport(t)
	_, peerAddr := uttPeer(t)

	err := tr.Send(Datagram{Kind: KindESP, Local: tr.LocalIKE(), Remote: peerAddr, Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8}})
	if err == nil {
		t.Fatalf("从 500 发 ESP 应当被拒绝")
	}
	err = tr.Send(Datagram{Kind: KindKeepalive, Local: tr.LocalIKE(), Remote: peerAddr})
	if err == nil {
		t.Fatalf("从 500 发 keepalive 应当被拒绝")
	}
}

// keepalive 上线必须正好是一个字节 0xFF（RFC 3948 §4）。
// 多一个字节都会被对端当成畸形 ESP 或畸形 IKE 丢掉，而丢包是不报错的。
func TestUDPTransportKeepaliveIsSingleFF(t *testing.T) {
	tr := uttTransport(t)
	peer, peerAddr := uttPeer(t)

	if err := tr.Send(Datagram{Kind: KindKeepalive, Remote: peerAddr, Payload: []byte("这段内容应当被忽略")}); err != nil {
		t.Fatalf("发 keepalive 失败：%v", err)
	}
	buf := make([]byte, 64)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("收 keepalive 失败：%v", err)
	}
	if n != 1 || buf[0] != 0xFF {
		t.Errorf("keepalive 必须是单字节 0xFF，实得 % x", buf[:n])
	}
}

// Local 没填时按类型推断：ESP 走 4500；IKE 看对端端口。
func TestUDPTransportPicksSocketByKind(t *testing.T) {
	tr := uttTransport(t)
	peer, peerAddr := uttPeer(t)

	esp := []byte{0xAB, 0xCD, 0xEF, 0x01, 0, 0, 0, 3}
	if err := tr.Send(Datagram{Kind: KindESP, Remote: peerAddr, Payload: esp}); err != nil {
		t.Fatalf("发 ESP 失败：%v", err)
	}
	buf := make([]byte, 128)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("收包失败：%v", err)
	}
	if from.AddrPort().Port() != tr.LocalNAT().Port() {
		t.Errorf("ESP 必须从 4500 侧发出：期望源端口 %d，实得 %d", tr.LocalNAT().Port(), from.AddrPort().Port())
	}
	if !bytes.Equal(buf[:n], esp) {
		t.Errorf("ESP 不该被加 marker：期望 % x，实得 % x", esp, buf[:n])
	}
}

func TestUDPTransportCloseUnblocksRecv(t *testing.T) {
	tr, err := NewUDPTransport(netip.MustParseAddr("127.0.0.1"), 0, 0)
	if err != nil {
		t.Fatalf("绑定失败：%v", err)
	}
	done := make(chan error, 1)
	go func() { _, e := tr.Recv(); done <- e }()
	time.Sleep(20 * time.Millisecond)
	_ = tr.Close()
	select {
	case e := <-done:
		if e != ErrClosed {
			t.Errorf("Close 后 Recv 应返回 ErrClosed，实得 %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Close 没能唤醒阻塞中的 Recv")
	}
	// 可重复 Close。
	if err := tr.Close(); err != nil {
		t.Errorf("重复 Close 应当无害，实得 %v", err)
	}
	if err := tr.Send(Datagram{Kind: KindIKE, Remote: netip.MustParseAddrPort("127.0.0.1:1")}); err != ErrClosed {
		t.Errorf("Close 后 Send 应返回 ErrClosed，实得 %v", err)
	}
}
