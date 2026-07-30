package ike

import (
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// 认证闸：IKE_AUTH 之外的交换必须发生在认证之后。
//
// ★这道闸挡的不是"防御纵深不足"，而是 PSK 认证被整体绕过：SK_e/SK_a 只由 DH 共享
// 秘密 + Ni/Nr + SPI 派生，PSK 只进 AUTH 载荷。于是任何完成一次 IKE_SA_INIT 的
// 对端——完全不知道 PSK——都持有可用的 SK 密钥，能自行加解密 SK 载荷。它跳过
// IKE_AUTH 直发 CREATE_CHILD_SA，若无此闸就能让本端 installChild，拿到一条真能
// 收发业务流量的 ESP 隧道直通内网；而 States() 因 primary() 要求 SAEstablished
// 仍不显示 up——数据面已通、控制台无痕。

// agSendSK 用某条 SA 的**入向**密钥封一条请求送给它（模拟对端发来的报文）。
// 用入向密钥是因为对端的出向 == 本端的入向。
func agSendSK(t *testing.T, e *Engine, sa *IKESA, et ExchangeType, inner []Payload) {
	t.Helper()
	iv, err := sa.nextIV()
	if err != nil {
		t.Fatalf("取 IV 失败: %v", err)
	}
	// ★I 位必须与本端**相反**：本端是响应方时，对端发来的请求带 I 位。
	// 用 sa.header() 直接构造会打上本端的 I 位，报文按 localSPI 索引就落到另一半，
	// 引擎报「SPI 对不上任何 SA」而丢弃——测试会假通过（闸没验证也照样"没响应"）。
	hdr := Header{
		SPIi: sa.SPIi, SPIr: sa.SPIr, Version: Version,
		ExchangeType: et, MessageID: sa.expectRxMID,
	}
	if !sa.LocalIsInit {
		hdr.Flags |= FlagInitiator
	}
	raw, err := EncryptSK(hdr, sa.Suite, sa.EncKeyIn(), sa.IntegKeyIn(), iv, inner)
	if err != nil {
		t.Fatalf("封装请求失败: %v", err)
	}
	e.handle(ipsec.Datagram{Kind: ipsec.KindIKE, Local: sa.Local, Remote: sa.Peer, Payload: raw})
}

// agHalfOpenSA 取 B 侧那条已建立的 SA，并把它按住在"认证之前"的状态。
// 用一条真实协商出来的 SA 而非手搓：密钥、SPI、MID 全都是真的，
// 这样测试与生产走的是同一条解密路径，闸失效时确实会被处理。
func agHalfOpenSA(t *testing.T, e *Engine) *IKESA {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sites["site-1"]
	if s == nil || len(s.sas) == 0 {
		t.Fatal("B 侧没有 SA")
	}
	return s.sas[0]
}

func TestUnauthenticatedPeerCannotCreateChildSA(t *testing.T) {
	f, _ := rkSetup(t, nil)
	sa := agHalfOpenSA(t, f.b)

	before := f.pb.count()
	if before == 0 {
		t.Fatal("前置条件不成立：握手后 B 侧应已装载 Child SA")
	}
	pktsBefore := len(f.cap.snapshot())

	// 把 SA 按回"已回 IKE_SA_INIT、等 IKE_AUTH"——密钥就绪但身份未验。
	f.b.mu.Lock()
	sa.State = SAHalfOpen
	f.b.mu.Unlock()

	// 未认证对端发 CREATE_CHILD_SA。载荷不必合法：闸在解密之前，
	// 闸生效时 B 连解都不该解，更不该回任何响应。
	agSendSK(t, f.b, sa, ExchangeCreateChildSA, []Payload{&NoncePayload{Nonce: []byte("0123456789abcdef")}})

	hsWait(t, "B 处理完毕", func() bool { return true })
	time.Sleep(50 * time.Millisecond) // 给事件循环一个真实的处理窗口

	if got := f.pb.count(); got != before {
		t.Fatalf("未认证对端不得改动数据面：Child SA 数 %d → %d", before, got)
	}
	if got := len(f.cap.snapshot()); got != pktsBefore {
		t.Fatalf("未认证对端不该收到任何响应（收到 %d 条新报文）", got-pktsBefore)
	}
}

func TestUnauthenticatedPeerCannotSendInformational(t *testing.T) {
	f, _ := rkSetup(t, nil)
	sa := agHalfOpenSA(t, f.b)

	before := f.pb.count()
	f.b.mu.Lock()
	sa.State = SAHalfOpen
	f.b.mu.Unlock()

	// 未认证对端发 D(ESP)：若无闸，它能拆掉一条正在承载业务的隧道（DoS）。
	agSendSK(t, f.b, sa, ExchangeInformational, []Payload{&DeletePayload{Protocol: ProtocolIKE}})

	time.Sleep(50 * time.Millisecond)
	if got := f.pb.count(); got != before {
		t.Fatalf("未认证对端不得拆除已装载的 Child SA：%d → %d", before, got)
	}
	f.b.mu.Lock()
	st := sa.State
	f.b.mu.Unlock()
	if st == SADead {
		t.Fatal("未认证对端不得拆掉 IKE SA")
	}
}

// 已认证的对端走同一条路径必须**能**被处理——否则上面两个用例可能只是
// 因为报文本身无效而通过，闸有没有生效根本没被验证。
func TestAuthenticatedPeerStillServed(t *testing.T) {
	f, _ := rkSetup(t, nil)
	sa := agHalfOpenSA(t, f.b)
	pktsBefore := len(f.cap.snapshot())

	// State 保持 Established（rkSetup 已完成握手），同样的畸形 CREATE_CHILD_SA：
	// 闸放行 → 解密成功 → 载荷不合法 → 回 INVALID_SYNTAX。有响应即证明闸没误伤。
	agSendSK(t, f.b, sa, ExchangeCreateChildSA, []Payload{&NoncePayload{Nonce: []byte("0123456789abcdef")}})

	hsWait(t, "B 回了错误响应", func() bool { return len(f.cap.snapshot()) > pktsBefore })
}
