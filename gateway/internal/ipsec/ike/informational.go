package ike

import (
	"encoding/binary"
	"fmt"

	"baidi.dev/gateway/internal/ipsec"
)

// INFORMATIONAL 交换（Exchange 37）：DPD 探活、优雅删除、错误通知。
//
// 三条不变量：
//  1. **任何 INFORMATIONAL 请求都必须回响应**，哪怕是空的 SK{}（Next Payload=0）。
//     不回的后果是对端把我们当死了——而我们其实活得好好的，只是"不认识"它发的通知。
//  2. **DPD 就是空请求 SK{}**，没有专用载荷。对端回一个空响应即证明它还在，
//     且证明的是"它持有正确的密钥"（响应是加密并完整性保护的），比 ICMP 强得多。
//  3. **建立之前不存在 INFORMATIONAL**：它永远加密。所以本文件里没有任何明文路径。

// sendDPD 发一条空的 INFORMATIONAL 请求探活。
func (e *Engine) sendDPD(sa *IKESA) error {
	iv, err := sa.nextIV()
	if err != nil {
		return err
	}
	raw, err := EncryptSK(sa.header(ExchangeInformational, sa.nextTxMID, false),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv, nil)
	if err != nil {
		return fmt.Errorf("ike: 封装 DPD 请求失败: %w", err)
	}
	return e.startExchange(sa, &exchange{
		kind: exDPD, et: ExchangeInformational, mid: sa.nextTxMID, raw: raw,
	})
}

// sendDeleteIKE 向对端发 D(IKE)。
//
// ★**单发不重传**，这是有意的取舍：本端无论如何都要把这条 SA 拆掉，
// 重传只会让一个正在退出的进程多活几分钟。丢了也不至于出错——对端的 DPD
// 会在 30 秒内发现并清理。真正不能省的是"至少发一次"：完全不发的话，
// 对端会在整个 DPD 周期内继续往一条没人接收的隧道里灌业务流量。
//
// 删 IKE SA 的 D 载荷形态是固定的：Protocol=IKE、SPI Size=0、Num SPIs=0
// （SPI 就在报文头里，再写一遍是冗余）。带上 SPI 会被严格的实现判成 INVALID_SYNTAX。
func (e *Engine) sendDeleteIKE(sa *IKESA) error {
	iv, err := sa.nextIV()
	if err != nil {
		return err
	}
	mid := sa.allocTxMID()
	raw, err := EncryptSK(sa.header(ExchangeInformational, mid, false),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv,
		[]Payload{&DeletePayload{Protocol: ProtocolIKE}})
	if err != nil {
		return fmt.Errorf("ike: 封装 D(IKE) 失败: %w", err)
	}
	e.send(sa.Local, sa.Peer, raw)
	return nil
}

// sendDeleteChild 向对端发 D(ESP)，SPI 列表放的是**本端入向**的 SPI。
//
// ★放本端入向而不是出向：D 的语义是"我不再用这些 SPI 收包了"。
// 放成出向 SPI 的话，对端会去删它自己的入向 SA——那条恰好是**另一个方向**的，
// 结果是删错了一半，隧道变成单向通。
func (e *Engine) sendDeleteChild(sa *IKESA, inSPIs []uint32) error {
	if len(inSPIs) == 0 {
		return nil
	}
	spis := make([][]byte, 0, len(inSPIs))
	for _, v := range inSPIs {
		spis = append(spis, binary.BigEndian.AppendUint32(nil, v))
	}
	iv, err := sa.nextIV()
	if err != nil {
		return err
	}
	mid := sa.allocTxMID()
	raw, err := EncryptSK(sa.header(ExchangeInformational, mid, false),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv,
		[]Payload{&DeletePayload{Protocol: ProtocolESP, SPIs: spis}})
	if err != nil {
		return fmt.Errorf("ike: 封装 D(ESP) 失败: %w", err)
	}
	e.send(sa.Local, sa.Peer, raw)
	return nil
}

// onInformationalRequest 处理对端的 INFORMATIONAL 请求。
func (e *Engine) onInformationalRequest(sa *IKESA, m *Message, d ipsec.Datagram) {
	if sa.Keys == nil {
		return // 密钥未就绪时不存在 INFORMATIONAL
	}
	if err := DecryptSK(m, sa.Suite, sa.EncKeyIn(), sa.IntegKeyIn()); err != nil {
		e.opt.Log.Debug("ike: 无法解开 INFORMATIONAL 请求，丢弃", "site", sa.SiteID, "err", err)
		return
	}
	mid := m.Hdr.MessageID
	sa.expectRxMID = mid + 1
	sa.lastSeen = e.now()
	sa.Peer = d.Remote // NAT 后地址可能变，以最后一次通过完整性校验的报文为准

	var (
		resp     []Payload
		killIKE  bool
		echoSPIs []uint32
	)

	for _, p := range m.Payloads {
		switch pl := p.(type) {
		case *DeletePayload:
			switch pl.Protocol {
			case ProtocolIKE:
				killIKE = true
			case ProtocolESP:
				for _, raw := range pl.SPIs {
					if len(raw) != 4 {
						continue
					}
					// 对端发来的是**它的入向** SPI = 本端的出向 SPI。
					peerIn := binary.BigEndian.Uint32(raw)
					c := sa.childByOut(peerIn)
					if c == nil {
						continue
					}
					echoSPIs = append(echoSPIs, c.InSPI)
					e.removeChild(sa, c, false, "对端发来 D(ESP)")
				}
			}
		case *NotifyPayload:
			e.onPeerNotify(sa, pl)
		}
	}

	if len(echoSPIs) > 0 {
		spis := make([][]byte, 0, len(echoSPIs))
		for _, v := range echoSPIs {
			spis = append(spis, binary.BigEndian.AppendUint32(nil, v))
		}
		resp = append(resp, &DeletePayload{Protocol: ProtocolESP, SPIs: spis})
	}
	// ★删 IKE SA 的响应是**空 SK{}**，不回 D。回一个 D 会被对端当成"你也要删我"，
	// 于是它再回一条……在实现不够严谨的对端上能刷成删除风暴。
	if killIKE {
		resp = nil
	}

	iv, err := sa.nextIV()
	if err != nil {
		e.opt.Log.Warn("ike: 取出向 IV 失败", "site", sa.SiteID, "err", err)
		return
	}
	raw, err := EncryptSK(sa.header(ExchangeInformational, mid, true),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv, resp)
	if err != nil {
		e.opt.Log.Warn("ike: 封装 INFORMATIONAL 响应失败", "site", sa.SiteID, "err", err)
		return
	}
	e.respond(sa, mid, d.Remote, raw)

	if killIKE {
		// ★先回响应再拆：拆完密钥就没了，那条空响应也就发不出去，
		// 对端只能靠重传超时收敛——它会在 3 分钟里以为隧道还在。
		e.destroySA(sa, false, "对端发来 D(IKE)")
	}
}

// onInformationalResponse 处理本端 INFORMATIONAL 请求的响应（DPD 回包 / 删除确认）。
func (e *Engine) onInformationalResponse(sa *IKESA, ex *exchange, m *Message) {
	if err := DecryptSK(m, sa.Suite, sa.EncKeyIn(), sa.IntegKeyIn()); err != nil {
		e.opt.Log.Debug("ike: 无法解开 INFORMATIONAL 响应", "site", sa.SiteID, "err", err)
		return
	}
	sa.lastSeen = e.now()
	for _, p := range m.Payloads {
		if n, ok := p.(*NotifyPayload); ok {
			e.onPeerNotify(sa, n)
		}
	}
	if ex.kind == exDPD {
		e.opt.Log.Debug("ike: DPD 探活成功", "site", sa.SiteID, "peer", sa.Peer)
	}
}

// onPeerNotify 处理对端在 INFORMATIONAL 里捎带的通知。
//
// ★分界线在 16384：小于它是错误，大于等于它是状态，**不认识的状态类一律静默忽略**。
// 这条是互通生命线——strongSwan 默认会发 IKE_FRAGMENTATION_SUPPORTED /
// SIGNATURE_HASH_ALGORITHMS / MOBIKE_SUPPORTED / REDIRECT_SUPPORTED 等一串，
// 把它们当错误处理会导致完全无法建连，而日志里只有一句"对端报错"。
func (e *Engine) onPeerNotify(sa *IKESA, n *NotifyPayload) {
	if !n.NotifyType.IsError() {
		e.opt.Log.Debug("ike: 忽略状态类通知", "site", sa.SiteID, "notify", n.NotifyType)
		return
	}
	s := e.sites[sa.SiteID]
	switch n.NotifyType {
	case NotifyAuthenticationFailed:
		if s != nil {
			e.failSite(s, fmt.Sprintf("对端 %s 在 INFORMATIONAL 里回了 AUTHENTICATION_FAILED（两端 PSK 不一致，或对端刚换过 PSK）", sa.Peer))
		}
		e.destroySA(sa, false, "对端报 AUTHENTICATION_FAILED")
	case NotifyTemporaryFailure:
		// rekey 冲突。退避后重试，见 rekey.go 的 onRekeyChildResponse。
		e.opt.Log.Info("ike: 对端回 TEMPORARY_FAILURE（重协商撞车），稍后重试", "site", sa.SiteID)
	case NotifyChildSANotFound:
		e.opt.Log.Warn("ike: 对端找不到要重协商的 Child SA（两端 SA 表已不一致，将由生存期收敛）", "site", sa.SiteID)
	default:
		if s != nil {
			s.lastError = fmt.Sprintf("对端 %s 通知：%s", sa.Peer, n.NotifyType)
			s.lastErrorAt = e.now()
		}
		e.opt.Log.Warn("ike: 对端通知了一个错误码点", "site", sa.SiteID, "notify", n.NotifyType)
	}
}
