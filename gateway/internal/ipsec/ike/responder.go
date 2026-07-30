package ike

import (
	"encoding/binary"
	"fmt"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// 响应方的两轮：处理 IKE_SA_INIT 请求（建 half-open）→ 处理 IKE_AUTH 请求（转 Established）。
//
// ★这里的每一条拒绝路径都必须想清楚"回什么"：
//   - **未认证阶段**（IKE_SA_INIT）的拒绝是明文的，任何回包都可能被用作反射放大器。
//     所以只在"报文本身结构合法、且确实指向一条已配置的站点"时才回，
//     其余一律**静默丢包**（解析失败、找不到站点、限速命中、cookie 不匹配）。
//   - **已认证阶段**（IKE_AUTH）的拒绝走加密通道，不构成放大器，此时应当把原因
//     明确告诉对端——否则对端只会看到"重传超时"，把管理员的注意力引到网络上。

// onSAInitRequest 处理一条 IKE_SA_INIT 请求。
func (e *Engine) onSAInitRequest(m *Message, d ipsec.Datagram) {
	peerIP := d.Remote.Addr().Unmap()

	// ① 每源 IP 限速。命中即静默丢包。
	if !e.limiter.allow(peerIP) {
		e.opt.Log.Debug("ike: IKE_SA_INIT 限速丢弃", "from", d.Remote)
		return
	}

	// ② 必须能对应到一条**已启用**的站点配置。
	// ★这一步同时是最有效的一道过滤：网关上 UDP 500 是唯一不受 SPA 保护的端口，
	// 扫描流量会持续打上来，而它们的源地址不在任何站点配置里，到此为止。
	s := e.findSiteByPeer(d.Remote)
	if s == nil {
		e.opt.Log.Debug("ike: 收到来自未配置对端的 IKE_SA_INIT，丢弃", "from", d.Remote)
		return
	}

	// ③ 重传检测：同一个 SPIi 已经建过 half-open → 原样回放缓存的响应。
	// ★不做这一步会为同一个对端建出一串 half-open SA，把配额吃光；
	// 更糟的是对端会收到多个不同 SPIr 的响应，它只认第一个，剩下的都是垃圾。
	if old := s.halfOpenBySPIi(m.Hdr.SPIi); old != nil {
		if raw, ok := old.replayResponse(0); ok {
			e.send(old.Local, d.Remote, raw)
			e.opt.Log.Debug("ike: 回放 IKE_SA_INIT 响应（对端重传）", "site", s.cfg.ID, "spiI", spiHex(m.Hdr.SPIi))
		}
		return
	}

	saPl := findSAPayload(m)
	ke := findKE(m)
	ni := findNonce(m)
	if saPl == nil || ke == nil || len(ni) == 0 {
		e.opt.Log.Debug("ike: IKE_SA_INIT 请求缺少必需载荷，丢弃", "site", s.cfg.ID, "from", d.Remote)
		return
	}

	// ④ half-open 配额与 COOKIE。
	if e.halfOpen.overLimit(peerIP) {
		ck := m.FindNotify(NotifyCookie)
		if ck == nil || !e.cookies.verify(ck.Data, ni, peerIP, m.Hdr.SPIi) {
			// 只有"报文结构完全合法 + 指向已配置站点"才走到这里，所以回一个
			// COOKIE 不构成通用放大器（攻击者必须先猜中站点配置里的对端 IP）。
			e.sendStateless(d, m.Hdr.SPIi, &NotifyPayload{
				Protocol:   ProtocolNone,
				NotifyType: NotifyCookie,
				Data:       e.cookies.issue(ni, peerIP, m.Hdr.SPIi),
			})
			e.opt.Log.Info("ike: half-open 配额已满，要求对端带 COOKIE 重来",
				"site", s.cfg.ID, "from", d.Remote, "全局半开", e.halfOpen.total)
			return
		}
	}

	// ⑤ 提案协商。
	sel, spec, err := SelectProposal(saPl.Proposals, s.spec1, ProtocolIKE)
	if err != nil {
		e.opt.Log.Warn("ike: 拒绝对端 IKE 提案", "site", s.cfg.ID, "from", d.Remote, "err", err)
		e.sendStateless(d, m.Hdr.SPIi, &NotifyPayload{
			Protocol: ProtocolNone, NotifyType: NotifyNoProposalChosen,
		})
		e.failSite(s, fmt.Sprintf("对端 %s 的 IKE 提案不可接受：%v", d.Remote, err))
		return
	}

	// ⑥ KE 群必须与选中的 D-H 变换一致。
	if ke.Group != spec.DHID {
		var data [2]byte
		binary.BigEndian.PutUint16(data[:], spec.DHID)
		e.sendStateless(d, m.Hdr.SPIi, &NotifyPayload{
			Protocol: ProtocolNone, NotifyType: NotifyInvalidKEPayload, Data: data[:],
		})
		e.opt.Log.Info("ike: 对端 KE 群与协商结果不符，回 INVALID_KE_PAYLOAD",
			"site", s.cfg.ID, "对端KE群", ke.Group, "本端要求", spec.DHID)
		return
	}

	suite, err := spec.Build()
	if err != nil {
		e.opt.Log.Warn("ike: 协商出的套件无法构造（不应发生）", "site", s.cfg.ID, "err", err)
		return
	}
	dh, err := suite.DH.Generate(e.opt.Rand)
	if err != nil {
		e.opt.Log.Warn("ike: 生成 DH 私钥失败", "site", s.cfg.ID, "err", err)
		return
	}
	shared, err := dh.Shared(ke.Data)
	if err != nil {
		// 对端公钥非法（小子群 / 不在曲线上）。静默丢弃：这已经是攻击行为，
		// 回任何东西都只是告诉对方"你猜对了报文格式"。
		e.opt.Log.Warn("ike: 对端 KE 公钥非法，丢弃", "site", s.cfg.ID, "from", d.Remote, "err", err)
		return
	}
	spir, err := randIKESPI(e.opt.Rand)
	if err != nil {
		return
	}

	now := e.now()
	sa := newIKESA(s.cfg.ID, false, now)
	sa.SPIi = m.Hdr.SPIi
	sa.SPIr = spir
	sa.Spec = spec
	sa.Suite = suite
	sa.ni = ni
	sa.nr = readRand(e.opt.Rand, defaultNonceLen)
	sa.Local = d.Local
	sa.Peer = d.Remote
	sa.State = SAHalfOpen
	sa.halfOpenUntil = now.Add(halfOpenTTL)
	sa.halfOpenIP = peerIP
	// ★RealMessage1 是对端**实际发来的**这条报文的原始字节。
	// 它可能是带 COOKIE 的重发版本——正因为如此，这里只能取 m.Raw，
	// 绝不能"按载荷重新拼一条出来"。
	sa.initMsgRaw = m.Raw

	// NAT 检测用**收包时的实际地址**，且必须在切端口之前做。
	peerNATed, localNATed, present := detectNAT(m, d.Remote, d.Local)

	// 响应报文：SA(选中的那条提案，SPI 留空——IKE 提案的 SPI 在报文头里) → KE → Nr → NAT 通知。
	resp := []Payload{
		&SAPayload{Proposals: []Proposal{spec.IKEProposal(sel.Num)}},
		&KEPayload{Group: spec.DHID, Data: dh.Public()},
		&NoncePayload{Nonce: sa.nr},
	}
	resp = append(resp, natNotifies(sa.SPIi, sa.SPIr, d.Local, d.Remote)...)

	raw, err := Encode(sa.header(ExchangeIKESAInit, 0, true), resp)
	if err != nil {
		e.opt.Log.Warn("ike: 编码 IKE_SA_INIT 响应失败", "site", s.cfg.ID, "err", err)
		return
	}
	sa.respMsgRaw = raw // RealMessage2

	keys, err := DeriveIKEKeys(suite, shared, sa.ni, sa.nr, sa.SPIi, sa.SPIr)
	if err != nil {
		e.opt.Log.Warn("ike: 派生 IKE 密钥失败", "site", s.cfg.ID, "err", err)
		return
	}
	sa.Keys = keys
	sa.expectRxMID = 1 // 下一条该是 MID=1 的 IKE_AUTH

	e.halfOpen.add(peerIP)
	sa.countedHalfOpen = true
	e.registerSA(s, sa)
	if s.state != ipsec.StateUp {
		s.state = ipsec.StateConnecting
	}

	// ★响应发出之后再缓存是不行的——必须先缓存：对端的重传可能在我们
	// 处理完之前就已经到了（同一进程内的 MemNet 上尤其容易）。
	e.respond(sa, 0, d.Remote, raw)

	// ★NAT 端口切换必须在响应**发出之后**才生效：IKE_SA_INIT 这一轮双方都在
	// 500 上收发，从 IKE_AUTH 起才切 4500（RFC 3947）。提前切的后果是这条响应
	// 从 4500 发出、并被 Transport 加上 4 字节 non-ESP marker，而对端还在 500 上
	// 按裸 IKE 报文解析——收到的第一个字节就是 0，解析直接失败，且**静默丢包**。
	if present {
		sa.applyNAT(peerNATed, localNATed, e.opt.LocalNAT, s.cfg.PeerNATPort)
	}
	e.opt.Log.Info("ike: 已响应 IKE_SA_INIT（half-open）",
		"site", s.cfg.ID, "from", d.Remote, "spiI", spiHex(sa.SPIi), "spiR", spiHex(sa.SPIr),
		"套件", spec, "对端在NAT后", sa.PeerNATed, "本端在NAT后", sa.LocalNATed)
}

// halfOpenBySPIi 找该站点下 SPIi 匹配的 half-open SA（IKE_SA_INIT 重传判定）。
func (s *site) halfOpenBySPIi(spii [8]byte) *IKESA {
	for _, sa := range s.sas {
		if sa.State == SAHalfOpen && sa.SPIi == spii {
			return sa
		}
	}
	return nil
}

// sendStateless 发一条**不建立任何状态**的明文响应（COOKIE / NO_PROPOSAL_CHOSEN /
// INVALID_KE_PAYLOAD）。
//
// SPIr 填零：我们没有为这次请求生成过 SPI，填一个随机值会让对端误以为
// SA 已经建立，之后它发来的 IKE_AUTH 会因为找不到 SA 被丢弃，症状是
// 「协商卡在第二步，两端都不报错」。
func (e *Engine) sendStateless(d ipsec.Datagram, spii [8]byte, ps ...Payload) {
	hdr := Header{
		SPIi:         spii,
		Version:      Version,
		ExchangeType: ExchangeIKESAInit,
		Flags:        FlagResponse, // 响应方发的响应：I=0，R=1
		MessageID:    0,
	}
	raw, err := Encode(hdr, ps)
	if err != nil {
		e.opt.Log.Warn("ike: 编码无状态响应失败", "err", err)
		return
	}
	e.send(d.Local, d.Remote, raw)
}

// onAuthRequest 处理 IKE_AUTH 请求：校验对端身份、协商第一个 Child SA、回响应。
func (e *Engine) onAuthRequest(sa *IKESA, m *Message, d ipsec.Datagram) {
	s := e.sites[sa.SiteID]
	if s == nil {
		return
	}
	if sa.State != SAHalfOpen {
		e.opt.Log.Debug("ike: 在非 half-open 状态收到 IKE_AUTH，丢弃", "site", s.cfg.ID, "state", sa.State)
		return
	}

	if err := DecryptSK(m, sa.Suite, sa.EncKeyIn(), sa.IntegKeyIn()); err != nil {
		// 解不开说明 IKE 密钥不一致（DH/nonce/SPI 任一环节两端不同），
		// 与 PSK 无关。★这条错误信息必须点明这一点，否则所有人第一反应都是去改 PSK。
		e.opt.Log.Warn("ike: 无法解开 IKE_AUTH 请求（IKE 密钥不一致，与 PSK 无关）",
			"site", s.cfg.ID, "from", d.Remote, "err", err)
		return
	}
	mid := m.Hdr.MessageID
	sa.expectRxMID = mid + 1

	idi := findID(m, PayloadIDi)
	authPl := findAuth(m)
	if idi == nil || authPl == nil {
		e.replyAuthFailed(sa, mid, d, "IKE_AUTH 请求缺少 IDi 或 AUTH 载荷")
		return
	}
	if authPl.Method != AuthSharedKeyMIC {
		e.replyAuthFailed(sa, mid, d, fmt.Sprintf("对端用了认证方法 %d，本实现只支持 PSK（方法 2）", authPl.Method))
		return
	}
	if !sameID(idi, s.cfg.RemoteID) {
		e.replyAuthFailed(sa, mid, d,
			fmt.Sprintf("对端身份不符：期望 FQDN %q，实际收到 %s", s.cfg.RemoteID, idi))
		return
	}
	// 对端若指明了想连谁（IDr），必须是我们。不校验的话，一个配错 remoteId 的
	// 对端会连上来并建立隧道，而两端的意图其实不同。
	if idr := findID(m, PayloadIDr); idr != nil && !sameID(idr, s.cfg.LocalID) {
		e.replyAuthFailed(sa, mid, d,
			fmt.Sprintf("对端想连的身份是 %s，本端身份是 %q", idr, s.cfg.LocalID))
		return
	}

	// InitiatorSignedOctets = RealMessage1 ‖ **Nr**（本端的 nonce）‖ MACedIDForI
	macedI := MACedID(sa.Suite.PRF, sa.Keys.SKpi, idi)
	signed := InitiatorSignedOctets(sa.initMsgRaw, sa.nr, macedI)
	if !VerifyPSKAuth(sa.Suite.PRF, s.cfg.PSK, signed, authPl.Data) {
		e.opt.Log.Warn("ike: 对端 AUTH 校验失败，本端算出的待签串摘要如下（与对端日志逐段对比即可定位）",
			"site", s.cfg.ID, "摘要", SignedOctetsDigest(sa.initMsgRaw, sa.nr, macedI))
		e.replyAuthFailed(sa, mid, d,
			fmt.Sprintf("对端 %s 的 AUTH 校验失败（两端 PSK 不一致；PSK 口径是**原文字节**，控制面若存的是 hex/base64 必须先解码）", d.Remote))
		return
	}

	// 认证通过。从这里往下，**IKE SA 必须存活**，无论 Child SA 谈成谈不成。
	idr := idPayload(PayloadIDr, s.cfg.LocalID)
	macedR := MACedID(sa.Suite.PRF, sa.Keys.SKpr, idr)
	respAuth := &AuthPayload{
		Method: AuthSharedKeyMIC,
		Data:   PSKAuth(sa.Suite.PRF, s.cfg.PSK, ResponderSignedOctets(sa.respMsgRaw, sa.ni, macedR)),
	}

	if sa.countedHalfOpen {
		e.halfOpen.remove(sa.halfOpenIP)
		sa.countedHalfOpen = false
	}
	sa.halfOpenUntil = time.Time{}
	sa.Peer = d.Remote // 以实测地址为准（NAT 后必须如此）
	e.armLifetimes(s, sa)

	child, childErr := e.acceptChildFromAuth(s, sa, m)
	inner := []Payload{idr, respAuth}
	if childErr != nil {
		// ★这个分支必须实现：认证成功但 Child SA 谈不拢时，响应里仍要带 IDr+AUTH，
		// 只是把 SA/TS 换成一个错误通知。少了 IDr+AUTH，对端会认为**认证**失败并
		// 拆掉整条 IKE SA，接着重连——两端就此进入"建了拆、拆了建"的循环，
		// 而真正的根因（TS 或算法不匹配）一次都不会被人看到。
		inner = append(inner, &NotifyPayload{Protocol: ProtocolESP, NotifyType: childErr.notify})
		sa.State = SAEstablished
		e.failSite(s, childErr.reason)
	} else {
		inner = append(inner,
			&SAPayload{Proposals: []Proposal{child.spec.ESPProposal(child.num, child.sa.InSPI, false)}},
			child.tsi, child.tsr,
		)
	}

	iv, err := sa.nextIV()
	if err != nil {
		e.opt.Log.Warn("ike: 取出向 IV 失败", "site", s.cfg.ID, "err", err)
		return
	}
	raw, err := EncryptSK(sa.header(ExchangeIKEAuth, mid, true),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv, inner)
	if err != nil {
		e.opt.Log.Warn("ike: 封装 IKE_AUTH 响应失败", "site", s.cfg.ID, "err", err)
		return
	}
	e.respond(sa, mid, d.Remote, raw)

	if childErr != nil {
		return
	}
	// ★装载放在响应**之后**：万一装载失败，对端至少已经收到一条语义完整的响应，
	// 后续由 DPD/删除流程收敛；反过来（先装载后发响应）则会出现
	// "本端数据面已就绪、对端一无所知"的半边隧道。
	if err := e.installChild(s, sa, child.sa, child.keys); err != nil {
		e.failSite(s, err.Error())
		sa.State = SAEstablished
		return
	}
	e.markEstablished(s, sa, sa.Spec, child.sa.Spec)
	e.opt.Log.Info("ike: 隧道已建立（响应方）", "site", s.cfg.ID,
		"spiI", spiHex(sa.SPIi), "spiR", spiHex(sa.SPIr),
		"childIn", fmt.Sprintf("%08x", child.sa.InSPI),
		"childOut", fmt.Sprintf("%08x", child.sa.OutSPI),
		"协商结果", s.negotiated)
}

// acceptedChild 响应方接受一条 Child SA 后需要回传给调用处的全部材料。
type acceptedChild struct {
	sa   *ChildSA
	spec SuiteSpec
	num  uint8
	keys ChildKeys
	tsi  *TSPayload
	tsr  *TSPayload
}

// childReject 一次 Child SA 协商失败：既要回给对端的码点，也要给管理员看的中文。
type childReject struct {
	notify NotifyType
	reason string
}

func (c *childReject) Error() string { return c.reason }

// acceptChildFromAuth 处理 IKE_AUTH 里的 Child SA 协商（响应方视角）。
func (e *Engine) acceptChildFromAuth(s *site, sa *IKESA, m *Message) (*acceptedChild, *childReject) {
	saPl := findSAPayload(m)
	tsi := findTS(m, PayloadTSi)
	tsr := findTS(m, PayloadTSr)
	if saPl == nil || tsi == nil || tsr == nil {
		return nil, &childReject{NotifyTSUnacceptable,
			fmt.Sprintf("对端 %s 的 IKE_AUTH 缺少 Child SA 协商载荷（SA=%v TSi=%v TSr=%v）", sa.Peer, saPl != nil, tsi != nil, tsr != nil)}
	}

	// ★TS 是**发起方视角**：TSi 是对端的本地网段（= 本端配置里的 RemoteSubnet），
	// TSr 是对端的远端网段（= 本端配置里的 LocalSubnet）。这个交叉是必错点之一，
	// 写反的表现是一条两端配置都正确的站点永远回 TS_UNACCEPTABLE。
	if !samePrefixTS(tsi, s.cfg.RemoteSubnet, PayloadTSi) || !samePrefixTS(tsr, s.cfg.LocalSubnet, PayloadTSr) {
		return nil, &childReject{NotifyTSUnacceptable, fmt.Sprintf(
			"对端 %s 提的流量选择器与本端配置不一致：对端 TSi=%v TSr=%v，本端期望 TSi=%s（本端配置的 remoteSubnet）TSr=%s（本端配置的 localSubnet）；本实现不做 narrowing",
			sa.Peer, tsi.Selectors, tsr.Selectors, s.cfg.RemoteSubnet, s.cfg.LocalSubnet)}
	}

	want := s.spec2.ForPFS(false) // IKE_AUTH 的第一个 Child SA 不带 KE，故无 D-H
	sel, spec, err := SelectProposal(saPl.Proposals, want, ProtocolESP)
	if err != nil {
		return nil, &childReject{NotifyNoProposalChosen,
			fmt.Sprintf("对端 %s 的 ESP 提案不可接受：%v", sa.Peer, err)}
	}
	outSPI, err := sel.ESPSPI()
	if err != nil {
		return nil, &childReject{NotifyNoProposalChosen, fmt.Sprintf("读取对端 ESP SPI 失败：%v", err)}
	}
	inSPI, err := allocChildSPI(e.opt.Rand)
	if err != nil {
		return nil, &childReject{NotifyNoProposalChosen, err.Error()}
	}

	ck, err := DeriveChildKeys(sa.Suite.PRF, sa.Keys.SKd, nil, sa.ni, sa.nr, s.espEncrLen, s.espIntegLen)
	if err != nil {
		return nil, &childReject{NotifyNoProposalChosen, fmt.Sprintf("派生 Child SA 密钥失败：%v", err)}
	}

	now := e.now()
	c := &ChildSA{SiteID: s.cfg.ID, InSPI: inSPI, OutSPI: outSPI, Spec: spec, CreatedAt: now}
	c.SoftExpire, c.HardExpire = e.childLifetimes(s, sa, now)
	return &acceptedChild{sa: c, spec: spec, num: sel.Num, keys: ck, tsi: tsi, tsr: tsr}, nil
}

// replyAuthFailed 回一条加密的 AUTHENTICATION_FAILED 并拆掉这条 SA。
func (e *Engine) replyAuthFailed(sa *IKESA, mid uint32, d ipsec.Datagram, reason string) {
	s := e.sites[sa.SiteID]
	if s != nil {
		e.failSite(s, reason)
	}
	iv, err := sa.nextIV()
	if err == nil {
		raw, err := EncryptSK(sa.header(ExchangeIKEAuth, mid, true),
			sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv,
			[]Payload{&NotifyPayload{Protocol: ProtocolNone, NotifyType: NotifyAuthenticationFailed}})
		if err == nil {
			e.respond(sa, mid, d.Remote, raw)
		}
	}
	// ★响应发出去之后才拆：先拆的话密钥就没了，连这条"告诉你为什么失败"的
	// 加密通知都发不出去，对端只能靠重传超时判死。
	e.destroySA(sa, false, "对端认证失败")
}
