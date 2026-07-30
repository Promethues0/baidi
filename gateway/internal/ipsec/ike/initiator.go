package ike

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// 发起方的三轮：IKE_SA_INIT 请求 → 处理响应并派生密钥 → IKE_AUTH 请求 → 处理响应并装载 Child SA。
//
// ★贯穿全文的一条纪律：**RealMessage1 是"响应方实际响应了的那一条"**。
// COOKIE 或 INVALID_KE_PAYLOAD 重试之后，它是重发的那条而不是第一条。
// 用错的症状仍然只有一句「认证失败」，而且只在被要求 COOKIE 的高负载场景下才出现——
// 平时测不出来，上线被打的时候才炸。所以本文件里只有 resendSAInit 一处会写 initMsgRaw。

// defaultNonceLen 本实现固定发 32 字节 nonce。
//
// RFC 要求 16..256 且 ≥ PRF 密钥长度的一半（HMAC-SHA256 → 16）。取 32 而不是最小值：
// nonce 同时参与 SKEYSEED 与 AUTH，多一倍熵的成本是 16 个字节。
const defaultNonceLen = 32

// defaultIKELifetime / defaultESPLifetime / defaultDPDDelay 配置缺省值。
const (
	defaultIKELifetime = 4 * time.Hour
	defaultESPLifetime = time.Hour
	defaultDPDDelay    = 30 * time.Second
)

// maxSAInitRetries COOKIE / INVALID_KE_PAYLOAD 各自允许的重发次数。
//
// ★必须有上限：对端若无条件地一直回 COOKIE（实现有 bug，或就是想耗我们），
// 无上限的重发会变成自己打自己。2 次足够覆盖"一次轮换 + 一次真实拒绝"。
const maxSAInitRetries = 2

// initiate 发起一条站点的 IKE_SA_INIT。
func (e *Engine) initiate(s *site) error {
	now := e.now()

	suite, err := s.spec1.Build()
	if err != nil {
		return &ipsec.ConfigError{SiteID: s.cfg.ID, Field: "phase1", Reason: err.Error()}
	}
	if suite.DH == nil {
		return &ipsec.ConfigError{SiteID: s.cfg.ID, Field: "phase1.dh", Reason: "IKE SA 必须协商 D-H 群，配置里没有"}
	}
	dh, err := suite.DH.Generate(e.opt.Rand)
	if err != nil {
		return fmt.Errorf("ike: 生成 DH 私钥失败: %w", err)
	}
	spii, err := randIKESPI(e.opt.Rand)
	if err != nil {
		return err
	}

	sa := newIKESA(s.cfg.ID, true, now)
	sa.SPIi = spii
	sa.Spec = s.spec1
	sa.Suite = suite
	sa.dh = dh
	sa.ni = readRand(e.opt.Rand, defaultNonceLen)
	sa.Local = e.localIKEAddr()
	sa.Peer = peerIKEAddr(s.cfg.Peer)
	sa.State = SASAInitSent

	raw, err := e.buildSAInitRequest(s, sa, nil)
	if err != nil {
		return err
	}
	sa.initMsgRaw = raw

	e.registerSA(s, sa)
	if err := e.startExchange(sa, &exchange{
		kind: exSAInit, et: ExchangeIKESAInit, mid: 0, raw: raw,
	}); err != nil {
		e.destroySA(sa, false, "")
		return err
	}
	s.state = ipsec.StateConnecting
	s.retryAt = time.Time{}
	e.opt.Log.Info("ike: 发起协商", "site", s.cfg.ID, "peer", sa.Peer, "spiI", spiHex(sa.SPIi), "套件", s.spec1)
	return nil
}

// peerIKEAddr 补齐对端 IKE 端口（缺省 500）。
func peerIKEAddr(p netip.AddrPort) netip.AddrPort {
	if p.Port() == 0 {
		return netip.AddrPortFrom(p.Addr(), 500)
	}
	return p
}

// buildSAInitRequest 组装 IKE_SA_INIT 请求。
//
// ★载荷顺序是 SA → KE → Nonce → NAT 通知，且 COOKIE（若有）必须排在**最前面**。
// 顺序本身对本实现的解析无所谓，但 RFC 明确规定，且部分实现按顺序校验；
// 更要命的是这条报文的字节会原样进入 AUTH 的待签串，顺序一变两端就对不上。
func (e *Engine) buildSAInitRequest(s *site, sa *IKESA, cookie []byte) ([]byte, error) {
	ps := make([]Payload, 0, 6)
	if len(cookie) > 0 {
		ps = append(ps, &NotifyPayload{
			Protocol:   ProtocolNone,
			NotifyType: NotifyCookie,
			Data:       cookie,
		})
	}
	ps = append(ps,
		&SAPayload{Proposals: []Proposal{sa.Spec.IKEProposal(1)}},
		&KEPayload{Group: sa.Spec.DHID, Data: sa.dh.Public()},
		&NoncePayload{Nonce: sa.ni},
	)
	ps = append(ps, natNotifies(sa.SPIi, sa.SPIr, sa.Local, sa.Peer)...)

	raw, err := Encode(sa.header(ExchangeIKESAInit, 0, false), ps)
	if err != nil {
		return nil, fmt.Errorf("ike: 站点 %s 编码 IKE_SA_INIT 失败: %w", s.cfg.ID, err)
	}
	return raw, nil
}

// resendSAInit 重发 IKE_SA_INIT（COOKIE 或 INVALID_KE_PAYLOAD 之后）。
//
// ★这是唯一允许改写 sa.initMsgRaw 的地方。RealMessage1 必须是**响应方最终实际
// 响应了的那一条**——写在同一个函数里，是为了让"重发但忘了更新 RealMessage1"
// 这个错误在代码结构上不可能发生。
//
// Message ID 仍为 0、SPIi 不变（RFC 7296 §2.6）：对端把这当作同一次协商的续集，
// 换 SPIi 会被当成一次全新连接，COOKIE 校验立刻失败，陷入无限循环。
func (e *Engine) resendSAInit(s *site, sa *IKESA, cookie []byte) error {
	raw, err := e.buildSAInitRequest(s, sa, cookie)
	if err != nil {
		return err
	}
	sa.initMsgRaw = raw
	sa.pending = nil
	sa.State = SASAInitSent
	return e.startExchange(sa, &exchange{kind: exSAInit, et: ExchangeIKESAInit, mid: 0, raw: raw})
}

// onSAInitResponse 处理 IKE_SA_INIT 响应：算共享秘密、派生 IKE 密钥、发 IKE_AUTH。
func (e *Engine) onSAInitResponse(sa *IKESA, ex *exchange, m *Message, d ipsec.Datagram) {
	s := e.sites[sa.SiteID]
	if s == nil {
		e.destroySA(sa, false, "")
		return
	}

	// ── ① COOKIE：不是错误，是"请你带着这个再来一次"（状态类通知 16390）──
	if n := m.FindNotify(NotifyCookie); n != nil {
		if sa.cookieRetries >= maxSAInitRetries {
			e.failSite(s, fmt.Sprintf("对端 %s 连续 %d 次要求 COOKIE 仍不接受连接（对端可能正处于半开连接过载状态）",
				sa.Peer, sa.cookieRetries+1))
			e.destroySA(sa, false, "")
			return
		}
		sa.cookieRetries++
		e.opt.Log.Info("ike: 对端要求 COOKIE，带 cookie 重发 IKE_SA_INIT（RealMessage1 随之更新）",
			"site", s.cfg.ID, "第几次", sa.cookieRetries)
		if err := e.resendSAInit(s, sa, n.Data); err != nil {
			e.failSite(s, err.Error())
			e.destroySA(sa, false, "")
		}
		return
	}

	// ── ② INVALID_KE_PAYLOAD：对端要求换 D-H 群 ──
	if n := m.FindNotify(NotifyInvalidKEPayload); n != nil {
		e.onInvalidKE(s, sa, n)
		return
	}

	// ── ③ 其它错误通知一律终止 ──
	if n := m.FirstErrorNotify(); n != nil {
		e.failSite(s, fmt.Sprintf("对端 %s 拒绝了 IKE_SA_INIT：%s（本端提案：%s）",
			sa.Peer, n.NotifyType, sa.Spec))
		e.destroySA(sa, false, "")
		return
	}

	// ── ④ 正常路径 ──
	if m.Hdr.SPIr == ([8]byte{}) {
		e.opt.Log.Debug("ike: IKE_SA_INIT 响应的 SPIr 为零，丢弃", "site", s.cfg.ID)
		return
	}
	// ★IKE_SA_INIT 重传时对端可能不保存状态，于是把重传当成新连接并回一个**不同的
	// SPIr**。规则：以第一个收到的合法响应为准并锁定 SPIr，之后不同 SPIr 的一律丢弃。
	// 不锁的后果是两端对 SPIr 的认知不一致，AUTH 的密钥派生 seed 里就带着不同的 SPI，
	// 症状又是「认证失败」。
	if sa.SPIr != ([8]byte{}) && sa.SPIr != m.Hdr.SPIr {
		e.opt.Log.Debug("ike: 丢弃 SPIr 不一致的 IKE_SA_INIT 响应（多半是重传被当成了新连接）",
			"site", s.cfg.ID, "已锁定", spiHex(sa.SPIr), "收到", spiHex(m.Hdr.SPIr))
		return
	}
	sa.SPIr = m.Hdr.SPIr

	saPl := findSAPayload(m)
	ke := findKE(m)
	nr := findNonce(m)
	if saPl == nil || ke == nil || len(nr) == 0 {
		e.failSite(s, fmt.Sprintf("对端 %s 的 IKE_SA_INIT 响应缺少必需载荷（SA=%v KE=%v Nonce=%v）",
			sa.Peer, saPl != nil, ke != nil, len(nr) > 0))
		e.destroySA(sa, false, "")
		return
	}

	// 对端只该回一条提案，且必须与本端提的完全一致。用 SelectProposal 复核，
	// 是为了拦住"对端回了一个我们没提过的算法"——那种情况下继续走下去，
	// 双方会用不同算法派生密钥，最终以解密失败告终。
	if _, _, err := SelectProposal(saPl.Proposals, sa.Spec, ProtocolIKE); err != nil {
		e.failSite(s, fmt.Sprintf("对端 %s 回选的 IKE 提案与本端配置不符：%v", sa.Peer, err))
		e.destroySA(sa, false, "")
		return
	}
	if ke.Group != sa.Spec.DHID {
		e.failSite(s, fmt.Sprintf("对端 %s 的 KE 载荷用了 D-H 群 %d，本端协商的是 %d", sa.Peer, ke.Group, sa.Spec.DHID))
		e.destroySA(sa, false, "")
		return
	}

	shared, err := sa.dh.Shared(ke.Data)
	if err != nil {
		e.failSite(s, fmt.Sprintf("对端 %s 的 KE 公钥不合法：%v", sa.Peer, err))
		e.destroySA(sa, false, "")
		return
	}
	sa.nr = nr
	sa.respMsgRaw = m.Raw // RealMessage2

	// NAT 检测必须在切端口**之前**用收包时的实际地址做。
	peerNATed, localNATed, present := detectNAT(m, d.Remote, d.Local)
	if present {
		sa.applyNAT(peerNATed, localNATed, e.opt.LocalNAT, s.cfg.PeerNATPort)
		if peerNATed || localNATed {
			e.opt.Log.Info("ike: 检测到 NAT，IKE_AUTH 起改走 UDP 4500",
				"site", s.cfg.ID, "对端在NAT后", peerNATed, "本端在NAT后", localNATed,
				"本端落点", sa.Local, "对端落点", sa.Peer)
		}
	}
	// 对端**地址**一律以实测值为准（NAT 后配置里的地址根本收不到包；非 NAT 时对端
	// 也可能有多个出口）。
	//
	// ★但只跟随地址、不跟随端口——端口归 applyNAT 管，它刚按「发起方 / 响应方」
	// 分别算好了该发往哪个口。这里若连端口一起覆盖成 d.Remote.Port()，就等于把
	// 刚切到的封装口冲回成 IKE_SA_INIT 响应的源端口（对端的 **IKE 口**）：
	// 本端从封装口发出（带 non-ESP marker），对端在 IKE 口收（不剥 marker）→
	// 解析失败后静默丢弃，协商停在 IKE_AUTH 且两端都不报错。
	// 更隐蔽的是上面那条日志打在覆盖**之前**，显示的落点是对的，与实际发出的不符——
	// 照着日志排查会一直看错方向。
	sa.Peer = netip.AddrPortFrom(d.Remote.Addr(), sa.Peer.Port())

	keys, err := DeriveIKEKeys(sa.Suite, shared, sa.ni, sa.nr, sa.SPIi, sa.SPIr)
	if err != nil {
		e.failSite(s, fmt.Sprintf("派生 IKE 密钥失败：%v", err))
		e.destroySA(sa, false, "")
		return
	}
	sa.Keys = keys
	sa.dh = nil // 共享秘密已经用完，尽早丢弃私钥
	_ = shared

	if err := e.sendAuthRequest(s, sa); err != nil {
		e.failSite(s, err.Error())
		e.destroySA(sa, false, "")
	}
}

// onInvalidKE 处理对端的 INVALID_KE_PAYLOAD。
//
// ★这里有一处真实的价值冲突，代码按"能通 + 说实话"取舍：
// 换群意味着最终跑的 D-H 与控制台配的不一样，而本项目最忌讳"配了 A 跑了 B"。
// 但拒绝换群会让一条与第三方设备的连接永远建不起来，且 RFC 明确要求发起方照做。
// 折中：**照做，但把真实算法写进 NegotiatedProposal**（SiteState 上按真实算法名呈现），
// 并打一条 WARN。这样界面上"配的是 A、谈出来 B"一眼可见，而不是悄悄降级。
func (e *Engine) onInvalidKE(s *site, sa *IKESA, n *NotifyPayload) {
	if len(n.Data) != 2 {
		e.failSite(s, fmt.Sprintf("对端 %s 回了 INVALID_KE_PAYLOAD 但通知数据不是 2 字节的群号（%d 字节）", sa.Peer, len(n.Data)))
		e.destroySA(sa, false, "")
		return
	}
	want := binary.BigEndian.Uint16(n.Data)
	if sa.keRetries >= maxSAInitRetries {
		e.failSite(s, fmt.Sprintf("对端 %s 连续 %d 次要求换 D-H 群，放弃（最后一次要的是群 %d）", sa.Peer, sa.keRetries+1, want))
		e.destroySA(sa, false, "")
		return
	}
	grp, err := LookupDH(want)
	if err != nil || grp == nil {
		e.failSite(s, fmt.Sprintf("对端 %s 要求用 D-H 群 %d，本实现不支持（本端配的是 %s）；请把两端的 phase1.dh 改成同一个受支持的群",
			sa.Peer, want, dhName(sa.Spec.DHID)))
		e.destroySA(sa, false, "")
		return
	}

	sa.keRetries++
	e.opt.Log.Warn("ike: 对端要求换 D-H 群，本端照做——实际跑的群与控制台配置不同，请以 NegotiatedProposal 为准",
		"site", s.cfg.ID, "配置", dhName(sa.Spec.DHID), "实际", dhName(want))

	sa.Spec.DHID = want
	suite, err := sa.Spec.Build()
	if err != nil {
		e.failSite(s, fmt.Sprintf("换到 D-H 群 %d 后套件无法构造：%v", want, err))
		e.destroySA(sa, false, "")
		return
	}
	sa.Suite = suite
	dh, err := suite.DH.Generate(e.opt.Rand)
	if err != nil {
		e.failSite(s, fmt.Sprintf("为 D-H 群 %d 生成私钥失败：%v", want, err))
		e.destroySA(sa, false, "")
		return
	}
	sa.dh = dh
	if err := e.resendSAInit(s, sa, nil); err != nil {
		e.failSite(s, err.Error())
		e.destroySA(sa, false, "")
	}
}

// sendAuthRequest 发出 IKE_AUTH 请求（含第一个 Child SA 的协商）。
//
// 内层载荷顺序：IDi → IDr → AUTH → SA → TSi → TSr → N。
// ★TSi 在前 TSr 在后，且**永远按发起方视角**——响应方回的时候也不许交换，
// 交换的症状是双方各自认为自己的网段被对端接受了，隧道建成后流量方向全反。
func (e *Engine) sendAuthRequest(s *site, sa *IKESA) error {
	idi := idPayload(PayloadIDi, s.cfg.LocalID)
	idr := idPayload(PayloadIDr, s.cfg.RemoteID)

	// AUTH：InitiatorSignedOctets = RealMessage1 ‖ **Nr** ‖ MACedIDForI
	// （交叉关系写在函数名里，见 auth.go）
	macedI := MACedID(sa.Suite.PRF, sa.Keys.SKpi, idi)
	signed := InitiatorSignedOctets(sa.initMsgRaw, sa.nr, macedI)
	auth := &AuthPayload{Method: AuthSharedKeyMIC, Data: PSKAuth(sa.Suite.PRF, s.cfg.PSK, signed)}
	e.opt.Log.Debug("ike: 计算发起方 AUTH", "site", s.cfg.ID, "摘要", SignedOctetsDigest(sa.initMsgRaw, sa.nr, macedI))

	// ★IKE_AUTH 里创建的第一个 Child SA **不允许带 KE 载荷**（RFC 7296 §1.2），
	// 所以提案里也不能带 D-H 变换——用 ForPFS(false) 归一化。
	// PFS 从第一次 CREATE_CHILD_SA 重协商起才生效，这一点要写进文档，
	// 否则"开了 PFS 但第一条 Child SA 没有 PFS"会被当成 bug 反复排查。
	childSpec := s.spec2.ForPFS(false)
	inSPI, err := allocChildSPI(e.opt.Rand)
	if err != nil {
		return err
	}
	child := &ChildSA{SiteID: s.cfg.ID, InSPI: inSPI, Spec: childSpec}

	inner := []Payload{
		idi, idr, auth,
		&SAPayload{Proposals: []Proposal{childSpec.ESPProposal(1, inSPI, false)}},
		&TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{TSFromPrefix(s.cfg.LocalSubnet)}},
		&TSPayload{T: PayloadTSr, Selectors: []TrafficSelector{TSFromPrefix(s.cfg.RemoteSubnet)}},
		// INITIAL_CONTACT 告诉对端"我这边刚起，你手上关于我的旧 SA 可以扔了"。
		// 不发的后果：网关重启后对端会同时留着新旧两条 SA，旧的要等 DPD 判死才清。
		&NotifyPayload{Protocol: ProtocolNone, NotifyType: NotifyInitialContact},
	}

	iv, err := sa.nextIV()
	if err != nil {
		return err
	}
	raw, err := EncryptSK(sa.header(ExchangeIKEAuth, sa.nextTxMID, false),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv, inner)
	if err != nil {
		return fmt.Errorf("ike: 站点 %s 封装 IKE_AUTH 失败: %w", s.cfg.ID, err)
	}

	sa.State = SAAuthSent
	return e.startExchange(sa, &exchange{
		kind: exAuth, et: ExchangeIKEAuth, mid: sa.nextTxMID, raw: raw, childNew: child,
	})
}

// onAuthResponse 处理 IKE_AUTH 响应：校验对端身份、装载第一个 Child SA。
func (e *Engine) onAuthResponse(sa *IKESA, ex *exchange, m *Message, d ipsec.Datagram) {
	s := e.sites[sa.SiteID]
	if s == nil {
		e.destroySA(sa, false, "")
		return
	}

	if err := DecryptSK(m, sa.Suite, sa.EncKeyIn(), sa.IntegKeyIn()); err != nil {
		// 走到这里说明 IKE 密钥两端不一致——而 IKE 密钥只由 DH 与 nonce 决定，
		// 与 PSK 无关。所以这**不是**认证问题，别把它报成「认证失败」误导排障。
		e.failSite(s, fmt.Sprintf("无法解开对端 %s 的 IKE_AUTH 响应（IKE 密钥不一致，与 PSK 无关）：%v", sa.Peer, err))
		e.destroySA(sa, false, "")
		return
	}

	// 认证失败：对端连自己的身份都不会回，直接判死。
	if n := m.FindNotify(NotifyAuthenticationFailed); n != nil {
		e.failSite(s, fmt.Sprintf("对端 %s 拒绝了本端身份 %q：AUTHENTICATION_FAILED（两端 PSK 不一致，或 localId/remoteId 配反了）",
			sa.Peer, s.cfg.LocalID))
		e.destroySA(sa, false, "")
		return
	}

	idr := findID(m, PayloadIDr)
	authPl := findAuth(m)
	if idr == nil || authPl == nil {
		e.failSite(s, fmt.Sprintf("对端 %s 的 IKE_AUTH 响应缺少 IDr 或 AUTH 载荷", sa.Peer))
		e.destroySA(sa, false, "")
		return
	}
	if authPl.Method != AuthSharedKeyMIC {
		e.failSite(s, fmt.Sprintf("对端 %s 用了认证方法 %d，本实现只支持 PSK（方法 2）；对端多半配的是证书认证",
			sa.Peer, authPl.Method))
		e.destroySA(sa, false, "")
		return
	}
	if !sameID(idr, s.cfg.RemoteID) {
		e.failSite(s, fmt.Sprintf("对端身份不符：期望 FQDN %q，实际收到 %s", s.cfg.RemoteID, idr))
		e.destroySA(sa, false, "")
		return
	}

	// ResponderSignedOctets = RealMessage2 ‖ **Ni** ‖ MACedIDForR
	macedR := MACedID(sa.Suite.PRF, sa.Keys.SKpr, idr)
	signed := ResponderSignedOctets(sa.respMsgRaw, sa.ni, macedR)
	if !VerifyPSKAuth(sa.Suite.PRF, s.cfg.PSK, signed, authPl.Data) {
		e.opt.Log.Warn("ike: 对端 AUTH 校验失败，本端算出的待签串摘要如下（与对端日志逐段对比即可定位）",
			"site", s.cfg.ID, "摘要", SignedOctetsDigest(sa.respMsgRaw, sa.ni, macedR))
		e.failSite(s, fmt.Sprintf("对端 %s 的 AUTH 校验失败（两端 PSK 不一致；PSK 口径是**原文字节**，控制面若存的是 hex/base64 必须先解码）", sa.Peer))
		// 回一条 AUTHENTICATION_FAILED 让对端也别等了，然后拆掉。
		e.sendAuthFailedNotice(sa)
		e.destroySA(sa, false, "")
		return
	}

	// 认证通过。IKE SA 从此刻起必须存活，哪怕 Child SA 谈不拢。
	e.armLifetimes(s, sa)

	if err := e.finishChildFromAuth(s, sa, ex, m); err != nil {
		// ★关键分支：认证成功但 Child SA 失败 → IKE SA **存活**，站点置 failed。
		// 拆掉 IKE SA 会让对端以为整条连接没了，它会立刻重连，两端陷入
		// "建了拆、拆了建"的循环，而根因（TS 或算法不匹配）一次都不会被看到。
		sa.State = SAEstablished
		e.failSite(s, err.Error())
		return
	}
	e.markEstablished(s, sa, sa.Spec, ex.childNew.Spec)
	e.opt.Log.Info("ike: 隧道已建立", "site", s.cfg.ID,
		"spiI", spiHex(sa.SPIi), "spiR", spiHex(sa.SPIr),
		"childIn", fmt.Sprintf("%08x", ex.childNew.InSPI),
		"childOut", fmt.Sprintf("%08x", ex.childNew.OutSPI),
		"协商结果", s.negotiated)
}

// finishChildFromAuth 从 IKE_AUTH 响应里取出 Child SA 协商结果并装载。
func (e *Engine) finishChildFromAuth(s *site, sa *IKESA, ex *exchange, m *Message) error {
	if n := m.FirstErrorNotify(); n != nil {
		return fmt.Errorf("对端 %s 接受了身份但拒绝了 Child SA：%s（本端 ESP 提案 %s，网段 %s ↔ %s）",
			sa.Peer, n.NotifyType, ex.childNew.Spec, s.cfg.LocalSubnet, s.cfg.RemoteSubnet)
	}
	saPl := findSAPayload(m)
	tsi := findTS(m, PayloadTSi)
	tsr := findTS(m, PayloadTSr)
	if saPl == nil || tsi == nil || tsr == nil {
		return fmt.Errorf("对端 %s 的 IKE_AUTH 响应缺少 Child SA 协商载荷（SA=%v TSi=%v TSr=%v）",
			sa.Peer, saPl != nil, tsi != nil, tsr != nil)
	}
	if !samePrefixTS(tsi, s.cfg.LocalSubnet, PayloadTSi) || !samePrefixTS(tsr, s.cfg.RemoteSubnet, PayloadTSr) {
		return fmt.Errorf("对端 %s 回的流量选择器与本端配置不一致（本端 TSi=%s TSr=%s，对端回 TSi=%v TSr=%v）；本实现不做 narrowing",
			sa.Peer, s.cfg.LocalSubnet, s.cfg.RemoteSubnet, tsi.Selectors, tsr.Selectors)
	}

	sel, spec, err := SelectProposal(saPl.Proposals, ex.childNew.Spec, ProtocolESP)
	if err != nil {
		return fmt.Errorf("对端 %s 回选的 ESP 提案与本端配置不符：%v", sa.Peer, err)
	}
	outSPI, err := sel.ESPSPI()
	if err != nil {
		return fmt.Errorf("读取对端 %s 的 ESP SPI 失败：%v", sa.Peer, err)
	}

	// 第一个 Child SA 无 PFS：KEYMAT = prf+(SK_d, Ni ‖ Nr)，
	// 且 ★Ni/Nr 用的是 **IKE_SA_INIT 的那两个 nonce**，不是别的。
	ck, err := DeriveChildKeys(sa.Suite.PRF, sa.Keys.SKd, nil, sa.ni, sa.nr, s.espEncrLen, s.espIntegLen)
	if err != nil {
		return fmt.Errorf("派生 Child SA 密钥失败：%v", err)
	}

	c := ex.childNew
	c.OutSPI = outSPI
	c.Spec = spec
	now := e.now()
	c.CreatedAt = now
	c.SoftExpire, c.HardExpire = e.childLifetimes(s, sa, now)
	if err := e.installChild(s, sa, c, ck); err != nil {
		return err
	}
	return nil
}

// sendAuthFailedNotice 在本端判定对端认证失败时回一条 AUTHENTICATION_FAILED。
//
// 它是加密的（此时 IKE 密钥已就绪），所以不构成放大器；发它的价值在于让对端
// 立刻知道"是认证问题"，而不是傻等重传超时后报"对端无响应"——后者会把
// 管理员的注意力引到网络上，而根因在 PSK。
func (e *Engine) sendAuthFailedNotice(sa *IKESA) {
	if sa.Keys == nil {
		return
	}
	iv, err := sa.nextIV()
	if err != nil {
		return
	}
	raw, err := EncryptSK(sa.header(ExchangeInformational, sa.nextTxMID, false),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv,
		[]Payload{&NotifyPayload{Protocol: ProtocolNone, NotifyType: NotifyAuthenticationFailed}})
	if err != nil {
		return
	}
	e.send(sa.Local, sa.Peer, raw)
}

// armLifetimes 设定 IKE SA 的软/硬生存期。
//
// ★软生存期必须带抖动：两端配置相同 → 同时到点 → 必然并发重协商。
// 虽然有 TEMPORARY_FAILURE 兜底，但每次 rekey 都白跑一轮往返。
//
// ★只有**原始发起方**按 0.85~0.95 触发；响应方 +10%（0.95~1.05）作为兜底——
// 对端还活着的时候轮不到它，对端挂了才由它接手。两端都按同样比例触发会
// 100% 撞车，这不是概率问题。
func (e *Engine) armLifetimes(s *site, sa *IKESA) {
	now := e.now()
	hard := s.cfg.IKELifetime
	if hard <= 0 {
		hard = defaultIKELifetime
	}
	sa.hardExpire = now.Add(hard)
	sa.softExpire = now.Add(softLifetime(hard, sa.LocalIsInit, e.opt.Rand))
}

// childLifetimes 给出一条 Child SA 的软/硬到期时刻。
func (e *Engine) childLifetimes(s *site, sa *IKESA, now time.Time) (soft, hard time.Time) {
	d := s.cfg.ESPLifetime
	if d <= 0 {
		d = defaultESPLifetime
	}
	return now.Add(softLifetime(d, sa.LocalIsInit, e.opt.Rand)), now.Add(d)
}

// softLifetime = hard × (0.85 + rand[0,0.10])，响应方再 +10% 并**封顶在 0.98**。
//
// ★封顶那一步不能省。响应方 +10% 后区间是 0.95~1.05——超过 1.0 的那一段意味着
// 软生存期落在硬生存期之后，于是"兜底重协商"永远轮不到，SA 直接硬过期断流。
// 现象是：只要原始发起方那一侧出问题（进程挂了、单向丢包），隧道就会在硬生存期
// 到点时毫无预兆地断一次，且日志里只有一句"硬生存期到期"。封在 0.98 让兜底真的兜得住。
func softLifetime(hard time.Duration, isInitiator bool, rnd interface{ Read([]byte) (int, error) }) time.Duration {
	var b [2]byte
	frac := 0.05
	if _, err := rnd.Read(b[:]); err == nil {
		frac = float64(binary.BigEndian.Uint16(b[:])) / 65535 * 0.10
	}
	ratio := 0.85 + frac
	if !isInitiator {
		if ratio += 0.10; ratio > 0.98 {
			ratio = 0.98
		}
	}
	return time.Duration(float64(hard) * ratio)
}
