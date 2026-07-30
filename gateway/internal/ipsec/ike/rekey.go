package ike

import (
	"encoding/binary"
	"fmt"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// 重协商（CREATE_CHILD_SA，Exchange 36）。
//
// 两种形态共用一个交换类型，靠 SA 载荷里的 Protocol ID 区分：
//   - Protocol=ESP(3) → 换 Child SA（可选 REKEY_SA 通知指明换掉哪一条）
//   - Protocol=IKE(1) → 换 IKE SA（无 TS、无 REKEY_SA，SPI Size=8）
//
// ★三个容易写成"能跑但错"的地方：
//
//  1. **旧 SA 不能立刻拆**。新 Child SA 装好后出向立刻切新的，但**入向旧 SA 要留 5 秒**：
//     对端在途的报文还在用旧 SPI。立刻拆的症状是"每次重协商掉几个包"——
//     在业务侧看是随机丢包，几乎不可能归因到 rekey 上。
//  2. **并发冲突回 TEMPORARY_FAILURE**。两端软生存期同时到点是常态（配置相同），
//     RFC §2.8.1 给了一套 nonce 比大小 + 双 SA 收敛的算法，实现复杂且容易写错；
//     回 TEMPORARY_FAILURE 让对端退避重试是 RFC 明确允许的做法，行为确定得多。
//  3. **IKE SA 重协商后 Message ID 双向归零**，且**发起重协商的一方就是新 SA 的
//     原始发起方**（决定新 SA 的 I 位与密钥 i/r 方向）。沿用旧 SA 的 MID 或角色，
//     症状是重协商"成功"后隧道静默断流。

// childRetireDelay 旧 Child SA 的延迟删除时长（≈2× 报文最大寿命）。
const childRetireDelay = 5 * time.Second

// ikeRetireDelay 旧 IKE SA 的延迟删除时长。
const ikeRetireDelay = 5 * time.Second

// rekeyConflictBackoff 收到 TEMPORARY_FAILURE 后的退避中值；实际取 3s ± 66% ≈ [1s, 5s]。
const rekeyConflictBackoff = 3 * time.Second

// rekeyBackoff 撞车后的随机退避。
//
// ★必须随机。固定退避会让两端以完全相同的节奏反复撞车（活锁）：
// 日志里全是 TEMPORARY_FAILURE，隧道却永远换不成密钥，而每一条日志单看都正常。
func rekeyBackoff(e *Engine) time.Duration {
	return jitter(rekeyConflictBackoff, e.opt.Rand, 66)
}

// ── 发起方 ──

// rekeyChild 对一条 Child SA 发起重协商。
func (e *Engine) rekeyChild(s *site, sa *IKESA, old *ChildSA) error {
	if sa.pending != nil {
		return nil // 窗口固定 1，下一轮定时器再试
	}
	spec := s.spec2 // 已按 cfg.PFS 归一化过 DH 群
	inSPI, err := allocChildSPI(e.opt.Rand)
	if err != nil {
		return err
	}
	ni := readRand(e.opt.Rand, defaultNonceLen)

	inner := []Payload{
		// REKEY_SA 指明"我要换掉的是哪一条"，SPI 放**本端入向**的旧 SPI。
		// 不带这条通知就变成"新建一条 Child SA"，对端会同时保留新旧两条，
		// 旧的要等硬生存期才消失——SA 表越积越多，且两端不一致。
		&NotifyPayload{
			Protocol:   ProtocolESP,
			SPI:        binary.BigEndian.AppendUint32(nil, old.InSPI),
			NotifyType: NotifyRekeySA,
		},
		&SAPayload{Proposals: []Proposal{spec.ESPProposal(1, inSPI, s.cfg.PFS)}},
		&NoncePayload{Nonce: ni},
	}
	ex := &exchange{kind: exRekeyChild, et: ExchangeCreateChildSA, childNi: ni, childOld: old.InSPI}
	if s.cfg.PFS {
		su, err := spec.Build()
		if err != nil {
			return err
		}
		if su.DH == nil {
			return fmt.Errorf("ike: 站点 %s 开了 PFS 但套件里没有 D-H 群", s.cfg.ID)
		}
		dh, err := su.DH.Generate(e.opt.Rand)
		if err != nil {
			return err
		}
		ex.childDH = dh
		inner = append(inner, &KEPayload{Group: spec.DHID, Data: dh.Public()})
	}
	inner = append(inner,
		&TSPayload{T: PayloadTSi, Selectors: []TrafficSelector{TSFromPrefix(s.cfg.LocalSubnet)}},
		&TSPayload{T: PayloadTSr, Selectors: []TrafficSelector{TSFromPrefix(s.cfg.RemoteSubnet)}},
	)

	iv, err := sa.nextIV()
	if err != nil {
		return err
	}
	raw, err := EncryptSK(sa.header(ExchangeCreateChildSA, sa.nextTxMID, false),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv, inner)
	if err != nil {
		return fmt.Errorf("ike: 封装 CREATE_CHILD_SA 失败: %w", err)
	}

	ex.mid = sa.nextTxMID
	ex.raw = raw
	ex.childNew = &ChildSA{SiteID: s.cfg.ID, InSPI: inSPI, Spec: spec, PFS: s.cfg.PFS}
	if err := e.startExchange(sa, ex); err != nil {
		return err
	}
	old.rekeying = true
	sa.State = SARekeying
	if s.state == ipsec.StateUp {
		s.state = ipsec.StateRekeying
	}
	e.opt.Log.Info("ike: 发起 Child SA 重协商", "site", s.cfg.ID,
		"旧入向SPI", fmt.Sprintf("%08x", old.InSPI), "新入向SPI", fmt.Sprintf("%08x", inSPI), "PFS", s.cfg.PFS)
	return nil
}

// onRekeyChildResponse 处理 Child SA 重协商的响应。
func (e *Engine) onRekeyChildResponse(sa *IKESA, ex *exchange, m *Message) {
	s := e.sites[sa.SiteID]
	if s == nil {
		return
	}
	// restore 把重协商状态退回"未在换"，并**把软生存期往后推**。
	//
	// ★推软生存期不是可选的礼貌：timerLifetime 的触发判据是
	// `!rekeying && now >= SoftExpire`，只清 rekeying 而把 SoftExpire 留在已经
	// 过去的时刻，下一个 tick（200ms）立刻再发一次——两端 phase2 配置不一致时
	// （一端开了 PFS、或 enc 一个 GCM 一个 CBC），这就是每秒 5 次的请求风暴 +
	// 每秒 5 条日志刷屏，一直烧到硬生存期，真实故障日志被彻底淹没。
	restore := func() {
		if old := sa.children[ex.childOld]; old != nil {
			old.rekeying = false
			old.SoftExpire = e.now().Add(rekeyBackoff(e))
		}
		sa.State = SAEstablished
		if s.state == ipsec.StateRekeying {
			s.state = ipsec.StateUp
		}
	}

	if err := DecryptSK(m, sa.Suite, sa.EncKeyIn(), sa.IntegKeyIn()); err != nil {
		e.opt.Log.Warn("ike: 无法解开 CREATE_CHILD_SA 响应", "site", s.cfg.ID, "err", err)
		restore()
		return
	}
	sa.lastSeen = e.now()

	if n := m.FirstErrorNotify(); n != nil {
		if n.NotifyType == NotifyTemporaryFailure {
			// 撞车：对端也在换同一条 SA。退避 1~5 秒后重试（随机，见 rekeyBackoff）。
			if old := sa.children[ex.childOld]; old != nil {
				old.rekeying = false
				old.SoftExpire = e.now().Add(rekeyBackoff(e))
			}
			sa.State = SAEstablished
			if s.state == ipsec.StateRekeying {
				s.state = ipsec.StateUp
			}
			e.opt.Log.Info("ike: 对端回 TEMPORARY_FAILURE（重协商撞车），已排随机退避重试", "site", s.cfg.ID)
			return
		}
		e.opt.Log.Warn("ike: 对端拒绝 Child SA 重协商", "site", s.cfg.ID, "notify", n.NotifyType)
		s.lastError = fmt.Sprintf("Child SA 重协商被对端拒绝：%s（旧 SA 仍在承载流量，将在硬生存期到点后断开）", n.NotifyType)
		s.lastErrorAt = e.now()
		restore()
		return
	}

	saPl := findSAPayload(m)
	nr := findNonce(m)
	tsi := findTS(m, PayloadTSi)
	tsr := findTS(m, PayloadTSr)
	if saPl == nil || len(nr) == 0 || tsi == nil || tsr == nil {
		e.opt.Log.Warn("ike: CREATE_CHILD_SA 响应缺少必需载荷", "site", s.cfg.ID)
		restore()
		return
	}
	if !samePrefixTS(tsi, s.cfg.LocalSubnet, PayloadTSi) || !samePrefixTS(tsr, s.cfg.RemoteSubnet, PayloadTSr) {
		e.opt.Log.Warn("ike: 重协商回来的流量选择器与配置不符", "site", s.cfg.ID)
		restore()
		return
	}

	want := s.spec2.ForPFS(s.cfg.PFS)
	sel, spec, err := SelectProposal(saPl.Proposals, want, ProtocolESP)
	if err != nil {
		e.opt.Log.Warn("ike: 重协商回来的 ESP 提案不符", "site", s.cfg.ID, "err", err)
		restore()
		return
	}
	outSPI, err := sel.ESPSPI()
	if err != nil {
		restore()
		return
	}

	var shared []byte
	if s.cfg.PFS {
		ke := findKE(m)
		if ke == nil || ex.childDH == nil {
			e.opt.Log.Warn("ike: 开了 PFS 但重协商响应里没有 KE 载荷（对端多半没开 PFS）", "site", s.cfg.ID)
			restore()
			return
		}
		if shared, err = ex.childDH.Shared(ke.Data); err != nil {
			e.opt.Log.Warn("ike: 重协商的对端 KE 公钥非法", "site", s.cfg.ID, "err", err)
			restore()
			return
		}
	}

	// ★CREATE_CHILD_SA 建的 Child SA 用**该次交换的** Ni/Nr，不是 IKE_SA_INIT 的那两个。
	ck, err := DeriveChildKeys(sa.Suite.PRF, sa.Keys.SKd, shared, ex.childNi, nr, s.espEncrLen, s.espIntegLen)
	if err != nil {
		e.opt.Log.Warn("ike: 派生重协商 Child SA 密钥失败", "site", s.cfg.ID, "err", err)
		restore()
		return
	}

	now := e.now()
	c := ex.childNew
	c.OutSPI = outSPI
	c.Spec = spec
	c.CreatedAt = now
	c.SoftExpire, c.HardExpire = e.childLifetimes(s, sa, now)
	if err := e.installChild(s, sa, c, ck); err != nil {
		e.opt.Log.Warn("ike: 装载重协商出的 Child SA 失败", "site", s.cfg.ID, "err", err)
		restore()
		return
	}
	e.retireChild(sa, ex.childOld, now)

	sa.State = SAEstablished
	s.state = ipsec.StateUp
	s.negotiated = fmt.Sprintf("IKE:%s | ESP:%s", sa.Spec, spec)
	e.opt.Log.Info("ike: Child SA 重协商完成", "site", s.cfg.ID,
		"新入向SPI", fmt.Sprintf("%08x", c.InSPI), "新出向SPI", fmt.Sprintf("%08x", c.OutSPI),
		"旧SPI延迟删除", childRetireDelay)
}

// retireChild 把旧 Child SA 标成退休并排上延迟删除。
func (e *Engine) retireChild(sa *IKESA, inSPI uint32, now time.Time) {
	old := sa.children[inSPI]
	if old == nil {
		return
	}
	old.rekeying = false
	old.retiring = true
	old.retireAt = now.Add(childRetireDelay)
}

// rekeyIKE 换掉整条 IKE SA。
func (e *Engine) rekeyIKE(s *site, sa *IKESA) error {
	if sa.pending != nil {
		return nil
	}
	suite, err := sa.Spec.Build()
	if err != nil {
		return err
	}
	if suite.DH == nil {
		return fmt.Errorf("ike: 站点 %s 的 IKE 套件没有 D-H 群，无法重协商", s.cfg.ID)
	}
	dh, err := suite.DH.Generate(e.opt.Rand)
	if err != nil {
		return err
	}
	newSPIi, err := randIKESPI(e.opt.Rand)
	if err != nil {
		return err
	}
	ni := readRand(e.opt.Rand, defaultNonceLen)

	// SA 载荷里的 SPI 必须是 8 字节的**自己新生成的那半**。
	// ★留空（SPI Size=0）会让对端按 IKE_SA_INIT 的形态解析，重协商以 INVALID_SYNTAX 告终。
	prop := sa.Spec.IKEProposal(1)
	prop.SPI = append([]byte(nil), newSPIi[:]...)

	inner := []Payload{
		&SAPayload{Proposals: []Proposal{prop}},
		&NoncePayload{Nonce: ni},
		&KEPayload{Group: sa.Spec.DHID, Data: dh.Public()},
	}
	iv, err := sa.nextIV()
	if err != nil {
		return err
	}
	raw, err := EncryptSK(sa.header(ExchangeCreateChildSA, sa.nextTxMID, false),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv, inner)
	if err != nil {
		return fmt.Errorf("ike: 封装 IKE SA 重协商失败: %w", err)
	}

	// ★发起重协商的一方就是**新 SA 的原始发起方**，所以 LocalIsInit 恒为 true，
	// 与旧 SA 上本端是什么角色无关。抄旧 SA 的角色是这里最容易犯的错，
	// 症状是重协商"成功"之后所有报文都解不开。
	next := newIKESA(s.cfg.ID, true, e.now())
	next.SPIi = newSPIi
	next.Spec = sa.Spec
	next.Suite = suite
	next.dh = dh
	next.ni = ni
	next.Local = sa.Local
	next.Peer = sa.Peer
	next.PeerNATed, next.LocalNATed = sa.PeerNATed, sa.LocalNATed

	if err := e.startExchange(sa, &exchange{
		kind: exRekeyIKE, et: ExchangeCreateChildSA, mid: sa.nextTxMID, raw: raw, ikeNew: next,
	}); err != nil {
		return err
	}
	sa.rekeying = true
	sa.State = SARekeying
	e.opt.Log.Info("ike: 发起 IKE SA 重协商", "site", s.cfg.ID, "新SPIi", spiHex(newSPIi))
	return nil
}

// onRekeyIKEResponse 处理 IKE SA 重协商的响应。
func (e *Engine) onRekeyIKEResponse(sa *IKESA, ex *exchange, m *Message) {
	s := e.sites[sa.SiteID]
	if s == nil {
		return
	}
	// 与 onRekeyChildResponse 的 restore 同构：失败后必须推软生存期，
	// 否则 timerLifetime 每个 tick（200ms）都会重发一次 CREATE_CHILD_SA。
	abort := func(msg string) {
		sa.rekeying = false
		sa.State = SAEstablished
		sa.softExpire = e.now().Add(rekeyBackoff(e))
		if msg != "" {
			e.opt.Log.Warn("ike: IKE SA 重协商失败（旧 SA 继续承载，退避后再试）", "site", s.cfg.ID, "原因", msg)
		}
	}

	if err := DecryptSK(m, sa.Suite, sa.EncKeyIn(), sa.IntegKeyIn()); err != nil {
		abort(err.Error())
		return
	}
	sa.lastSeen = e.now()
	if n := m.FirstErrorNotify(); n != nil {
		if n.NotifyType == NotifyTemporaryFailure {
			// 撞车：退避后由软生存期再次触发。
			sa.rekeying = false
			sa.State = SAEstablished
			sa.softExpire = e.now().Add(rekeyBackoff(e))
			return
		}
		abort(n.NotifyType.String())
		return
	}

	saPl := findSAPayload(m)
	nr := findNonce(m)
	ke := findKE(m)
	if saPl == nil || len(nr) == 0 || ke == nil {
		abort("响应缺少 SA/Nonce/KE 载荷")
		return
	}
	if _, _, err := SelectProposal(saPl.Proposals, sa.Spec, ProtocolIKE); err != nil {
		abort(err.Error())
		return
	}
	var newSPIr [8]byte
	if len(saPl.Proposals[0].SPI) != 8 {
		abort(fmt.Sprintf("对端回的 IKE 提案 SPI 长度为 %d（应为 8）", len(saPl.Proposals[0].SPI)))
		return
	}
	copy(newSPIr[:], saPl.Proposals[0].SPI)

	next := ex.ikeNew
	shared, err := next.dh.Shared(ke.Data)
	if err != nil {
		abort(err.Error())
		return
	}
	next.SPIr = newSPIr
	next.nr = nr
	keys, err := DeriveRekeyedIKEKeys(next.Suite, sa.Keys.SKd, shared, next.ni, next.nr, next.SPIi, next.SPIr)
	if err != nil {
		abort(err.Error())
		return
	}
	next.Keys = keys
	next.dh = nil
	e.promoteRekeyedIKE(s, sa, next)
}

// ── 响应方 ──

// onCreateChildRequest 处理对端的 CREATE_CHILD_SA 请求（换 Child SA 或换 IKE SA）。
func (e *Engine) onCreateChildRequest(sa *IKESA, m *Message, d ipsec.Datagram) {
	s := e.sites[sa.SiteID]
	if s == nil || sa.Keys == nil {
		return
	}
	if err := DecryptSK(m, sa.Suite, sa.EncKeyIn(), sa.IntegKeyIn()); err != nil {
		e.opt.Log.Debug("ike: 无法解开 CREATE_CHILD_SA 请求", "site", s.cfg.ID, "err", err)
		return
	}
	mid := m.Hdr.MessageID
	sa.expectRxMID = mid + 1
	sa.lastSeen = e.now()

	saPl := findSAPayload(m)
	if saPl == nil || len(saPl.Proposals) == 0 {
		e.replyChildError(sa, mid, d, NotifyInvalidSyntax)
		return
	}
	if saPl.Proposals[0].Protocol == ProtocolIKE {
		e.answerRekeyIKE(s, sa, m, mid, d, saPl)
		return
	}
	e.answerRekeyChild(s, sa, m, mid, d, saPl)
}

// answerRekeyChild 响应一次 Child SA 重协商/新建。
func (e *Engine) answerRekeyChild(s *site, sa *IKESA, m *Message, mid uint32, d ipsec.Datagram, saPl *SAPayload) {
	// ① 冲突检测。本端也正在换同一条（或任意一条）Child SA 时回 TEMPORARY_FAILURE。
	//    ★判据放宽到"本端有任何未完成的 rekey 交换"：窗口固定为 1，同时处理两条
	//    重协商本来就做不到；宽一点的判据换来行为完全确定，代价只是多一轮退避。
	var oldIn uint32
	if n := m.FindNotify(NotifyRekeySA); n != nil && len(n.SPI) == 4 {
		peerIn := binary.BigEndian.Uint32(n.SPI)
		if c := sa.childByOut(peerIn); c != nil {
			oldIn = c.InSPI
		} else {
			// 对端要换一条我们已经不认识的 SA。回 CHILD_SA_NOT_FOUND 而不是默默新建：
			// 默默新建会让两端 SA 表长期不一致，最终表现为单向不通。
			e.replyChildError(sa, mid, d, NotifyChildSANotFound)
			return
		}
	}
	if sa.pending != nil && (sa.pending.kind == exRekeyChild || sa.pending.kind == exRekeyIKE) {
		e.replyChildError(sa, mid, d, NotifyTemporaryFailure)
		e.opt.Log.Info("ike: 重协商撞车，回 TEMPORARY_FAILURE 让对端退避", "site", s.cfg.ID)
		return
	}

	ni := findNonce(m)
	tsi := findTS(m, PayloadTSi)
	tsr := findTS(m, PayloadTSr)
	if len(ni) == 0 || tsi == nil || tsr == nil {
		e.replyChildError(sa, mid, d, NotifyInvalidSyntax)
		return
	}
	// TS 仍是发起方视角：TSi = 对端本地网段 = 本端配置的 RemoteSubnet。
	if !samePrefixTS(tsi, s.cfg.RemoteSubnet, PayloadTSi) || !samePrefixTS(tsr, s.cfg.LocalSubnet, PayloadTSr) {
		e.replyChildError(sa, mid, d, NotifyTSUnacceptable)
		return
	}

	// PFS 是否启用以**对端是否带 KE** 为准，再与本端配置核对：
	// 本端要求 PFS 而对端没带 KE，等于静默把前向保密关掉，必须拒绝。
	ke := findKE(m)
	if s.cfg.PFS && ke == nil {
		e.opt.Log.Warn("ike: 本端要求 PFS，对端重协商请求里却没有 KE 载荷，拒绝（放行等于静默关闭前向保密）", "site", s.cfg.ID)
		e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
		return
	}
	want := s.spec2.ForPFS(s.cfg.PFS)
	sel, spec, err := SelectProposal(saPl.Proposals, want, ProtocolESP)
	if err != nil {
		e.opt.Log.Warn("ike: 拒绝对端的 ESP 重协商提案", "site", s.cfg.ID, "err", err)
		e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
		return
	}
	outSPI, err := sel.ESPSPI()
	if err != nil {
		e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
		return
	}

	var shared []byte
	var myDH DHPrivate
	if s.cfg.PFS {
		su, err := spec.Build()
		if err != nil || su.DH == nil {
			e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
			return
		}
		if myDH, err = su.DH.Generate(e.opt.Rand); err != nil {
			e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
			return
		}
		if shared, err = myDH.Shared(ke.Data); err != nil {
			e.opt.Log.Warn("ike: 重协商的对端 KE 公钥非法", "site", s.cfg.ID, "err", err)
			e.replyChildError(sa, mid, d, NotifyInvalidKEPayload)
			return
		}
	}

	inSPI, err := allocChildSPI(e.opt.Rand)
	if err != nil {
		e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
		return
	}
	nr := readRand(e.opt.Rand, defaultNonceLen)
	ck, err := DeriveChildKeys(sa.Suite.PRF, sa.Keys.SKd, shared, ni, nr, s.espEncrLen, s.espIntegLen)
	if err != nil {
		e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
		return
	}

	resp := []Payload{
		&SAPayload{Proposals: []Proposal{spec.ESPProposal(sel.Num, inSPI, s.cfg.PFS)}},
		&NoncePayload{Nonce: nr},
	}
	if s.cfg.PFS {
		resp = append(resp, &KEPayload{Group: spec.DHID, Data: myDH.Public()})
	}
	resp = append(resp, tsi, tsr)

	iv, err := sa.nextIV()
	if err != nil {
		return
	}
	raw, err := EncryptSK(sa.header(ExchangeCreateChildSA, mid, true),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv, resp)
	if err != nil {
		e.opt.Log.Warn("ike: 封装 CREATE_CHILD_SA 响应失败", "site", s.cfg.ID, "err", err)
		return
	}
	e.respond(sa, mid, d.Remote, raw)

	now := e.now()
	c := &ChildSA{SiteID: s.cfg.ID, InSPI: inSPI, OutSPI: outSPI, Spec: spec, PFS: s.cfg.PFS, CreatedAt: now}
	c.SoftExpire, c.HardExpire = e.childLifetimes(s, sa, now)
	if err := e.installChild(s, sa, c, ck); err != nil {
		e.opt.Log.Warn("ike: 装载重协商出的 Child SA 失败", "site", s.cfg.ID, "err", err)
		return
	}
	if oldIn != 0 {
		e.retireChild(sa, oldIn, now)
	}
	s.negotiated = fmt.Sprintf("IKE:%s | ESP:%s", sa.Spec, spec)
	e.opt.Log.Info("ike: 已响应 Child SA 重协商", "site", s.cfg.ID,
		"新入向SPI", fmt.Sprintf("%08x", inSPI), "新出向SPI", fmt.Sprintf("%08x", outSPI))
}

// answerRekeyIKE 响应一次 IKE SA 重协商。
func (e *Engine) answerRekeyIKE(s *site, sa *IKESA, m *Message, mid uint32, d ipsec.Datagram, saPl *SAPayload) {
	if sa.rekeying || (sa.pending != nil && sa.pending.kind == exRekeyIKE) {
		e.replyChildError(sa, mid, d, NotifyTemporaryFailure)
		return
	}
	ni := findNonce(m)
	ke := findKE(m)
	if len(ni) == 0 || ke == nil || len(saPl.Proposals[0].SPI) != 8 {
		e.replyChildError(sa, mid, d, NotifyInvalidSyntax)
		return
	}
	if _, _, err := SelectProposal(saPl.Proposals, sa.Spec, ProtocolIKE); err != nil {
		e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
		return
	}

	suite, err := sa.Spec.Build()
	if err != nil || suite.DH == nil {
		e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
		return
	}
	dh, err := suite.DH.Generate(e.opt.Rand)
	if err != nil {
		return
	}
	shared, err := dh.Shared(ke.Data)
	if err != nil {
		e.replyChildError(sa, mid, d, NotifyInvalidKEPayload)
		return
	}
	newSPIr, err := randIKESPI(e.opt.Rand)
	if err != nil {
		return
	}
	var newSPIi [8]byte
	copy(newSPIi[:], saPl.Proposals[0].SPI)
	nr := readRand(e.opt.Rand, defaultNonceLen)

	// ★对端发起了重协商 → 对端是新 SA 的原始发起方 → 本端 LocalIsInit=false。
	next := newIKESA(s.cfg.ID, false, e.now())
	next.SPIi, next.SPIr = newSPIi, newSPIr
	next.Spec = sa.Spec
	next.Suite = suite
	next.ni, next.nr = ni, nr
	next.Local, next.Peer = sa.Local, d.Remote
	next.PeerNATed, next.LocalNATed = sa.PeerNATed, sa.LocalNATed
	keys, err := DeriveRekeyedIKEKeys(suite, sa.Keys.SKd, shared, ni, nr, newSPIi, newSPIr)
	if err != nil {
		e.replyChildError(sa, mid, d, NotifyNoProposalChosen)
		return
	}
	next.Keys = keys

	prop := sa.Spec.IKEProposal(saPl.Proposals[0].Num)
	prop.SPI = append([]byte(nil), newSPIr[:]...)
	iv, err := sa.nextIV()
	if err != nil {
		return
	}
	raw, err := EncryptSK(sa.header(ExchangeCreateChildSA, mid, true),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv, []Payload{
			&SAPayload{Proposals: []Proposal{prop}},
			&NoncePayload{Nonce: nr},
			&KEPayload{Group: sa.Spec.DHID, Data: dh.Public()},
		})
	if err != nil {
		e.opt.Log.Warn("ike: 封装 IKE SA 重协商响应失败", "site", s.cfg.ID, "err", err)
		return
	}
	e.respond(sa, mid, d.Remote, raw)
	e.promoteRekeyedIKE(s, sa, next)
}

// promoteRekeyedIKE 把新 IKE SA 顶上：迁移 Child SA、旧 SA 排延迟删除。
//
// ★Child SA 与 IKE SA 是**解耦**的：ESP 数据面只认 SPI 与密钥，换 IKE SA
// 不需要重新协商任何一条 Child SA，也不允许中断它们。所以这里只是把 map 搬过去，
// 不碰 Protector——碰了就会出现"换 IKE SA 时业务流量断一下"。
func (e *Engine) promoteRekeyedIKE(s *site, old *IKESA, next *IKESA) {
	now := e.now()
	next.State = SAEstablished
	next.lastSeen = now
	next.nextTxMID = 0   // ★新 SA 双向 MID 归零
	next.expectRxMID = 0 //
	next.children = old.children
	old.children = make(map[uint32]*ChildSA)
	for _, c := range next.children {
		e.childSite[c.InSPI] = s.cfg.ID
	}
	e.armLifetimes(s, next)
	e.registerSA(s, next)

	// ★rekeying 标记保持为 true：旧 SA 的软生存期早已过去，清掉它会让旧 SA 在
	// 延迟删除到点之前的每一轮定时器里都再发起一次重协商（timerLifetime 里还有
	// 一道 retiring 闸兜底，两处都留着是因为这个错误的表现是"SA 无限繁殖"，
	// 而每条日志单看都正常）。
	old.retiring = true
	old.retireAt = now.Add(ikeRetireDelay)
	old.State = SAEstablished // 保持可收发，直到延迟删除到点

	s.state = ipsec.StateUp
	s.establishedAt = now
	e.opt.Log.Info("ike: IKE SA 重协商完成，新 SA 已顶上", "site", s.cfg.ID,
		"新SPIi", spiHex(next.SPIi), "新SPIr", spiHex(next.SPIr),
		"旧SA延迟删除", ikeRetireDelay, "迁移ChildSA数", len(next.children))
}

// replyChildError 回一条只含错误通知的 CREATE_CHILD_SA 响应。
//
// 这条响应是加密的，所以不构成放大器；而且**必须回**——CREATE_CHILD_SA 是
// 一次正常的请求/响应交换，不回的话对端会一路重传到超时，然后把整条 IKE SA 判死。
func (e *Engine) replyChildError(sa *IKESA, mid uint32, d ipsec.Datagram, nt NotifyType) {
	iv, err := sa.nextIV()
	if err != nil {
		return
	}
	raw, err := EncryptSK(sa.header(ExchangeCreateChildSA, mid, true),
		sa.Suite, sa.EncKeyOut(), sa.IntegKeyOut(), iv,
		[]Payload{&NotifyPayload{Protocol: ProtocolNone, NotifyType: nt}})
	if err != nil {
		return
	}
	e.respond(sa, mid, d.Remote, raw)
}
