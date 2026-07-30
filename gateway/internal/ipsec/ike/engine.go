package ike

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// Engine 是 IKEv2 控制面的对外全部：多站点调度、事件循环、状态导出。
//
// # 并发模型
//
// 一把大锁 e.mu 串行化所有状态变更。这不是偷懒——IKE 是**控制面**，报文速率
// 以每秒个位数计，锁竞争无从谈起；而状态机里"读到一半状态被改"的 bug 极难复现
// （表现为偶发的协商失败）。用一把锁换掉整类竞态，是这里唯一正确的取舍。
//
// 唯一从其它 goroutine 进来的高频调用是 Touch（ESP 收包回调），它只写一个时间戳。
//
// # 时钟注入
//
// 所有超时判定都走 opt.Now()。★这不是可测性洁癖：rekey / DPD / 重传的时间常数
// 是 30 秒到 4 小时，用真实时钟测就只能 sleep，测试会慢到被 -short 跳过，
// 最终等于没有测试。注入时钟后 rekey_test.go 零 sleep。
type Engine struct {
	opt EngineOptions

	mu    sync.Mutex
	sites map[string]*site

	// saByLocal 按**本端那半 SPI** 索引所有活着的 IKE SA。
	// 取键规则见 IKESA.localSPI 的注释（按 I 位取另一半，恒好取到本端的）。
	saByLocal map[[8]byte]*IKESA

	// childSite 入向 ESP SPI → 站点 ID，专供 Touch 用（ESP 数据面只知道 SPI）。
	childSite map[uint32]string

	cookies  *cookieJar
	halfOpen *halfOpenTracker
	limiter  *rateLimiter

	closed bool
}

// EngineOptions 见 PLAN §1.5。除 Transport 外均可省略（有合理默认）。
type EngineOptions struct {
	Transport ipsec.Transport
	// Protector 是与 ESP 数据面的**唯一**接缝。为 nil 时协商照常跑完但不装载
	// Child SA——只在单测里有意义，生产必须给。
	Protector ipsec.Protector

	// LocalIKE 本端 500（或 -ike-port）落点；LocalNAT 本端 4500 落点。
	// 检测到 NAT 后 IKE_AUTH 起改用 LocalNAT，见 nat.go。
	LocalIKE netip.AddrPort
	LocalNAT netip.AddrPort

	Log  *slog.Logger
	Now  func() time.Time
	Rand io.Reader

	// Tick 定时器扫描周期（默认 200ms）。它只决定"多快发现超时"，
	// 不参与任何超时判定本身——那些一律用 Now()。
	Tick time.Duration

	// OnESP 收到 ESP 报文时的回调。
	//
	// ★Transport 的 Recv 是单一队列（IKE 与 ESP 共用一条 socket 是 NAT 穿越的
	// 硬要求，见 types.go），所以只能有一个读者。Engine 是那个读者，于是必须把
	// 不属于自己的 ESP 报文转出去。没有这个回调，site 层的入向泵就会与 Engine
	// 抢同一个 Recv，表现为"一半的包神秘消失"。
	OnESP func(ipsec.Datagram)
}

// site 一条站点在 Engine 里的运行态。
type site struct {
	cfg ipsec.SiteConfig

	spec1 SuiteSpec // IKE SA 套件
	spec2 SuiteSpec // Child SA（ESP）套件，DH 已按 PFS 归一化

	espEncrLen  int // 单方向 ESP 加密密钥长度（GCM 含 4 字节 salt）
	espIntegLen int

	sas []*IKESA // 该站点当前挂着的全部 IKE SA（含半开与待退休）

	state       ipsec.State
	negotiated  string
	lastError   string
	lastErrorAt time.Time

	establishedAt time.Time
	retryAt       time.Time
	retryStep     int

	// fingerprint 用于判断 AddSite 是不是"同一条配置又下发了一遍"。
	// ★不比较就会每 15 秒把所有站点拆了重建——控制面同步是全量声明式的，
	// 每轮都会重下发一次完全一样的配置。症状是隧道每 15 秒断一次。
	fingerprint string
}

// NewEngine 建一个引擎。
func NewEngine(opt EngineOptions) *Engine {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Rand == nil {
		opt.Rand = rand.Reader
	}
	if opt.Log == nil {
		// 丢弃而不是 slog.Default()：库里默认往全局 logger 灌日志，
		// 在单测与嵌入场景里都是噪音。调用方想看就自己传。
		opt.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opt.Tick <= 0 {
		opt.Tick = 200 * time.Millisecond
	}
	return &Engine{
		opt:       opt,
		sites:     make(map[string]*site),
		saByLocal: make(map[[8]byte]*IKESA),
		childSite: make(map[uint32]string),
		cookies:   newCookieJar(opt.Now, opt.Rand),
		halfOpen:  newHalfOpenTracker(),
		limiter:   newRateLimiter(opt.Now),
	}
}

// ── 对外 API ──

// AddSite 装载（或更新）一条站点配置。
//
// 配置不可用时返回 *ipsec.ConfigError 并**不**留下任何状态。
// ★必须 fail loud：站点会被置 failed 并把 Reason 原样回报控制面，让管理员在
// 界面上看到「phase1.dh=group24 本实现不支持」，而不是网关默默跳过这条站点、
// 界面上永远停在 connecting。
func (e *Engine) AddSite(cfg ipsec.SiteConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ipsec.ErrClosed
	}

	fp := siteFingerprint(cfg)
	if old, ok := e.sites[cfg.ID]; ok && old.fingerprint == fp {
		return nil // 同一条配置重复下发（15s 全量同步的常态），什么都不做
	}

	s, err := e.buildSite(cfg)
	if err != nil {
		// 已有同 ID 站点时保留旧的运行态，只把错误挂上去——
		// 把一条正在跑的隧道因为一次配置笔误拆掉，比拒绝新配置更糟。
		if old, ok := e.sites[cfg.ID]; ok {
			old.lastError = err.Error()
			old.lastErrorAt = e.now()
		}
		return err
	}
	s.fingerprint = fp

	if old, ok := e.sites[cfg.ID]; ok {
		// 配置真的变了：旧 SA 已经按旧套件/旧 PSK 协商过，留着只会让
		// 「改了配置但没生效」变成常态。拆掉重来，并把 D(IKE) 发出去。
		for _, sa := range old.sas {
			e.destroySA(sa, true, "站点配置已更新，重新协商")
		}
	}
	e.sites[cfg.ID] = s

	if !cfg.Enabled {
		s.state = ipsec.StateDown
		return nil
	}
	s.state = ipsec.StateConnecting
	s.retryAt = e.now() // 下一次 runTimers 立刻发起
	return nil
}

// RemoveSite 拆除一条站点：向对端发 D(IKE) 后清理本地状态。
//
// ★发 D 不是礼貌问题：不发的话对端会留一条"幽灵 SA"，直到 DPD 判死（默认最长
// 30 秒 + 重传 182 秒）才清理，期间它仍会往一条已经没人接收的隧道里发业务流量。
func (e *Engine) RemoveSite(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.sites[id]
	if !ok {
		return fmt.Errorf("ike: 站点 %s 未装载", id)
	}
	for _, sa := range s.sas {
		e.destroySA(sa, true, "站点已删除")
	}
	delete(e.sites, id)
	return nil
}

// States 导出全部站点的实测运行态，供控制面回报。
//
// ★这里的每一个字段都来自状态机与 ESP 计数器，没有任何一项是配置回显——
// 回显配置正是旧实现「toggle 一下就显示 up」的根源。
func (e *Engine) States() []ipsec.SiteState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ipsec.SiteState, 0, len(e.sites))
	now := e.now()
	for _, s := range e.sites {
		st := ipsec.SiteState{
			SiteID:             s.cfg.ID,
			GatewayID:          s.cfg.GatewayID,
			State:              s.state,
			NegotiatedProposal: s.negotiated,
			LastError:          s.lastError,
			ReportedAt:         now.Unix(),
		}
		if !s.lastErrorAt.IsZero() {
			st.LastErrorAt = s.lastErrorAt.Unix()
		}
		if sa := s.primary(); sa != nil {
			st.IKESPIi = spiHex(sa.SPIi)
			st.IKESPIr = spiHex(sa.SPIr)
			if !s.establishedAt.IsZero() {
				st.EstablishedAt = s.establishedAt.Unix()
			}
			if c := sa.activeChild(); c != nil {
				st.ChildSPIIn = c.InSPI
				st.ChildSPIOut = c.OutSPI
				if !c.SoftExpire.IsZero() {
					st.RekeyAt = c.SoftExpire.Unix()
				}
				if !c.HardExpire.IsZero() {
					st.ExpiresAt = c.HardExpire.Unix()
				}
				if e.opt.Protector != nil {
					st.Counters = e.opt.Protector.Counters(c.InSPI)
				}
			}
		}
		out = append(out, st)
	}
	return out
}

// Touch 由 ESP 数据面在收到**合法**受保护报文时回调，刷新该站点的 DPD 计时。
//
// ★只有 IKE 报文刷新计时是不够的：一条跑着满速业务流量的隧道，IKE 层可能几十分钟
// 一句话都没说。不接这个回调的症状是"越忙的隧道越容易被 DPD 判死"。
func (e *Engine) Touch(inSPI uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id, ok := e.childSite[inSPI]
	if !ok {
		return
	}
	s := e.sites[id]
	if s == nil {
		return
	}
	now := e.now()
	for _, sa := range s.sas {
		if _, ok := sa.children[inSPI]; ok {
			sa.lastSeen = now
		}
	}
}

// Run 事件循环：收包 + 定时器，直到 ctx 取消或 Transport 关闭。
func (e *Engine) Run(ctx context.Context) error {
	recvCh := make(chan ipsec.Datagram, 64)
	errCh := make(chan error, 1)
	go func() {
		for {
			d, err := e.opt.Transport.Recv()
			if err != nil {
				errCh <- err
				return
			}
			select {
			case recvCh <- d:
			case <-ctx.Done():
				return
			}
		}
	}()

	tk := time.NewTicker(e.opt.Tick)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			e.shutdown()
			return ctx.Err()
		case err := <-errCh:
			if errors.Is(err, ipsec.ErrClosed) {
				e.shutdown()
				return nil
			}
			return err
		case d := <-recvCh:
			e.handle(d)
		case <-tk.C:
			e.runTimersGuarded()
		}
	}
}

// shutdown 优雅退出：向所有对端发 D(IKE)。
func (e *Engine) shutdown() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	for _, s := range e.sites {
		for _, sa := range s.sas {
			e.destroySA(sa, true, "网关退出")
		}
	}
}

// ── 收包分发 ──

// handle 处理一个从 Transport 收上来的报文。
//
// ★顶层 panic 兜底：IKE 是网关上第一个「非暗」的对外端口——它必须监听 UDP 500/4500，
// 且在任何认证之前就解析对端报文（SPA 敲门保护不到它）。解析与状态机代码再小心，
// 也不能假设「一定不会 panic」：一旦某条路径真的 panic，整个 baidi-ipsec 进程就没了，
// 于是**一个畸形包 = 打掉全站点组网**，这是最廉价的远程 DoS。
//
// 兜底把「打掉进程」降级成「丢一个包 + 一条响亮的日志」。注意几点取舍：
//   - defer 是 LIFO，本 recover 注册最早、执行最晚，因此 handle 内部的
//     `defer e.mu.Unlock()` 会先于它执行——锁一定会被释放，不会死锁；
//   - panic 若发生在状态修改中途，该 SA 的状态可能已不自洽。这里刻意**不**尝试
//     就地修复：修复逻辑本身也可能 panic。日志里带上对端地址与堆栈，靠 DPD/重传
//     超时把这条 SA 自然拆掉，比冒险续用一个半坏的状态安全；
//   - 打 Error 级别并附堆栈，是因为这条日志出现就意味着有真 bug，必须能被发现。
//     兜底不是用来掩盖 panic 的，是用来让进程活着把 panic 报出来。
func (e *Engine) handle(d ipsec.Datagram) {
	defer func() {
		if r := recover(); r != nil {
			e.opt.Log.Error("ike: 处理报文时发生 panic（已丢弃该包，进程继续运行）",
				"from", d.Remote, "kind", d.Kind, "字节", len(d.Payload),
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
		}
	}()

	switch d.Kind {
	case ipsec.KindKeepalive:
		return // 单字节 0xFF，收到即丢（RFC 3948 §4）
	case ipsec.KindESP:
		if e.opt.OnESP != nil {
			e.opt.OnESP(d)
		}
		return
	}

	m, err := Decode(d.Payload)
	if err != nil {
		// ★未认证阶段的解析失败一律**静默丢包**，不回任何东西。
		// 回一个 INVALID_SYNTAX 就意味着：攻击者用一个伪造源 IP 的畸形包，
		// 换我们发一个包到受害者——反射放大器。这条纪律没有例外。
		e.opt.Log.Debug("ike: 丢弃无法解析的报文", "from", d.Remote, "字节", len(d.Payload), "err", err)
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}

	if m.Hdr.ExchangeType == ExchangeIKESAInit && m.Hdr.IsRequest() {
		e.onSAInitRequest(m, d)
		return
	}

	sa := e.lookupSA(m.Hdr)
	if sa == nil {
		// 找不到 SA。RFC 允许回 INVALID_IKE_SPI，本实现选择静默丢弃：
		// 该通知本身是明文且不需要任何认证，同样是放大器；而它带来的排障价值
		// （"对端认为 SA 还在"）已经由 DPD 覆盖。
		e.opt.Log.Debug("ike: 报文的 SPI 对不上任何 SA，丢弃",
			"from", d.Remote, "exchange", m.Hdr.ExchangeType,
			"spiI", spiHex(m.Hdr.SPIi), "spiR", spiHex(m.Hdr.SPIr))
		return
	}

	if m.Hdr.IsRequest() {
		e.onRequest(sa, m, d)
	} else {
		e.onResponse(sa, m, d)
	}
}

// lookupSA 按 I 位从报文头里取出**本端那半** SPI 并查表。
func (e *Engine) lookupSA(h Header) *IKESA {
	var key [8]byte
	if h.FromInitiator() {
		key = h.SPIr
	} else {
		key = h.SPIi
	}
	if key == ([8]byte{}) {
		return nil
	}
	sa := e.saByLocal[key]
	if sa == nil {
		return nil
	}
	// 两半都要对上：只比一半的话，一条伪造报文只要蒙对 8 字节里的一半就能
	// 让我们走进状态机（虽然过不了完整性校验，但足以干扰 MID 计数）。
	//
	// ★唯一的例外是 IKE_SA_INIT 响应：本端此刻还没有 SPIr（它正是这条响应
	// 要告诉我们的）。此时只能比 SPIi。忘了这条例外的症状是握手永远停在第二步，
	// 日志里只有一句「SPI 对不上任何 SA」——而两个 SPI 打出来看着都对。
	if sa.SPIi != h.SPIi {
		return nil
	}
	if sa.SPIr != h.SPIr {
		unlockedInit := sa.SPIr == ([8]byte{}) &&
			h.ExchangeType == ExchangeIKESAInit && !h.IsRequest()
		if !unlockedInit {
			return nil
		}
	}
	return sa
}

// onRequest 处理对端发来的请求（Message ID 规则的执行点）。
func (e *Engine) onRequest(sa *IKESA, m *Message, d ipsec.Datagram) {
	mid := m.Hdr.MessageID
	switch {
	case mid < sa.expectRxMID:
		// 对端重传。★必须**原样回放**缓存的响应字节，不得重新计算：
		// 重算会推进 GCM 的 IV 计数器并用新 nonce 加密，而对端会把两条内容不同的
		// 响应都当成同一个 MID 的答复——更糟的是，若实现里 IV 取的是"当前计数"
		// 而非"自增后的计数"，就直接构成 nonce 复用。
		if raw, ok := sa.replayResponse(mid); ok {
			e.send(sa.Local, d.Remote, raw)
			e.opt.Log.Debug("ike: 回放缓存响应", "site", sa.SiteID, "mid", mid)
			return
		}
		e.opt.Log.Debug("ike: 丢弃过期请求", "site", sa.SiteID, "mid", mid, "期待", sa.expectRxMID)
		return
	case mid > sa.expectRxMID:
		// 超窗。窗口固定为 1，理论上不该出现。
		// ★但实现分歧确实存在（尤其是"原始响应方自发的第一个请求该用 MID 0 还是接着数"），
		// 一条纯粹的拒绝会让互通彻底失败且无从诊断。落在 4 个之内就重同步并记 WARN；
		// 超出仍拒——重放保护的上界不因兼容性而放宽。
		if mid <= sa.expectRxMID+4 {
			e.opt.Log.Warn("ike: 对端请求的 Message ID 跳号，已重同步（对端实现与本端对 MID 起点的理解不同）",
				"site", sa.SiteID, "收到", mid, "期待", sa.expectRxMID)
			sa.expectRxMID = mid
		} else {
			e.opt.Log.Debug("ike: 丢弃超窗请求", "site", sa.SiteID, "mid", mid, "期待", sa.expectRxMID)
			return
		}
	}

	// ★已认证闸：IKE_AUTH 之外的一切交换都必须发生在**认证之后**。
	//
	// 少了这道闸就不是"防御纵深不足"，而是 PSK 认证被整体绕过：SK_e/SK_a 只由 DH 共享
	// 秘密 + Ni/Nr + SPI 派生（见 DeriveIKEKeys），PSK 只进 AUTH 载荷。于是任何能完成
	// 一次 IKE_SA_INIT 的对端——完全不知道 PSK——都持有可用的 SK 密钥，能自行加解密 SK
	// 载荷。它只要跳过 IKE_AUTH 直接发 CREATE_CHILD_SA，就能让本端 installChild，
	// 拿到一条真能收发业务流量的 ESP 隧道直通内网。而 States() 因 primary() 要求
	// SAEstablished 仍不显示 up：数据面已通、控制台无痕。
	//
	// 判据用 State 而非 Keys != nil：响应方在 IKE_SA_INIT 阶段（回 SA_INIT 响应时）
	// 就已经置好 Keys 且 State 仍是 SAHalfOpen——"密钥就绪"恰恰不等于"身份已验"。
	if m.Hdr.ExchangeType != ExchangeIKEAuth && !sa.State.authenticated() {
		e.opt.Log.Warn("ike: 拒绝未完成 IKE_AUTH 的对端发来的交换（PSK 未验证即请求建 SA）",
			"site", sa.SiteID, "exchange", m.Hdr.ExchangeType, "state", sa.State, "peer", sa.Peer)
		return
	}

	switch m.Hdr.ExchangeType {
	case ExchangeIKEAuth:
		e.onAuthRequest(sa, m, d)
	case ExchangeCreateChildSA:
		e.onCreateChildRequest(sa, m, d)
	case ExchangeInformational:
		e.onInformationalRequest(sa, m, d)
	default:
		e.opt.Log.Debug("ike: 忽略不支持的交换类型", "site", sa.SiteID, "exchange", m.Hdr.ExchangeType)
	}
}

// onResponse 处理对端对本端请求的响应。
func (e *Engine) onResponse(sa *IKESA, m *Message, d ipsec.Datagram) {
	ex := sa.pending
	if ex == nil || ex.mid != m.Hdr.MessageID {
		// 迟到的响应或重复响应。丢弃即可——本端的请求要么已经完成，要么已放弃。
		e.opt.Log.Debug("ike: 丢弃无主响应", "site", sa.SiteID, "mid", m.Hdr.MessageID)
		return
	}
	if ex.et != m.Hdr.ExchangeType {
		e.opt.Log.Debug("ike: 响应的交换类型与请求不符，丢弃",
			"site", sa.SiteID, "请求", ex.et, "响应", m.Hdr.ExchangeType)
		return
	}

	sa.pending = nil
	// ★只前进不回退：allocTxMID 可能已经为一条不等响应的 D(IKE) 借走了更大的号，
	// 直接赋 ex.mid+1 会把计数器退回去，下一个请求就复用已经用掉的 MID
	// （对端会把它当重传、回放旧响应）。
	if next := ex.mid + 1; next > sa.nextTxMID {
		sa.nextTxMID = next
	}
	sa.lastSeen = e.now()

	switch ex.kind {
	case exSAInit:
		e.onSAInitResponse(sa, ex, m, d)
	case exAuth:
		e.onAuthResponse(sa, ex, m, d)
	case exRekeyChild:
		e.onRekeyChildResponse(sa, ex, m)
	case exRekeyIKE:
		e.onRekeyIKEResponse(sa, ex, m)
	case exDPD, exDelete:
		e.onInformationalResponse(sa, ex, m)
	}
}

// ── 发送 ──

// send 把一条已编码好的 IKE 报文交给 Transport。
//
// ★local 必须显式给出：生产 Transport 同时监听 500 与 4500，靠它决定从哪条
// socket 发出去。填错的症状是"NAT 后的对端收不到 IKE_AUTH"——而 IKE_SA_INIT
// 明明通了，看起来像认证问题。
func (e *Engine) send(local, remote netip.AddrPort, raw []byte) {
	if e.opt.Transport == nil {
		return
	}
	if err := e.opt.Transport.Send(ipsec.Datagram{
		Kind:    ipsec.KindIKE,
		Local:   local,
		Remote:  remote,
		Payload: raw,
	}); err != nil && !errors.Is(err, ipsec.ErrClosed) {
		e.opt.Log.Warn("ike: 发送失败", "remote", remote, "err", err)
	}
}

// startExchange 发出一个新的出向请求并挂上重传定时器。
//
// ★窗口固定为 1：已有未完成请求时直接拒绝，而不是排队。排队会让 MID 分配
// 与响应匹配变复杂，而 IKE 控制面根本不需要并发——DPD、rekey、Delete 晚几秒
// 发出去没有任何影响。
func (e *Engine) startExchange(sa *IKESA, ex *exchange) error {
	if sa.pending != nil {
		return fmt.Errorf("ike: 站点 %s 已有未完成的 %s 交换（窗口固定为 1）", sa.SiteID, sa.pending.et)
	}
	ex.tries = 1
	ex.nextAt = e.now().Add(retransmitDelay(1, e.opt.Rand))
	sa.pending = ex
	e.send(sa.Local, sa.Peer, ex.raw)
	return nil
}

// respond 发出一条响应并写入响应缓存。两件事必须成对做，所以只有这一个入口。
func (e *Engine) respond(sa *IKESA, mid uint32, remote netip.AddrPort, raw []byte) {
	sa.cacheResponse(mid, raw)
	e.send(sa.Local, remote, raw)
}

// ── 定时器 ──

// runTimersGuarded 是 runTimers 的 panic 兜底外壳。
//
// 定时器路径同样触碰由对端输入塑造出来的状态（SA 生存期、重传队列、rekey 状态机），
// 所以和收包路径一样不能假设不会 panic。区别在于：定时器是**自驱动**的，
// 一次 panic 若打掉进程，表现为「隧道好好的，过一会儿整个进程没了」，
// 比收包路径更难归因——所以这层兜底同样必要。
func (e *Engine) runTimersGuarded() {
	defer func() {
		if r := recover(); r != nil {
			e.opt.Log.Error("ike: 定时器处理发生 panic（已跳过本轮，进程继续运行）",
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
		}
	}()
	e.runTimers()
}

// runTimers 扫描一遍所有站点与 SA 的超时。
//
// 它是幂等的：多调用几次不会有副作用（判定全部基于 Now() 与到点时刻）。
// 测试因此可以在推进注入时钟后直接调用它，无需等真实 ticker。
func (e *Engine) runTimers() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	now := e.now()

	for _, s := range e.sites {
		// ① 每条 SA 的定时职责
		for _, sa := range s.sas {
			e.timerRetransmit(s, sa, now)
			e.timerHalfOpen(s, sa, now)
			e.timerLifetime(s, sa, now)
			e.timerDPD(s, sa, now)
			e.timerKeepalive(sa, now)
			e.timerRetire(sa, now)
		}
		// ② 清理已死的 SA
		e.reapSAs(s)
		// ③ 站点级重连
		if s.cfg.Enabled && s.primary() == nil && !s.hasInFlight() && !s.retryAt.IsZero() && !now.Before(s.retryAt) {
			if err := e.initiate(s); err != nil {
				e.failSite(s, err.Error())
			}
		}
	}
}

// timerRetransmit 重传未完成的出向请求；耗尽即判死。
func (e *Engine) timerRetransmit(s *site, sa *IKESA, now time.Time) {
	ex := sa.pending
	if ex == nil || now.Before(ex.nextAt) {
		return
	}
	if ex.tries > maxRetransmits {
		sa.pending = nil
		reason := fmt.Sprintf("对端 %s 无响应（%s 交换重传 %d 次全部超时，累计约 %s）",
			sa.Peer, ex.et, maxRetransmits, totalRetransmitWindow())
		e.opt.Log.Warn("ike: 交换超时", "site", sa.SiteID, "exchange", ex.et, "peer", sa.Peer)
		e.failSite(s, reason)
		e.destroySA(sa, false, reason) // 对端本来就不回，发 D 没有意义
		return
	}
	// ★原样重发缓存的字节，不重新构造（见 retransmit.go 开头第 2、3 条）。
	e.send(sa.Local, sa.Peer, ex.raw)
	ex.tries++
	ex.nextAt = now.Add(retransmitDelay(ex.tries, e.opt.Rand))
}

func totalRetransmitWindow() time.Duration {
	var t time.Duration
	for _, d := range retransmitDelays {
		t += d
	}
	return t
}

// timerHalfOpen 清理超时的 half-open SA（响应方侧）。
//
// ★静默清理，不通知对端：对端根本没完成认证，我们无法证明它是谁，
// 给它发任何东西都只是把自己变成放大器。
func (e *Engine) timerHalfOpen(s *site, sa *IKESA, now time.Time) {
	if sa.State != SAHalfOpen || sa.halfOpenUntil.IsZero() || now.Before(sa.halfOpenUntil) {
		return
	}
	e.opt.Log.Debug("ike: half-open 超时，静默清理", "site", sa.SiteID, "peer", sa.Peer)
	e.destroySA(sa, false, "")
	if s.primary() == nil && s.cfg.Enabled && s.state != ipsec.StateFailed {
		s.state = ipsec.StateConnecting
	}
}

// timerLifetime 处理软/硬生存期。
func (e *Engine) timerLifetime(s *site, sa *IKESA, now time.Time) {
	if sa.State != SAEstablished && sa.State != SARekeying {
		return
	}
	// ★已被新 SA 取代、正在等延迟删除的旧 SA 一律跳过。
	// 漏了这一条会踩一个很隐蔽的坑：旧 SA 的软生存期早就过去了（正是它触发了这次
	// 重协商），于是每一轮定时器都会让它再发起一次 IKE SA 重协商——每 5 秒换一条
	// 新 SA，无限繁殖，而日志里每一行看起来都完全正常。
	if sa.retiring {
		return
	}
	// 硬生存期：到点必须消失。留着等于用一把超期的密钥继续加密。
	if !sa.hardExpire.IsZero() && !now.Before(sa.hardExpire) {
		e.destroySA(sa, true, "IKE SA 硬生存期到期")
		return
	}
	for _, c := range sa.children {
		if c.retiring {
			continue
		}
		if !c.HardExpire.IsZero() && !now.Before(c.HardExpire) {
			e.removeChild(sa, c, true, "Child SA 硬生存期到期")
			continue
		}
		if !c.rekeying && !c.SoftExpire.IsZero() && !now.Before(c.SoftExpire) {
			if err := e.rekeyChild(s, sa, c); err != nil {
				e.opt.Log.Warn("ike: 发起 Child SA 重协商失败", "site", s.cfg.ID, "err", err)
			}
		}
	}
	// ★只有**原始发起方**在软生存期到点时换 IKE SA。两端都换会立刻撞成
	// 并发重协商，虽然有 TEMPORARY_FAILURE 兜底，但白白多一轮往返。
	// 响应方的软生存期由 initiator.go 设成 +10%，只在对端失联时兜底。
	if !sa.rekeying && !sa.softExpire.IsZero() && !now.Before(sa.softExpire) {
		if err := e.rekeyIKE(s, sa); err != nil {
			e.opt.Log.Warn("ike: 发起 IKE SA 重协商失败", "site", s.cfg.ID, "err", err)
		}
	}
}

// timerDPD 空闲超过 DPDDelay 就发一个空的 INFORMATIONAL 探活。
func (e *Engine) timerDPD(s *site, sa *IKESA, now time.Time) {
	if sa.State != SAEstablished && sa.State != SARekeying || sa.retiring {
		return
	}
	if sa.pending != nil {
		return // 已有未完成交换，它自己的重传就是探活
	}
	delay := s.cfg.DPDDelay
	if delay <= 0 {
		delay = 30 * time.Second
	}
	if now.Sub(sa.lastSeen) < delay {
		return
	}
	if err := e.sendDPD(sa); err != nil {
		e.opt.Log.Debug("ike: 发起 DPD 失败", "site", sa.SiteID, "err", err)
	}
}

// timerKeepalive 本端在 NAT 后时定期发单字节 0xFF 保住 NAT 映射。
func (e *Engine) timerKeepalive(sa *IKESA, now time.Time) {
	if !sa.LocalNATed || sa.State != SAEstablished {
		return
	}
	if now.Sub(sa.lastKeepalive) < natKeepaliveInterval {
		return
	}
	sa.lastKeepalive = now
	if e.opt.Transport == nil {
		return
	}
	_ = e.opt.Transport.Send(ipsec.Datagram{
		Kind:    ipsec.KindKeepalive,
		Local:   sa.Local,
		Remote:  sa.Peer,
		Payload: []byte{0xFF},
	})
}

// timerRetire 执行延迟删除：被取代的 Child SA / IKE SA 到点才真拆。
func (e *Engine) timerRetire(sa *IKESA, now time.Time) {
	for _, c := range sa.children {
		if c.retiring && !c.retireAt.IsZero() && !now.Before(c.retireAt) {
			e.removeChild(sa, c, true, "旧 Child SA 延迟删除到点")
		}
	}
	if sa.retiring && !sa.retireAt.IsZero() && !now.Before(sa.retireAt) {
		e.destroySA(sa, true, "旧 IKE SA 延迟删除到点")
	}
}

// reapSAs 把 SADead 的 SA 从站点里摘掉。
func (e *Engine) reapSAs(s *site) {
	alive := s.sas[:0]
	for _, sa := range s.sas {
		if sa.State == SADead {
			continue
		}
		alive = append(alive, sa)
	}
	for i := len(alive); i < len(s.sas); i++ {
		s.sas[i] = nil
	}
	s.sas = alive
}

// ── 站点辅助 ──

// primary 返回该站点当前承载流量的 IKE SA（已建立且未进入退休期）。
func (s *site) primary() *IKESA {
	var best *IKESA
	for _, sa := range s.sas {
		if sa.retiring || (sa.State != SAEstablished && sa.State != SARekeying) {
			continue
		}
		if best == nil || sa.createdAt.After(best.createdAt) {
			best = sa
		}
	}
	return best
}

// hasInFlight 报告是否有正在协商中的 SA（避免与重连定时器打架）。
func (s *site) hasInFlight() bool {
	for _, sa := range s.sas {
		switch sa.State {
		case SASAInitSent, SAAuthSent, SAHalfOpen:
			return true
		}
	}
	return false
}

// buildSite 把配置翻译成运行态（套件映射的唯一入口）。
func (e *Engine) buildSite(cfg ipsec.SiteConfig) (*site, error) {
	cfgErr := func(field, reason string) error {
		return &ipsec.ConfigError{SiteID: cfg.ID, Field: field, Reason: reason}
	}
	if cfg.ID == "" {
		return nil, cfgErr("id", "站点 ID 为空")
	}
	if cfg.Auth != "" && cfg.Auth != "psk" {
		return nil, cfgErr("auth", fmt.Sprintf("本轮只实现 PSK 认证，auth=%q 不支持（证书认证需要 RFC 7427 数字签名与 CERT/CERTREQ 载荷，尚未动工）", cfg.Auth))
	}
	if len(cfg.PSK) == 0 {
		// ★空 PSK 在密码学上完全可用：两端都空就能建起一条**没有任何认证**的隧道，
		// 全程零报错、界面显示 up。这正是必须在装载期拒绝的理由。
		return nil, cfgErr("psk", "PSK 为空——空 PSK 能协商成功，会建立一条没有任何认证的隧道")
	}
	if !cfg.Peer.IsValid() {
		return nil, cfgErr("peer", "对端 IKE 落点无效")
	}
	if !cfg.LocalSubnet.IsValid() || !cfg.RemoteSubnet.IsValid() {
		return nil, cfgErr("subnet", "本端/对端受保护网段无效")
	}
	if cfg.LocalID == "" || cfg.RemoteID == "" {
		return nil, cfgErr("id", "localId/remoteId 不能为空（NAT 场景下必须用 FQDN 形态的身份，不能靠 IP 匹配）")
	}

	spec1, err := SpecFromPhase(cfg.Phase1, cfg.Suite, false)
	if err != nil {
		return nil, specToConfigError(cfg.ID, err)
	}
	spec2, err := SpecFromPhase(cfg.Phase2, cfg.Suite, true)
	if err != nil {
		return nil, specToConfigError(cfg.ID, err)
	}
	// ★必须用 ForPFS 归一化：SpecFromPhase(phase2,…) 总带回一个 DH 群（Phase2.DH 必填），
	// 而关了 PFS 的对端提案里根本没有 D-H 变换。不归一化会让一条配置完全正确的站点
	// 永远谈不拢，且错误信息还指着 DH 群——极具误导性。
	spec2 = spec2.ForPFS(cfg.PFS)

	espSuite, err := spec2.Build()
	if err != nil {
		return nil, cfgErr("phase2", err.Error())
	}

	return &site{
		cfg:         cfg,
		spec1:       spec1,
		spec2:       spec2,
		espEncrLen:  espSuite.Encr.KeyLen(),
		espIntegLen: espSuite.IntegKeyLen(),
		state:       ipsec.StateDown,
	}, nil
}

// specToConfigError 把 *SpecError 原样翻译成控制面看得懂的 ConfigError。
func specToConfigError(siteID string, err error) error {
	var se *SpecError
	if errors.As(err, &se) {
		reason := se.Reason
		if se.Value != "" {
			reason = fmt.Sprintf("%s=%q：%s", se.Field, se.Value, se.Reason)
		}
		return &ipsec.ConfigError{SiteID: siteID, Field: se.Field, Reason: reason}
	}
	return &ipsec.ConfigError{SiteID: siteID, Field: "suite", Reason: err.Error()}
}

// siteFingerprint 只覆盖**会影响协商结果**的字段。
//
// ★把 PSKVersion 而不是 PSK 本身放进指纹：PSK 不进任何可能被打印的结构，
// 一次 debug 打印就是永久泄漏（风险清单第 12 条）。
// PeerNATPort 也在内：它决定 ESP 往哪个端口发（espEndpoints）。漏算的话，
// 管理员单独改这一个字段时指纹不变 → AddSite 判为"同一条配置又下发了一遍"
// 直接 return → 改动永远不生效，且界面上隧道还是 up 的。
func siteFingerprint(c ipsec.SiteConfig) string {
	return fmt.Sprintf("%v|%s|%s|%s|%s|%s|%s|%v|%v|%v|%v|%d|%v|%v|%v|%v|%d",
		c.Enabled, c.GatewayID, c.Peer, c.LocalSubnet, c.RemoteSubnet, c.LocalID, c.RemoteID,
		c.Auth, c.Suite, c.Phase1, c.Phase2, c.PSKVersion, c.PFS,
		c.IKELifetime, c.ESPLifetime, c.DPDDelay, c.PeerNATPort)
}

// findSiteByPeer 按对端 IP 找站点（响应方收到 IKE_SA_INIT 时用）。
//
// ★只比 IP 不比端口：对端在 NAT 后时源端口是 NAT 随机分配的，比端口必然匹配不上，
// 症状是"NAT 后的对端永远连不进来"，而日志里连一条记录都没有（静默丢包）。
func (e *Engine) findSiteByPeer(remote netip.AddrPort) *site {
	ip := remote.Addr().Unmap()
	for _, s := range e.sites {
		if !s.cfg.Enabled {
			continue
		}
		if s.cfg.Peer.Addr().Unmap() == ip {
			return s
		}
	}
	return nil
}

// ── SA 生命周期 ──

// registerSA 把 SA 挂进站点与索引。
func (e *Engine) registerSA(s *site, sa *IKESA) {
	s.sas = append(s.sas, sa)
	e.saByLocal[sa.localSPI()] = sa
}

// destroySA 拆一条 IKE SA：可选发 D(IKE)、拆掉全部 Child SA、清索引。
func (e *Engine) destroySA(sa *IKESA, sendDelete bool, reason string) {
	if sa.State == SADead {
		return
	}
	if sendDelete && sa.Keys != nil && !sa.deleteSent &&
		(sa.State == SAEstablished || sa.State == SARekeying || sa.State == SADeleting) {
		sa.deleteSent = true
		// 尽力而为：发不出去也照拆本地状态，否则一条发不出包的 SA 会永远赖着。
		if err := e.sendDeleteIKE(sa); err != nil {
			e.opt.Log.Debug("ike: 发送 D(IKE) 失败（仍继续本地拆除）", "site", sa.SiteID, "err", err)
		}
	}
	for _, c := range sa.children {
		e.detachChild(sa, c)
	}
	if sa.countedHalfOpen {
		e.halfOpen.remove(sa.halfOpenIP)
		sa.countedHalfOpen = false
	}
	if cur, ok := e.saByLocal[sa.localSPI()]; ok && cur == sa {
		delete(e.saByLocal, sa.localSPI())
	}
	sa.pending = nil
	sa.State = SADead
	if reason != "" {
		e.opt.Log.Info("ike: 拆除 IKE SA", "site", sa.SiteID, "原因", reason,
			"spiI", spiHex(sa.SPIi), "spiR", spiHex(sa.SPIr))
	}
	// 站点状态：主用 SA 没了就退回 connecting（除非已被判 failed）。
	if s := e.sites[sa.SiteID]; s != nil && s.primary() == nil {
		if s.cfg.Enabled && s.state != ipsec.StateFailed {
			s.state = ipsec.StateConnecting
			s.establishedAt = time.Time{}
			if s.retryAt.IsZero() || s.retryAt.Before(e.now()) {
				s.retryAt = e.now().Add(siteRetryDelay(s.retryStep, e.opt.Rand))
			}
		} else if !s.cfg.Enabled {
			s.state = ipsec.StateDown
		}
	}
}

// detachChild 只做本地拆除（从 Protector 摘掉 + 清索引），不发任何报文。
func (e *Engine) detachChild(sa *IKESA, c *ChildSA) {
	if c.installed && e.opt.Protector != nil {
		if err := e.opt.Protector.Remove(c.InSPI); err != nil {
			e.opt.Log.Debug("ike: 从数据面摘除 Child SA 失败", "site", sa.SiteID, "inSPI", c.InSPI, "err", err)
		}
	}
	c.installed = false
	delete(sa.children, c.InSPI)
	if id, ok := e.childSite[c.InSPI]; ok && id == sa.SiteID {
		delete(e.childSite, c.InSPI)
	}
}

// removeChild 拆一条 Child SA，可选向对端发 D(ESP)。
func (e *Engine) removeChild(sa *IKESA, c *ChildSA, sendDelete bool, reason string) {
	if sendDelete && sa.State == SAEstablished && sa.pending == nil {
		if err := e.sendDeleteChild(sa, []uint32{c.InSPI}); err != nil {
			e.opt.Log.Debug("ike: 发送 D(ESP) 失败（仍继续本地拆除）", "site", sa.SiteID, "err", err)
		}
	}
	e.detachChild(sa, c)
	if reason != "" {
		e.opt.Log.Info("ike: 拆除 Child SA", "site", sa.SiteID, "inSPI", c.InSPI, "outSPI", c.OutSPI, "原因", reason)
	}
}

// installChild 把协商结果推给 ESP 数据面。
//
// ★密钥方向在这里定型：本端是原始发起方 → 出向用 encr_i/integ_i、入向用 encr_r/integ_r；
// 响应方相反。与"本次 CREATE_CHILD_SA 是谁发起的"无关——永远看 IKE SA 的原始角色。
// 写反的症状是两端都建立成功、ESP 却一个包都解不开。
func (e *Engine) installChild(s *site, sa *IKESA, c *ChildSA, ck ChildKeys) error {
	espLocal, espPeer := sa.espEndpoints(e.opt.LocalNAT, s.cfg.PeerNATPort)
	p := ipsec.ChildSAParams{
		SiteID:   s.cfg.ID,
		InSPI:    c.InSPI,
		OutSPI:   c.OutSPI,
		EncrID:   c.Spec.EncrID,
		KeyBits:  c.Spec.KeyBits,
		IntegID:  c.Spec.IntegID,
		LocalTS:  s.cfg.LocalSubnet,
		RemoteTS: s.cfg.RemoteSubnet,
		// ★ESP 的落点与 IKE 的落点**必须分开算**：IKE 只在检测到 NAT 时才切到 4500，
		// 而 ESP 永远走 UDP 封装口。直接沿用 sa.Local/sa.Peer 的后果是「无 NAT 部署下
		// ESP 被发到对端 500 口后静默丢弃、隧道显示 up 却零流量」——详见 espEndpoints。
		Local:      espLocal,
		Peer:       espPeer,
		CreatedAt:  c.CreatedAt,
		HardExpire: c.HardExpire,
	}
	if sa.LocalIsInit {
		p.OutEncrKey, p.OutIntegKey = ck.EncrI, ck.IntegI
		p.InEncrKey, p.InIntegKey = ck.EncrR, ck.IntegR
	} else {
		p.OutEncrKey, p.OutIntegKey = ck.EncrR, ck.IntegR
		p.InEncrKey, p.InIntegKey = ck.EncrI, ck.IntegI
	}

	if e.opt.Protector != nil {
		if err := e.opt.Protector.Install(p); err != nil {
			return fmt.Errorf("ike: 装载 Child SA 到数据面失败（inSPI=%08x outSPI=%08x）: %w", c.InSPI, c.OutSPI, err)
		}
	}
	c.installed = true
	sa.children[c.InSPI] = c
	e.childSite[c.InSPI] = s.cfg.ID
	return nil
}

// ── 站点状态迁移 ──

// markEstablished 站点进入 up。
func (e *Engine) markEstablished(s *site, sa *IKESA, spec SuiteSpec, childSpec SuiteSpec) {
	now := e.now()
	sa.State = SAEstablished
	sa.lastSeen = now
	s.state = ipsec.StateUp
	s.establishedAt = now
	s.lastError = ""
	s.retryStep = 0
	s.retryAt = time.Time{}
	// 协商结果按**真实算法名**呈现（IKE 套件 + ESP 套件），不是 suite 标签。
	// 「配的是 A、谈出来 B」时能被一眼看出来，正是"真的在谈判"最直观的证据。
	s.negotiated = fmt.Sprintf("IKE:%s | ESP:%s", spec, childSpec)
	e.collapseDuplicates(s)
}

// failSite 记录一次失败并排下一次重连。
//
// ★LastError 必须是**可读中文 + 实际值**。把 NO_PROPOSAL_CHOSEN 这个码点直接甩给
// 管理员等于什么都没说；他要知道的是"对端提了什么、本端要什么"。
func (e *Engine) failSite(s *site, reason string) {
	now := e.now()
	s.state = ipsec.StateFailed
	s.lastError = reason
	s.lastErrorAt = now
	s.retryAt = now.Add(siteRetryDelay(s.retryStep, e.opt.Rand))
	if s.retryStep < 8 {
		s.retryStep++
	}
	e.opt.Log.Warn("ike: 站点协商失败", "site", s.cfg.ID, "原因", reason)
}

// collapseDuplicates 处理**同时发起**导致的两条 IKE SA。
//
// 双方都配了这条站点时，两端可能几乎同时发出 IKE_SA_INIT，各自又都尽责地响应了
// 对方——结果是两条完整可用的 IKE SA。RFC 7296 §2.8.1 给了一套 nonce 比大小的
// 收敛算法；这里用更简单也同样确定的判据：**比较 SPIi‖SPIr 的字节序，大的留下**。
//
// ★判据必须是两端算出来完全一样的东西，否则各留各的，隧道会在两条 SA 之间反复抖动。
// SPI 对两端是同一份数据，天然满足。被淘汰的一方由**它的原始发起方**发 D(IKE)，
// 避免两端同时发删除、互相把对方的确认当成新请求。
func (e *Engine) collapseDuplicates(s *site) {
	// 先选出赢家再统一淘汰其余的。
	//
	// ★不要写成"边遍历边两两比较、把败者当场拆掉"：那种写法里 `loser` 很容易被
	// 误置成当前的赢家（`loser := keep` 之后只在交换分支里改它），于是两端各拆各的，
	// 最后**两条 SA 全被拆光**。这个错误只在两端同时发起时出现，概率性复现，
	// 而现象是"隧道偶尔要过 30 秒才建起来"——极难归因。
	var keep *IKESA
	for _, sa := range s.sas {
		if sa.State != SAEstablished || sa.retiring {
			continue
		}
		if keep == nil || saOrder(sa) > saOrder(keep) {
			keep = sa
		}
	}
	if keep == nil {
		return
	}
	for _, sa := range s.sas {
		if sa == keep || sa.State != SAEstablished || sa.retiring {
			continue
		}
		e.opt.Log.Info("ike: 检测到两端同时发起造成的冗余 IKE SA，按 SPI 字典序收敛",
			"site", s.cfg.ID, "保留", spiHex(keep.SPIi)+"/"+spiHex(keep.SPIr),
			"淘汰", spiHex(sa.SPIi)+"/"+spiHex(sa.SPIr))
		// 只由**它的原始发起方**发 D(IKE)：两端同时发删除会让彼此把对方的
		// 删除请求当成新请求来回答，在实现不够严谨的对端上能刷成删除风暴。
		e.destroySA(sa, sa.LocalIsInit, "两端同时发起产生的冗余 IKE SA")
	}
}

// saOrder 给出 SPIi‖SPIr 的可比较视图。
func saOrder(sa *IKESA) string {
	var b [16]byte
	copy(b[:8], sa.SPIi[:])
	copy(b[8:], sa.SPIr[:])
	return string(b[:])
}

// ── 小工具 ──

func (e *Engine) now() time.Time { return e.opt.Now() }

// localIKEAddr 本端 500 落点；未配置时退回 Transport 报上来的地址。
func (e *Engine) localIKEAddr() netip.AddrPort { return e.opt.LocalIKE }

// samePrefixTS 判定收到的 TS 载荷是否与本地配置的网段**逐字节相等**。
//
// ★本轮不做 narrowing。理由不是省事：策略权威在控制面，网关侧自作主张收窄会造成
// 「控制台配了 /16、实际只通了 /24」这种无报错的假成功——与项目历史上最迷惑的
// `-route` 单网段事故同构。谈不拢就明确回 TS_UNACCEPTABLE，让管理员去改配置。
func samePrefixTS(got *TSPayload, want netip.Prefix, t PayloadType) bool {
	if got == nil {
		return false
	}
	exp := &TSPayload{T: t, Selectors: []TrafficSelector{TSFromPrefix(want)}}
	return got.Equal(exp)
}

// findTS 取指定类型的 TS 载荷。
func findTS(m *Message, t PayloadType) *TSPayload {
	if p := m.Find(t); p != nil {
		if ts, ok := p.(*TSPayload); ok {
			return ts
		}
	}
	return nil
}

// findSA 取 SA 载荷。
func findSAPayload(m *Message) *SAPayload {
	if p := m.Find(PayloadSA); p != nil {
		if sa, ok := p.(*SAPayload); ok {
			return sa
		}
	}
	return nil
}

// findKE 取 KE 载荷。
func findKE(m *Message) *KEPayload {
	if p := m.Find(PayloadKE); p != nil {
		if ke, ok := p.(*KEPayload); ok {
			return ke
		}
	}
	return nil
}

// findNonce 取 Nonce 载荷的值。
func findNonce(m *Message) []byte {
	if p := m.Find(PayloadNonce); p != nil {
		if n, ok := p.(*NoncePayload); ok {
			return n.Nonce
		}
	}
	return nil
}

// findID 取 IDi/IDr。
func findID(m *Message, t PayloadType) *IDPayload {
	if p := m.Find(t); p != nil {
		if id, ok := p.(*IDPayload); ok {
			return id
		}
	}
	return nil
}

// findAuth 取 AUTH 载荷。
func findAuth(m *Message) *AuthPayload {
	if p := m.Find(PayloadAUTH); p != nil {
		if a, ok := p.(*AuthPayload); ok {
			return a
		}
	}
	return nil
}

// idPayload 构造一个 FQDN 形态的身份载荷。
//
// ★固定用 ID_FQDN 而不是 ID_IPV4_ADDR：NAT 场景下对端看到的是 NAT 后地址，
// 用 IP 类型的身份必然匹配不上，而失败信息只有一句「认证失败」。
func idPayload(t PayloadType, value string) *IDPayload {
	return &IDPayload{T: t, IDType: IDFQDN, Data: []byte(value)}
}

// sameID 比对收到的身份与配置期望值。
func sameID(got *IDPayload, want string) bool {
	return got != nil && got.IDType == IDFQDN && bytes.Equal(got.Data, []byte(want))
}
