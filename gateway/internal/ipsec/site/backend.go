package site

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/esp"
)

// BackendOptions 组装一个 GoBackend 所需的全部零件。
//
// ★这些零件都由**调用方**（cmd/baidi-ipsec）创建并持有：本层不 new 任何一个，
// 也不负责关闭它们。理由是 Transport/Datapath 的生命周期跟进程绑，
// 而 Backend 在配置重载时可能被重建——让 Backend 关掉它没创建的 socket，
// 会得到一串没人能追溯来源的 "use of closed network connection"。
type BackendOptions struct {
	// GatewayID 本机的网关 id。Apply 时用它过滤"不归本机管"的站点。
	GatewayID string

	// Transport IKE 与 ESP 共用的 UDP 通道（生产用 ipsec.NewUDPTransport）。
	// 本层会在它上面架一个分流器（见 demux.go），把 IKE 支路交给状态机、
	// ESP 支路交给入向泵。
	Transport ipsec.Transport

	// Datapath 受保护流量的两端（生产用 TUN，测试用 pair/netstack）。
	Datapath ipsec.Datapath

	// IKE IKEv2 状态机。必填。
	IKE IKE

	// Protector ESP 数据面。必填，且**必须与传给 IKE 状态机的是同一个实例**——
	// 状态机协商完要往里 Install，泵要从里面 Protect/Unprotect。
	// 两个实例的后果是"握手全绿、一个包都不通"，而两边日志都正常。
	Protector ipsec.Protector

	Log *slog.Logger

	// Now 注入时钟。测试里推进时间不许靠 sleep（那种测试会随机红、
	// 久了就被 -short 跳过，等于没有）。
	Now func() time.Time

	// Extra 取一条站点的"控制面下发了但 SiteConfig 装不下"的开关
	// （ikeVersion / pqHybrid，见 ipsec.ExtraOptions）。
	// ★不接这个钩子的话，管理员在界面上选了 IKEv1、打开了 PQ 混合，
	// 网关会照常按 IKEv2 无 PQ 跑起来并显示 up——界面与实际彻底脱节且零报错。
	// 为 nil 表示调用方确认控制面没有这些字段。
	Extra func(siteID string) ipsec.ExtraOptions
}

// GoBackend 是 ipsec.Backend 的纯 Go 实现（本轮唯一的后端）。
//
// 它负责三件事，其余全部委托出去：
//   - 全量声明式对账（Apply）
//   - 起两条泵与一个分流器
//   - 把 IKE/ESP 的实测状态聚合成控制面要的 SiteState（States）
type GoBackend struct {
	gatewayID string
	tr        ipsec.Transport
	dp        ipsec.Datapath
	ike       IKE
	prot      ipsec.Protector
	log       *slog.Logger
	now       func() time.Time
	extra     func(string) ipsec.ExtraOptions

	dmx   *demux
	ikeTr ipsec.Transport // IKE 支路：交给状态机
	espTr ipsec.Transport // ESP 支路：入向泵自己读

	mu    sync.RWMutex
	sites map[string]*entry

	// noPolicy 引擎级的"出向包无匹配策略"计数。
	//
	// ★为什么单独放在这里：esp 引擎在出向匹配不到策略时**根本不知道该算到哪个站点头上**
	// （连目的地址属于谁都还没确定），所以它只有引擎级计数；而 ipsec.SiteState 里
	// 没有承载丢弃计数的字段。于是它既进不了站点状态、也进不了控制台——
	// 只能靠这里的访问器 + 递减频率日志把它露出来。
	// 这是本轮已知的一处契约缺口，见本文件 NoPolicyDrops 的说明。
	noPolicy  atomic.Uint64
	protErrTh throttle

	pumps  sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	closed sync.Once
}

// 编译期确认实现了契约。
var _ ipsec.Backend = (*GoBackend)(nil)

// NewBackend 组装并**立即启动**分流器与两条泵。
//
// 泵先起、站点后加是有意的：Apply 里 AddSite 一旦成功，握手随时可能完成并装载
// Child SA，此刻若泵还没起来，最初的若干业务包会被静默丢弃——那种"刚建好时丢几个包"
// 的现象几乎没人会去查。
func NewBackend(opt BackendOptions) (*GoBackend, error) {
	if strings.TrimSpace(opt.GatewayID) == "" {
		return nil, errors.New("site: 必须指定 GatewayID（否则无法判断哪些站点归本机管，多网关下会两台抢建同一条 SA）")
	}
	if opt.Transport == nil {
		return nil, errors.New("site: 必须提供 Transport（IKE 与 ESP 共用的 UDP 通道）")
	}
	if opt.Datapath == nil {
		return nil, errors.New("site: 必须提供 Datapath（受保护流量的出入口）")
	}
	if opt.IKE == nil {
		return nil, errors.New("site: 必须提供 IKE 状态机实例")
	}
	if opt.Protector == nil {
		return nil, errors.New("site: 必须提供 Protector（且须与 IKE 状态机用的是同一个实例，否则握手成功但一个包都不通）")
	}
	log := opt.Log
	if log == nil {
		log = slog.Default()
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}

	ctx, cancel := context.WithCancel(context.Background())
	b := &GoBackend{
		gatewayID: opt.GatewayID,
		tr:        opt.Transport,
		dp:        opt.Datapath,
		ike:       opt.IKE,
		prot:      opt.Protector,
		log:       log,
		now:       now,
		extra:     opt.Extra,
		sites:     make(map[string]*entry),
		ctx:       ctx,
		cancel:    cancel,
	}
	b.dmx = newDemux(opt.Transport, log)
	b.ikeTr = b.dmx.ikeSide()
	b.espTr = b.dmx.espSide()

	b.pumps.Add(2)
	go b.pumpOutbound(ctx)
	go b.pumpInbound(ctx)
	return b, nil
}

// IKETransport 是 IKE 状态机应当使用的那条支路。
//
// ★组装顺序上的坑：状态机必须收这条支路而不是原始 Transport。
// 收原始 Transport 的话，它会和入向泵抢同一个队列，两边各吞掉对方一部分报文——
// 表现为「握手偶尔卡住、流量偶尔丢包」，比例随负载变化，低负载下几乎不复现。
func (b *GoBackend) IKETransport() ipsec.Transport { return b.ikeTr }

// Run 跑 IKE 状态机的事件循环，阻塞到 ctx 结束。
// 泵在 NewBackend 里已经起了，不在这里。
func (b *GoBackend) Run(ctx context.Context) error { return b.ike.Run(ctx) }

// Apply 全量声明式对账：把本机的实际站点集合收敛到 sites 描述的目标状态。
//
// 返回 error 只代表**整批**没法处理（目前不存在这种情况）；
// ★单条站点的拒绝一律落到那条站点的 SiteState.LastError，不往上抛。
// 理由：把单站点错误抛成整批失败，会让同步循环反复重试整批，
// 而管理员在界面上看到的仍然只是"没反应"——错误必须落到它归属的那一行才有用。
func (b *GoBackend) Apply(_ context.Context, sites []ipsec.SiteConfig) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	desired := make(map[string]*entry, len(sites))
	for i := range sites {
		// 值拷贝：Validate 会**就地补齐缺省值**，不能改到调用方的切片。
		cfg := sites[i]

		// 归属过滤：明确指派给别的网关的站点整条忽略，连状态都不回报——
		// 回报会与真正负责的那台网关在同一行里互相覆盖。
		// （GatewayID 为空的情况刻意不在这里过滤，留给 Validate 当面拒绝，
		//  否则一条无主站点会被所有网关静默跳过，界面上永远没有任何解释。）
		if id := strings.TrimSpace(cfg.GatewayID); id != "" && id != b.gatewayID {
			continue
		}

		key := strings.TrimSpace(cfg.ID)
		e := &entry{cfg: cfg}
		if prev, dup := desired[key]; dup {
			// 同一批里出现两条同 id 的站点：控制面数据坏了。保留先到的那条，
			// 并把冲突写进它的状态——静默取后者会让"改了配置没生效"变成玄学。
			prev.rejectErr = fmt.Errorf("控制面下发了两条 id 相同的站点（%q），已保留先到的一条并忽略后者；请检查控制面数据", key)
			continue
		}

		var x ipsec.ExtraOptions
		if b.extra != nil {
			x = b.extra(key)
		}
		if err := e.cfg.ValidateWith(x); err != nil {
			e.rejectErr = err
		} else {
			e.fp = fingerprint(e.cfg)
			if e.cfg.WeakPSK() {
				// 不拒绝，但必须说出来：IKEv2 的 PSK 可离线爆破，短口令的实际强度
				// 远低于直觉。降级要看得见。
				b.log.Warn("站点 PSK 过短（可离线爆破，建议 ≥20 字节随机值）",
					"站点", key, "长度", len(e.cfg.PSK))
			}
		}
		desired[key] = e
	}

	// ── 第一趟：拆掉不该再跑的 ──
	for id, old := range b.sites {
		nw, keep := desired[id]
		var reason string
		switch {
		case !keep:
			reason = "已从控制面移除或改派给其它网关"
		case nw.rejectErr != nil:
			reason = "配置校验未通过：" + nw.rejectErr.Error()
		case !nw.cfg.Enabled:
			reason = "管理员已停用（enabled=false）"
		case nw.fp != old.fp:
			reason = fmt.Sprintf("配置已变更（%s → %s），需要重建 SA", shortFP(old.fp), shortFP(nw.fp))
		default:
			// 完全没变：什么都不做。
			// ★这一条是本函数最重要的分支。同步循环 15 秒一轮，若每轮都重建 SA，
			// 隧道会永远停在握手中、业务永远不通，而每一轮的日志都显示"正在协商"。
			nw.inEngine, nw.addedAt = old.inEngine, old.addedAt
			continue
		}
		b.teardown(id, reason)
	}

	// ── 第二趟：装上该跑的 ──
	for id, e := range desired {
		switch {
		case e.rejectErr != nil:
			continue // 保持 failed，原因已在 rejectErr 里
		case !e.cfg.Enabled:
			continue // 管理意图就是不跑，状态 down（不是故障）
		case e.inEngine:
			continue // 上一轮就在跑且配置没变
		}
		if err := b.ike.AddSite(e.cfg); err != nil {
			// 状态机侧的装载期拒绝（最典型的是 ike.SpecFromPhase 不认识的算法名）。
			// 原样留在这条站点上，让管理员在界面看到"phase1.dh=group24 本实现不支持"。
			e.rejectErr = err
			b.log.Warn("站点装载被拒绝", "站点", id, "原因", err.Error())
			continue
		}
		e.inEngine = true
		e.addedAt = b.now()
		b.log.Info("站点已装载，开始协商",
			"站点", id, "对端", e.cfg.Peer.String(),
			"本端网段", e.cfg.LocalSubnet.String(), "对端网段", e.cfg.RemoteSubnet.String(),
			"套件", e.cfg.Suite, "配置指纹", shortFP(e.fp))
	}

	b.sites = desired
	return nil
}

// teardown 拆一条站点：先让状态机发 Delete 并拆 IKE 侧，再清掉 ESP 侧残留的 SA。
//
// ★两步都要做。只拆 IKE 不清 ESP，会留下一条"控制面已停用、数据面还在收发"的隧道：
// 界面显示 down、流量照常通过——这是最坏的一种不一致，也是 e2e 里
// 「toggle enabled=false 后业务必须打不通」那条反例断言守着的东西。
func (b *GoBackend) teardown(id, reason string) {
	if err := b.ike.RemoveSite(id); err != nil {
		// 拆不掉也要继续清 ESP：宁可多拆，不可留残。
		b.log.Warn("拆除站点时状态机报错（继续清理 ESP 侧）", "站点", id, "err", err.Error())
	}
	if sr, ok := b.prot.(siteRemover); ok {
		if n := sr.RemoveSite(id); n > 0 {
			b.log.Info("已拆除该站点的 Child SA", "站点", id, "SA 条数", n)
		}
	} else {
		b.log.Warn("当前 Protector 不支持按站点批量拆除 SA，"+
			"停用站点后可能残留可收发的 SA（界面显示 down 但流量仍通）", "站点", id)
	}
	b.log.Info("站点已拆除", "站点", id, "原因", reason)
}

// States 聚合各站点的运行态。输出按站点 id 排序（稳定顺序让界面不跳、让测试可断言）。
func (b *GoBackend) States(_ context.Context) ([]ipsec.SiteState, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// 状态机的实测状态按 id 建索引。
	live := make(map[string]ipsec.SiteState)
	for _, st := range b.ike.States() {
		live[st.SiteID] = st
	}
	stats, hasStats := b.prot.(espStats)
	now := b.now().Unix()

	ids := make([]string, 0, len(b.sites))
	for id := range b.sites {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]ipsec.SiteState, 0, len(ids))
	for _, id := range ids {
		e := b.sites[id]
		st := b.stateOf(id, e, live)
		st.SiteID = id
		st.GatewayID = b.gatewayID
		st.ReportedAt = now

		if hasStats {
			// ★流量数字**只允许**来自 ESP 的实测计数（types.go 的 Counters 注释写死了这条）。
			// 无条件覆盖而不是"为空才取"：任何一条从别处来的数字，都是在给
			// 「toggle 一下界面就显示有流量」留后路。
			st.Counters = stats.SiteCounters(id)
			if st.LastError == "" {
				st.LastError = dropHint(stats.SiteDrops(id))
			}
		}
		out = append(out, st)
	}

	// 状态机报了、但本层不认识的站点：不能丢。它意味着某次拆除没拆干净，
	// 而"悄悄不显示"会让这条泄漏永远不被发现。
	for id, st := range live {
		if _, known := b.sites[id]; known {
			continue
		}
		st.SiteID = id
		st.GatewayID = b.gatewayID
		st.ReportedAt = now
		st.LastError = "该站点已不在控制面下发的清单中，但状态机里仍有残留（拆除未完成）：" + st.LastError
		out = append(out, st)
	}
	return out, nil
}

// stateOf 决定一条站点该报什么状态。
//
// 五态的分界线是本函数存在的全部意义：
//   - failed  ：启用了但跑不起来（配置被拒 / 协商失败）——**有原因可看**
//   - down    ：管理员就没打算让它跑（enabled=false）——不是故障
//   - 其余    ：交给状态机的实测结果（connecting / up / rekeying）
//
// ★把 failed 和 down 混成一个"未连接"，正是"接了真状态、用户仍然不知道为什么连不上"
// 的结局。这两者对管理员意味着完全不同的下一步动作。
func (b *GoBackend) stateOf(id string, e *entry, live map[string]ipsec.SiteState) ipsec.SiteState {
	if e.rejectErr != nil {
		return ipsec.SiteState{
			State:       ipsec.StateFailed,
			LastError:   e.rejectErr.Error(),
			LastErrorAt: b.now().Unix(),
		}
	}
	if !e.cfg.Enabled {
		return ipsec.SiteState{State: ipsec.StateDown}
	}
	if st, ok := live[id]; ok {
		return st
	}
	// 已交给状态机但它还没报出任何状态：刚 AddSite 完的正常空窗。
	return ipsec.SiteState{
		State:     ipsec.StateConnecting,
		LastError: "已装载，等待状态机开始协商",
	}
}

// dropHint 把该站点的实测丢弃计数拼成一句可读的补充说明。
//
// 只在没有更具体的错误时才用它填 LastError：这些计数说明的是
// 「隧道在跑，但有一部分包被扔了」，而排障时最需要知道的恰恰是扔的原因分布——
// 认证失败是密钥/对端问题，内层越权是对端在往隧道里塞不该塞的地址，
// 两者的下一步动作完全不同。
func dropHint(d esp.Drops) string {
	var parts []string
	add := func(n uint64, what string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", what, n))
		}
	}
	add(d.Auth, "完整性校验失败")
	add(d.TSMismatch, "内层地址越出流量选择器（对端越权）")
	add(d.Replay, "重放/窗口外陈旧报文")
	add(d.NoSA, "未知 SPI（对端仍在用已拆除的 SA）")
	add(d.Oversize, "内层包超长（隧道 MTU 偏大）")
	add(d.SeqExhausted, "出向序号耗尽（等待重协商）")
	add(d.Malformed, "报文结构非法")
	if len(parts) == 0 {
		return ""
	}
	return "实测丢弃：" + strings.Join(parts, "、")
}

// NoPolicyDrops 引擎级"出向包无匹配策略"的累计丢弃数。
//
// ★这个访问器存在，是因为 ipsec.SiteState 里没有地方放它（契约层已冻结），
// 而 esp 引擎在出向匹配不到策略时也确实不知道该算到哪个站点头上。
// 它是「流量本该进隧道却没走隧道」的唯一可见信号，埋在日志里等于没有——
// 守护进程务必把它上报或至少暴露到 /metrics 之类的地方。
func (b *GoBackend) NoPolicyDrops() uint64 { return b.noPolicy.Load() }

// TransportStats 分流器的三个计数：IKE 支路丢弃、ESP 支路丢弃、收到的 NAT keepalive。
// dropIKE 非零意味着状态机的事件循环卡住过，属必须追查的严重信号。
func (b *GoBackend) TransportStats() (dropIKE, dropESP, keepalives uint64) { return b.dmx.stats() }

// Close 停掉两条泵与分流器。**不关闭** Transport / Datapath / IKE / Protector——
// 那些都不是本层创建的（见 BackendOptions 的说明）。
//
// ★这里刻意**不无限等待**两条泵退出。原因是出向泵此刻多半正阻塞在
// Datapath.ReadOutbound 上，而那个调用只有数据面被它的持有者关闭时才会返回。
// 早期版本在这里写了 pumps.Wait()，结果是「Close 永远不返回」——
// 而它表现出来的样子是"进程停不下来"，没人会想到根因在一个 WaitGroup 上。
// 因此改成有界等待：等不到就打一条明确的日志，把"谁还没退出、为什么"说清楚。
func (b *GoBackend) Close() error {
	b.closed.Do(func() {
		b.cancel()
		b.dmx.stop()

		done := make(chan struct{})
		go func() { b.pumps.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(300 * time.Millisecond):
			// 只给一个短暂的宽限：入向泵会立刻退出（它阻塞在已停止的分流支路上），
			// 出向泵则要等数据面的持有者关闭数据面。等更久换不来任何确定性。
			b.log.Info("泵尚未退出（出向泵通常阻塞在 Datapath.ReadOutbound 上，" +
				"需由数据面的持有者关闭它才会返回）：Backend 已停止对账与投递，不再等待")
		}
	})
	return nil
}
