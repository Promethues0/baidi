package esp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// Engine 是 ipsec.Protector 的唯一实现：持有全部已装载的 Child SA，逐包封装与解封。
//
// 并发模型：
//   - SA 表用 RWMutex 保护，收发包只取读锁（两条泵是两个 goroutine，几乎不互相阻塞）；
//   - 每条 SA 的出向序号与入向反重放窗口用该 SA 自己的小锁串行化；
//   - 计数器全部是原子量，状态上报每 15s 全量读一次，不与收发包抢锁。
var _ ipsec.Protector = (*Engine)(nil)

type Engine struct {
	log *slog.Logger
	now func() time.Time

	mu      sync.RWMutex
	byInSPI map[uint32]*sa
	// policyDesc 当前策略摘要，**只在 SA 表变化时重算**。
	// 它是「无匹配策略」错误文案里最有用的一半（把「你的包」和「现有策略」并排摆出来），
	// 但每包重算一次就成了负担——SA 表几小时才变一次，缓存是显然的。
	policyDesc string
	// retired 已拆除 SA 的累计量，按站点归档。
	//
	// ★不归档的后果：每次 rekey（默认 1 小时一次）站点的流量与丢包计数都会归零，
	// 控制台上看到的永远是「最近这一小时」，而「这条隧道一直在少量丢包」这种
	// 需要横跨多个 SA 才看得出来的问题就永远看不见了。
	retired map[string]siteTotals

	// 尚未定位到具体 SA 时发生的丢弃，只能记在引擎级。
	dropNoPolicy  atomic.Uint64
	dropNoSA      atomic.Uint64
	dropOversize  atomic.Uint64
	dropMalformed atomic.Uint64
}

// siteTotals 一个站点的历史累计量（来自已被拆除的 SA）。
type siteTotals struct {
	counters ipsec.Counters
	drops    Drops
}

// New 建一个 ESP 引擎。
//
// log 为 nil 时丢弃全部日志（单测里最常见的用法）；
// now 为 nil 时用 time.Now。★now 可注入是硬要求：生存期与 rekey 判定若靠真实时钟，
// 相关测试就只能靠 sleep，慢且随机红绿，最后必然被 -short 跳过，等于没有测试。
func New(log *slog.Logger, now func() time.Time) *Engine {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return &Engine{
		log:     log,
		now:     now,
		byInSPI: make(map[uint32]*sa),
		retired: make(map[string]siteTotals),
	}
}

// Install 装载一条 Child SA（出向 + 入向）。同 InSPI 重复装载视为替换。
func (e *Engine) Install(p ipsec.ChildSAParams) error {
	s, err := newSA(p, e.now)
	if err != nil {
		return err
	}

	e.mu.Lock()
	old := e.byInSPI[s.inSPI]
	if old != nil {
		// SPI 是 32 位随机值，撞车概率约 2e-10，所以这条路径几乎只可能是逻辑错误
		// （同一个 ChildSAParams 被装了两次）。替换本身是接口约定的行为，但必须出声：
		// 替换会连带重置反重放窗口，若旧 SA 还在收包，那个窗口被清零等于短暂地
		// 重新接受了它已经拒过的重放包。
		e.foldRetired(old)
		e.log.Warn("esp: 入向 SPI 重复装载，旧 SA 被替换（反重放窗口已重置）",
			"inSpi", fmt.Sprintf("0x%08x", s.inSPI), "旧站点", old.siteID, "新站点", s.siteID)
	}
	e.byInSPI[s.inSPI] = s
	e.policyDesc = describeTable(e.byInSPI)
	n := len(e.byInSPI)
	e.mu.Unlock()

	e.log.Info("esp: 装载 Child SA",
		"站点", s.siteID,
		"入向SPI", fmt.Sprintf("0x%08x", s.inSPI),
		"出向SPI", fmt.Sprintf("0x%08x", s.outSPI),
		"本端网段", s.localTS.String(),
		"对端网段", s.remoteTS.String(),
		"对端落点", s.peer.String(),
		"加密算法", p.EncrID, "密钥位数", p.KeyBits, "完整性算法", p.IntegID,
		"在装SA数", n)
	return nil
}

// Remove 按入向 SPI 拆除一条 SA。
//
// ★rekey 时不要立刻拆旧的入向 SA：对端在途的报文还会用旧 SPI 到达，
// 立刻拆掉的表现是「每次重协商掉几个包」——量很小，但足以让 TCP 卡顿，
// 而且因为「隧道一直是 up」而极难与网络抖动区分。正确节奏由 ike 的 rekey 逻辑掌握
// （收到对端 Delete 或延迟若干秒后再调本方法）。
func (e *Engine) Remove(inSPI uint32) error {
	e.mu.Lock()
	s := e.byInSPI[inSPI]
	if s == nil {
		e.mu.Unlock()
		return fmt.Errorf("esp: 拆除失败，入向 SPI 0x%08x 未装载: %w", inSPI, ipsec.ErrNoSA)
	}
	delete(e.byInSPI, inSPI)
	e.foldRetired(s)
	e.policyDesc = describeTable(e.byInSPI)
	e.mu.Unlock()

	e.log.Info("esp: 拆除 Child SA", "站点", s.siteID,
		"入向SPI", fmt.Sprintf("0x%08x", inSPI), "出向SPI", fmt.Sprintf("0x%08x", s.outSPI))
	return nil
}

// RemoveSite 拆除某站点下的全部 SA，返回实际拆掉的条数。
// 站点被禁用或整条隧道判死时用它，省得调用方自己去枚举 SPI。
func (e *Engine) RemoveSite(siteID string) int {
	e.mu.Lock()
	n := 0
	for spi, s := range e.byInSPI {
		if s.siteID == siteID {
			delete(e.byInSPI, spi)
			e.foldRetired(s)
			n++
		}
	}
	if n > 0 {
		e.policyDesc = describeTable(e.byInSPI)
	}
	e.mu.Unlock()
	if n > 0 {
		e.log.Info("esp: 按站点拆除 Child SA", "站点", siteID, "条数", n)
	}
	return n
}

// foldRetired 把一条即将消失的 SA 的计数并入站点历史累计。调用方须持写锁。
func (e *Engine) foldRetired(s *sa) {
	t := e.retired[s.siteID]
	c := s.counters()
	t.counters.RxBytes += c.RxBytes
	t.counters.TxBytes += c.TxBytes
	t.counters.PacketsIn += c.PacketsIn
	t.counters.PacketsOut += c.PacketsOut
	t.drops.add(s.drops())
	e.retired[s.siteID] = t
}

// Counters 回读某条 SA 的实测计数。SA 不存在时返回零值——
// 调用方通常是在轮询上报，为一条刚被拆掉的 SA 报错没有意义。
func (e *Engine) Counters(inSPI uint32) ipsec.Counters {
	e.mu.RLock()
	s := e.byInSPI[inSPI]
	e.mu.RUnlock()
	if s == nil {
		return ipsec.Counters{}
	}
	return s.counters()
}

// SiteCounters 汇总某站点的实测计数，**跨 rekey 世代累加**（含已拆除的 SA）。
// ipsec.SiteState 里的流量数字应当来自这里，而不是某一条 SA 的瞬时值。
func (e *Engine) SiteCounters(siteID string) ipsec.Counters {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c := e.retired[siteID].counters
	for _, s := range e.byInSPI {
		if s.siteID != siteID {
			continue
		}
		x := s.counters()
		c.RxBytes += x.RxBytes
		c.TxBytes += x.TxBytes
		c.PacketsIn += x.PacketsIn
		c.PacketsOut += x.PacketsOut
	}
	return c
}

// SiteDrops 汇总某站点的丢弃计数，同样跨 rekey 世代累加。
//
// 注意 NoPolicy 不在这里：出向匹配不到策略时根本还不知道该算到哪个站点头上，
// 那一类只出现在 Engine.Drops() 的全局值里。
func (e *Engine) SiteDrops(siteID string) Drops {
	e.mu.RLock()
	defer e.mu.RUnlock()
	d := e.retired[siteID].drops
	for _, s := range e.byInSPI {
		if s.siteID == siteID {
			d.add(s.drops())
		}
	}
	return d
}

// Drops 全局丢弃计数（引擎级 + 在装 SA + 已拆除 SA）。
func (e *Engine) Drops() Drops {
	d := Drops{
		NoPolicy:  e.dropNoPolicy.Load(),
		NoSA:      e.dropNoSA.Load(),
		Oversize:  e.dropOversize.Load(),
		Malformed: e.dropMalformed.Load(),
	}
	e.mu.RLock()
	for _, t := range e.retired {
		d.add(t.drops)
	}
	for _, s := range e.byInSPI {
		d.add(s.drops())
	}
	e.mu.RUnlock()
	return d
}

// SeqOf 回读某条 SA 的出向最大序号与已认证接收的最大序号。
// rekey 的序号阈值判定与测试用它；SA 不存在返回 (0,0)。
func (e *Engine) SeqOf(inSPI uint32) (out, highestIn uint64) {
	e.mu.RLock()
	s := e.byInSPI[inSPI]
	e.mu.RUnlock()
	if s == nil {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outSeq, s.replay.highest
}

// Info 某条 SA 的运行态快照。
func (e *Engine) Info(inSPI uint32) (SAInfo, bool) {
	e.mu.RLock()
	s := e.byInSPI[inSPI]
	e.mu.RUnlock()
	if s == nil {
		return SAInfo{}, false
	}
	return s.info(e.now()), true
}

// List 全部在装 SA 的快照，按入向 SPI 升序（稳定输出便于 diff 两次采样）。
func (e *Engine) List() []SAInfo {
	now := e.now()
	e.mu.RLock()
	out := make([]SAInfo, 0, len(e.byInSPI))
	for _, s := range e.byInSPI {
		out = append(out, s.info(now))
	}
	e.mu.RUnlock()
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].InSPI > out[j].InSPI; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Protect 把一个出向明文 IP 包封装成 ESP 报文，并给出该发往哪个 UDP 落点。
//
// ★匹配不到策略时返回 ipsec.ErrNoPolicy，调用方**必须丢弃**，绝不允许原样明文发出。
// 「隧道建起来了、流量却没走隧道且全程无报错」是本项目历史上最迷惑人的失败形态。
func (e *Engine) Protect(ipPkt []byte) ([]byte, netip.AddrPort, error) {
	if len(ipPkt) > MaxInnerPacket {
		e.dropOversize.Add(1)
		// 丢弃而不是截断：截断出去的包在对端是一个校验和正确、内容却被腰斩的 IP 包，
		// 症状是「ping 通、HTTP 卡住」，属最难定位的一类。
		return nil, netip.AddrPort{}, fmt.Errorf("esp: 内层包 %d 字节超过上限 %d，已丢弃（本实现不做分片也不做 PMTUD，请调小隧道 MTU）: %w",
			len(ipPkt), MaxInnerPacket, ErrOversize)
	}
	src, dst, nh, err := innerAddrs(ipPkt)
	if err != nil {
		e.dropMalformed.Add(1)
		return nil, netip.AddrPort{}, err
	}

	now := e.now()
	e.mu.RLock()
	s, err := selectOutbound(e.byInSPI, e.policyDesc, src, dst, now)
	e.mu.RUnlock()
	if err != nil {
		e.dropNoPolicy.Add(1)
		// ★这条日志只能是 Debug，而且要先问一句 Enabled。出向无策略在「隧道刚断」时
		// 会以线速刷屏：用 Warn 打是给自己造日志 DoS；不问 Enabled 就把参数拼出来，
		// 则等于把 noPolicyError 的惰性格式化白白浪费掉。
		if e.log.Enabled(context.Background(), slog.LevelDebug) {
			e.log.Debug("esp: 出向包无匹配策略，已丢弃", "源", src.String(), "目的", dst.String(), "原因", err.Error())
		}
		return nil, netip.AddrPort{}, err
	}

	seq, err := s.nextSeq()
	if err != nil {
		s.dropSeqExhaust.Add(1)
		return nil, netip.AddrPort{}, err
	}
	pkt, err := s.out.encap(s.outSPI, seq, ipPkt, nh)
	if err != nil {
		s.dropMalformed.Add(1)
		return nil, netip.AddrPort{}, fmt.Errorf("esp: 站点 %s 出向封装失败: %w", s.siteID, err)
	}

	// 计的是 ESP 线上字节（含头/IV/补齐/ICV），不是内层明文长度——见 doc.go 的计数口径。
	s.txBytes.Add(uint64(len(pkt)))
	s.packetsOut.Add(1)
	return pkt, s.peer, nil
}

// Unprotect 解封一个入向 ESP 报文。
//
// 顺序是安全性的一部分，逐步都不能挪：
//
//	①取 SPI/序号 → ②查 SA → ③反重放**预检**（不改窗口）→ ④验 ICV/解密
//	→ ⑤反重放**推窗**（只有认证通过的包才配推窗）→ ⑥内层 TS 校验 → ⑦计数
//
// ★③与⑤拆开是关键。若在验 ICV 之前就推窗，攻击者只要发一个序号极大的垃圾包
// 就能把窗口推到远处，之后所有**合法**报文都落在窗口左侧被丢——
// 一个不需要任何密钥的单包 DoS，现象是「隧道 up，就是不通」。
func (e *Engine) Unprotect(espPkt []byte, from netip.AddrPort) ([]byte, error) {
	spi, seq, err := parseHeader(espPkt)
	if err != nil {
		e.dropMalformed.Add(1)
		return nil, err
	}

	e.mu.RLock()
	s := e.byInSPI[spi]
	e.mu.RUnlock()
	if s == nil {
		e.dropNoSA.Add(1)
		// 这在 rekey 后的短窗口里是正常现象（对端还在用刚被拆掉的 SPI），
		// 持续出现才说明对端与本端对 SA 的认知已经分叉。
		return nil, fmt.Errorf("esp: 来自 %s 的报文 SPI 0x%08x 没有对应的入向 SA（可能是刚被拆除的旧 SA，或对端在扫描）: %w",
			from, spi, ipsec.ErrNoSA)
	}

	// ③预检：廉价地挡掉重放洪水，省下 AES/HMAC 的开销。不改窗口。
	s.mu.Lock()
	err = s.replay.check(seq)
	s.mu.Unlock()
	if err != nil {
		s.dropReplay.Add(1)
		return nil, err
	}

	// ④验 ICV 并解密。
	inner, nh, err := s.in.decap(espPkt)
	if err != nil {
		if errors.Is(err, ipsec.ErrAuth) {
			s.dropAuth.Add(1)
		} else {
			s.dropMalformed.Add(1)
		}
		return nil, fmt.Errorf("esp: 站点 %s（SPI 0x%08x，序号 %d）解封失败: %w", s.siteID, spi, seq, err)
	}

	// ⑤推窗：到这一步才证明报文确实来自持密钥的对端。
	s.mu.Lock()
	err = s.replay.advance(seq)
	if err == nil {
		// 顺带记录对端实测地址。**只记录不采纳**：改用实测地址发包等于自己实现了半个
		// MOBIKE，而本轮不做——一旦对端地址被伪造的包带偏，隧道会单向不通且极难察觉。
		// 对端地址的权威来源始终是 IKE 协商结果。
		s.lastFrom = from
	}
	s.mu.Unlock()
	if err != nil {
		s.dropReplay.Add(1)
		return nil, err
	}

	// ⑥内层 TS 校验。
	if nh != protoIPv4 && nh != protoIPv6 {
		s.dropMalformed.Add(1)
		return nil, fmt.Errorf("esp: 站点 %s 收到 NextHeader=%d 的报文，隧道模式只接受 4(IPv4) 与 41(IPv6)"+
			"（59 是 TFC 哑包，本实现不发也不收）", s.siteID, nh)
	}
	src, dst, actual, err := innerAddrs(inner)
	if err != nil {
		s.dropMalformed.Add(1)
		return nil, fmt.Errorf("esp: 站点 %s 解出的内层包无法解析: %w", s.siteID, err)
	}
	if err := checkVersion(nh, actual); err != nil {
		s.dropMalformed.Add(1)
		return nil, fmt.Errorf("esp: 站点 %s: %w", s.siteID, err)
	}
	if err := checkInnerTS(s, src, dst); err != nil {
		s.dropTS.Add(1)
		// 这一条与出向无策略不同：它极少发生，一旦发生就值得当安全事件看，
		// 因此用 Warn。频率天然受限（对端得先通过 ICV 才走得到这里）。
		e.log.Warn("esp: 入向报文越出流量选择器，已丢弃",
			"站点", s.siteID, "源", src.String(), "目的", dst.String(), "对端", from.String())
		return nil, err
	}

	s.rxBytes.Add(uint64(len(espPkt)))
	s.packetsIn.Add(1)
	return inner, nil
}
