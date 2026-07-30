package esp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"baidi.dev/gateway/internal/ipsec"
)

// SPI 与序号的边界值。
const (
	// SPIMin ESP SPI 的最小可用值。两条理由叠加：
	//   ①RFC 4303 §2.1 把 0 与 1..255 划为保留；
	//   ②UDP-4500 封装下（RFC 3948）收到的报文要靠首字节自解释地三分流——
	//     4 字节全零 = non-ESP marker（其后是 IKE），单字节 0xFF = NAT keepalive，
	//     否则首 4 字节就是 ESP 的 SPI。SPI 若可能取 0，IKE 报文与 ESP 报文就分不开了。
	// ★分配时漏掉这条的症状：极低概率（约 6e-8）下某条隧道建起来后 IKE 完全失灵，
	// 重启即好，几乎不可能复现，也几乎不可能被想到。
	SPIMin uint32 = 256

	// MaxSeq 32 位序号上限。本实现不做 ESN（扩展序号），到顶即拒发。
	MaxSeq uint64 = 0xFFFFFFFF

	// SoftSeqLimit 触发重协商的序号软阈值（2³¹，即容量的一半）。
	// 留一半余量是为了让 rekey 有充足时间完成——等到 MaxSeq 才开始谈，
	// 谈判期间的包全都发不出去，表现为「隧道每隔很久卡死几秒」。
	SoftSeqLimit uint64 = 1 << 31

	// SoftBytesLimit 触发重协商的字节软阈值（32 GiB）。
	//
	// 取值依据是 AES-GCM 的安全数据量上限（约 2³⁹ bit ≈ 64 GiB/密钥，
	// 超过后认证标签的碰撞概率不再可忽略），取其一半留出重协商窗口。
	// 序号阈值管「包很多但都很小」，字节阈值管「包不多但都很大」，两条缺一不可。
	SoftBytesLimit uint64 = 32 << 30

	// softLifetimeRatio 硬生存期的多少比例处触发软到期。
	// 抖动（避免两端同时发起 rekey 而互撞 TEMPORARY_FAILURE）属于 IKE 层职责，
	// 本包只给一个确定值——数据面里塞随机数会让 rekey 相关的测试无法复现。
	softLifetimeRatio = 0.9
)

// ErrSeqExhausted 出向序号用尽。
//
// ★这是一个**必须拒发**而不是回绕的错误。回绕在 GCM 下等于 nonce 复用
// （本实现的显式 IV 就是序号），可同时恢复明文与认证密钥，且全程零报错；
// 在 CBC+HMAC 下则让反重放窗口彻底失效。宁可这条隧道停摆并在界面上报错，
// 也不能让它「看起来还在通」。
var ErrSeqExhausted = errors.New("esp: 出向序号已用尽，必须重协商")

// ErrOversize 内层包超过本实现允许的最大长度。
var ErrOversize = errors.New("esp: 内层包超长")

// MaxInnerPacket 内层 IP 包的长度上限（字节）。
//
// 这是一道**理智检查**而非 MTU 策略：真正的隧道 MTU 由数据面（TUN 的 MTU 设置）
// 决定，本包无从得知路径 MTU。取 9000 是为了容下巨帧场景又能挡住明显的荒谬输入。
// 超长包**丢弃并计数**，绝不截断——截断的症状是「能 ping 通、HTTP 卡住」。
const MaxInnerPacket = 9000

// Drops 丢弃计数。
//
// ★NoPolicy 是这里最该被盯着的一个：它意味着「有流量本该进隧道，却没有任何 SA 收它」。
// 本项目历史上最迷惑人的失败形态就是这条计数没有暴露出来——隧道显示已建立、
// 流量却从旁路直连出去了、全程零报错（见 CLAUDE.md 里 `baidi-tun -route` 那条）。
// 因此它必须逐条上报到控制面并在界面上可见，而不是只写进日志。
type Drops struct {
	NoPolicy     uint64 `json:"noPolicy"`     // 出向：没有匹配的 SPD 策略（最危险）
	NoSA         uint64 `json:"noSa"`         // 入向：SPI 查不到 SA（对端用了已拆除的 SA，或扫描）
	Auth         uint64 `json:"auth"`         // 入向：ICV/GCM 认证失败（密钥不符或报文被改）
	Replay       uint64 `json:"replay"`       // 入向：重放或窗口外陈旧报文
	TSMismatch   uint64 `json:"tsMismatch"`   // 入向：内层地址越出流量选择器（对端越权）
	Malformed    uint64 `json:"malformed"`    // 两向：报文结构非法
	Oversize     uint64 `json:"oversize"`     // 出向：内层包超长
	SeqExhausted uint64 `json:"seqExhausted"` // 出向：序号用尽，等待 rekey
}

// add 逐字段相加，用于把各 SA 的丢弃数聚合成站点级/全局值。
func (d *Drops) add(o Drops) {
	d.NoPolicy += o.NoPolicy
	d.NoSA += o.NoSA
	d.Auth += o.Auth
	d.Replay += o.Replay
	d.TSMismatch += o.TSMismatch
	d.Malformed += o.Malformed
	d.Oversize += o.Oversize
	d.SeqExhausted += o.SeqExhausted
}

// Total 丢弃总数。UI 上「丢了多少」要能一眼看到，再点开看构成。
func (d Drops) Total() uint64 {
	return d.NoPolicy + d.NoSA + d.Auth + d.Replay + d.TSMismatch + d.Malformed + d.Oversize + d.SeqExhausted
}

// sa 一条已装载的 Child SA（含出向与入向两个方向）。
//
// 生命周期由 ike 状态机决定，本结构只负责「按既定密钥收发包并如实计数」。
type sa struct {
	siteID   string
	inSPI    uint32
	outSPI   uint32
	out      *espCrypto
	in       *espCrypto
	localTS  netip.Prefix
	remoteTS netip.Prefix
	local    netip.AddrPort
	peer     netip.AddrPort

	createdAt  time.Time
	softExpire time.Time
	hardExpire time.Time

	// mu 保护出向序号与入向反重放窗口这两处**必须串行**的状态。
	// 计数器不在锁内（见下），因此这把锁只在每个包上被持有极短的一瞬。
	mu       sync.Mutex
	outSeq   uint64 // 已发出的最大序号；下一个包用 outSeq+1
	replay   replayWindow
	lastFrom netip.AddrPort // 最近一次收包的对端实测地址（NAT 重映射的诊断线索）

	// 计数器用原子量而非锁保护：状态上报每 15s 就要全量读一次，
	// 读计数不该和收发包抢同一把锁。各计数之间的瞬时不一致无害——
	// 它们本来就是统计量，不参与任何判定。
	rxBytes    atomic.Uint64
	txBytes    atomic.Uint64
	packetsIn  atomic.Uint64
	packetsOut atomic.Uint64

	dropAuth       atomic.Uint64
	dropReplay     atomic.Uint64
	dropTS         atomic.Uint64
	dropMalformed  atomic.Uint64
	dropSeqExhaust atomic.Uint64
}

// nextSeq 取下一个出向序号。
//
// 序号从 1 开始（RFC 4303 §3.3.3：使用某条 SA 发出的第一个包序号为 1）。
// 到顶不回绕，直接返回 ErrSeqExhausted——理由见该错误的注释。
func (s *sa) nextSeq() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outSeq >= MaxSeq {
		return 0, fmt.Errorf("esp: 出向 SA（SPI 0x%08x，站点 %s）序号已达上限 %d，拒绝继续发包"+
			"（本实现不做 ESN，也绝不回绕：GCM 下回绕即 nonce 复用）: %w",
			s.outSPI, s.siteID, MaxSeq, ErrSeqExhausted)
	}
	s.outSeq++
	return s.outSeq, nil
}

// counters 返回该 SA 的实测流量计数。
func (s *sa) counters() ipsec.Counters {
	return ipsec.Counters{
		RxBytes:    s.rxBytes.Load(),
		TxBytes:    s.txBytes.Load(),
		PacketsIn:  s.packetsIn.Load(),
		PacketsOut: s.packetsOut.Load(),
	}
}

// drops 返回该 SA 的丢弃计数（不含 NoPolicy/NoSA——那两类发生时还没定位到 SA）。
func (s *sa) drops() Drops {
	return Drops{
		Auth:         s.dropAuth.Load(),
		Replay:       s.dropReplay.Load(),
		TSMismatch:   s.dropTS.Load(),
		Malformed:    s.dropMalformed.Load(),
		SeqExhausted: s.dropSeqExhaust.Load(),
	}
}

// expired 硬生存期是否已到。零值 hardExpire 表示不设硬期限（仅用于测试与手工装载）。
func (s *sa) expired(now time.Time) bool {
	return !s.hardExpire.IsZero() && !now.Before(s.hardExpire)
}

// needRekey 是否已越过任一软阈值，以及**具体越过了哪一条**。
//
// ★理由字符串会一路传到控制台的 LastError/状态列。只回一个 bool 的话，
// 用户看到的是「在重协商」，但看不出是「时间到了」还是「这条隧道跑了 30 GB」——
// 后者往往意味着有人在拿站点隧道当大带宽通道用，是值得被看见的信息。
func (s *sa) needRekey(now time.Time) (bool, string) {
	s.mu.Lock()
	seq := s.outSeq
	s.mu.Unlock()

	if seq >= SoftSeqLimit {
		return true, fmt.Sprintf("出向序号 %d 已达软阈值 %d（32 位序号容量的一半）", seq, SoftSeqLimit)
	}
	if b := s.txBytes.Load() + s.rxBytes.Load(); b >= SoftBytesLimit {
		return true, fmt.Sprintf("累计流量 %d 字节已达软阈值 %d 字节（GCM 单密钥安全数据量上限的一半）", b, SoftBytesLimit)
	}
	if !s.softExpire.IsZero() && !now.Before(s.softExpire) {
		return true, fmt.Sprintf("已过软生存期（%s，硬到期 %s）", s.softExpire.Format(time.RFC3339), s.hardExpire.Format(time.RFC3339))
	}
	return false, ""
}

// SAInfo 一条 SA 的运行态快照，供状态上报与 rekey 判定使用。
//
// 全部字段都是**实测值**，没有一项是配置回显——回显配置正是旧实现
// 「toggle 一下界面就显示 up」的根源。
type SAInfo struct {
	SiteID string `json:"siteId"`
	InSPI  uint32 `json:"inSpi"`
	OutSPI uint32 `json:"outSpi"`

	ipsec.Counters
	Drops Drops `json:"drops"`

	OutSeq       uint64 `json:"outSeq"`       // 已发出的最大序号
	HighestInSeq uint64 `json:"highestInSeq"` // 已认证接收的最大序号

	LocalTS  netip.Prefix   `json:"localTs"`
	RemoteTS netip.Prefix   `json:"remoteTs"`
	Peer     netip.AddrPort `json:"peer"`
	// PeerSeen 最近一次收包的实测源地址。与 Peer 不一致说明中间有 NAT 做了重映射；
	// 本实现不做 MOBIKE，故只记录不采纳（见 Engine.Unprotect 的说明）。
	PeerSeen netip.AddrPort `json:"peerSeen"`

	CreatedAt  time.Time `json:"createdAt"`
	SoftExpire time.Time `json:"softExpire"`
	HardExpire time.Time `json:"hardExpire"`

	NeedRekey   bool   `json:"needRekey"`
	RekeyReason string `json:"rekeyReason"`
	Expired     bool   `json:"expired"`
}

// info 生成快照。
func (s *sa) info(now time.Time) SAInfo {
	s.mu.Lock()
	outSeq, highestIn, seen := s.outSeq, s.replay.highest, s.lastFrom
	s.mu.Unlock()

	need, reason := s.needRekey(now)
	return SAInfo{
		SiteID:       s.siteID,
		InSPI:        s.inSPI,
		OutSPI:       s.outSPI,
		Counters:     s.counters(),
		Drops:        s.drops(),
		OutSeq:       outSeq,
		HighestInSeq: highestIn,
		LocalTS:      s.localTS,
		RemoteTS:     s.remoteTS,
		Peer:         s.peer,
		PeerSeen:     seen,
		CreatedAt:    s.createdAt,
		SoftExpire:   s.softExpire,
		HardExpire:   s.hardExpire,
		NeedRekey:    need,
		RekeyReason:  reason,
		Expired:      s.expired(now),
	}
}

// newSA 由 ike 协商出的 ChildSAParams 构造一条可用的 SA。
//
// 这里是数据面唯一的「装载期拒绝」入口：所有不可用的组合必须在这一刻带着
// 实际值与期望值报出来。放过去的后果一律是运行期的「解密失败」或「不通」，
// 而那两句话指向不了任何具体原因。
func newSA(p ipsec.ChildSAParams, now func() time.Time) (*sa, error) {
	if p.InSPI < SPIMin {
		return nil, fmt.Errorf("esp: 入向 SPI 0x%08x 落在保留区间（须 ≥ %d，即 0 与 1..255 不可用）", p.InSPI, SPIMin)
	}
	if p.OutSPI < SPIMin {
		return nil, fmt.Errorf("esp: 出向 SPI 0x%08x 落在保留区间（须 ≥ %d，即 0 与 1..255 不可用）", p.OutSPI, SPIMin)
	}
	if err := checkTS("本端受保护网段 LocalTS", p.LocalTS); err != nil {
		return nil, err
	}
	if err := checkTS("对端受保护网段 RemoteTS", p.RemoteTS); err != nil {
		return nil, err
	}
	if p.LocalTS.Addr().Is4() != p.RemoteTS.Addr().Is4() {
		return nil, fmt.Errorf("esp: LocalTS %s 与 RemoteTS %s 的地址族不同——一条 SA 只承载一个族的流量，"+
			"混族配置下所有出向包都会因为 netip 的跨族比较恒 false 而落进 ErrNoPolicy", p.LocalTS, p.RemoteTS)
	}
	if !p.Peer.IsValid() {
		return nil, fmt.Errorf("esp: 对端 UDP-ESP 落点无效（%s）——出向包无处可发", p.Peer)
	}

	out, err := newCrypto(p.EncrID, p.KeyBits, p.IntegID, p.OutEncrKey, p.OutIntegKey)
	if err != nil {
		return nil, fmt.Errorf("esp: 站点 %s 出向密钥装载失败: %w", p.SiteID, err)
	}
	in, err := newCrypto(p.EncrID, p.KeyBits, p.IntegID, p.InEncrKey, p.InIntegKey)
	if err != nil {
		return nil, fmt.Errorf("esp: 站点 %s 入向密钥装载失败: %w", p.SiteID, err)
	}

	created := p.CreatedAt
	if created.IsZero() {
		created = now()
	}
	s := &sa{
		siteID: p.SiteID,
		inSPI:  p.InSPI,
		outSPI: p.OutSPI,
		out:    out,
		in:     in,
		// Masked 一下再存：日志与状态里出现 "10.60.0.7/24" 这种带主机位的写法时，
		// 读的人会以为策略只覆盖那一个地址，白白多一轮排查。
		localTS:    p.LocalTS.Masked(),
		remoteTS:   p.RemoteTS.Masked(),
		local:      p.Local,
		peer:       p.Peer,
		createdAt:  created,
		hardExpire: p.HardExpire,
	}
	if !p.HardExpire.IsZero() && p.HardExpire.After(created) {
		d := p.HardExpire.Sub(created)
		s.softExpire = created.Add(time.Duration(float64(d) * softLifetimeRatio))
	}
	return s, nil
}

// checkTS 校验一条流量选择器前缀。
func checkTS(name string, p netip.Prefix) error {
	if !p.IsValid() {
		return fmt.Errorf("esp: %s 无效（%s）", name, p)
	}
	if p.Addr().Is4In6() {
		// ★netip 的 Contains **不跨族匹配**：IPv4 包解析出来的地址是 Is4，
		// 而 ::ffff:10.60.0.0/120 是 Is4In6，两者永远不相等。
		// 症状是所有出向包都落进 ErrNoPolicy（隧道 up、流量却一个都不进去），
		// 且日志里两个地址肉眼看上去还一模一样。
		return fmt.Errorf("esp: %s 用了 IPv4-mapped IPv6 形态（%s）——请写成原生 IPv4 形态（如 10.60.0.0/24）。"+
			"netip 的前缀匹配不跨族，混用会让所有流量都匹配不到策略而被丢弃", name, p)
	}
	return nil
}

// AllocSPI 生成一个合法的 ESP SPI（排除 0 与 1..255）。
//
// 随机取值落进保留区间的概率约 6e-8，因此循环几乎不会走第二轮；
// 但**必须**有这个循环——直接 `v | 0x100` 之类的"修正"会把 256 个值挤成 1 个，
// 显著抬高与对端 SPI 撞车的概率。
// 尝试上限用于挡住被注入了退化随机源的情形（测试里常见），并给出可读的失败原因。
func AllocSPI(rand io.Reader) (uint32, error) {
	var b [4]byte
	for i := 0; i < 64; i++ {
		if _, err := io.ReadFull(rand, b[:]); err != nil {
			return 0, fmt.Errorf("esp: 生成 SPI 时读随机源失败: %w", err)
		}
		if v := binary.BigEndian.Uint32(b[:]); v >= SPIMin {
			return v, nil
		}
	}
	return 0, fmt.Errorf("esp: 连续 64 次取到的 SPI 都落在保留区间（< %d），随机源疑似退化或被固定为常量", SPIMin)
}
