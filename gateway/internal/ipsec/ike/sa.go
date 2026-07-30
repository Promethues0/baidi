package ike

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// 本文件是状态机的**数据底座**：一条 IKE SA 在内存里的全部形态，以及那些
// 「写反了不会报错、只会让隧道静默不通」的取值规则（密钥方向、I 位、Message ID、
// 响应缓存、IV 计数器）。行为放在 initiator.go / responder.go / rekey.go / informational.go。
//
// ★这里集中了四条最容易写错的规则，每条都在字段旁重复了一遍「写错的症状」——
// 因为它们的共同特征是：编译能过、握手能过、日志一片正常，只有对端解不开包。

// SAState 一条 IKE SA 的生命周期状态（2-ike.md §7.1）。
//
// 刻意不复用 ipsec.State：那是**站点**对控制台呈现的五态（含"管理员没启用"这种
// 纯管理语义），而这里是协议状态机。两者一对多（一个站点可能同时挂着一条已建立的
// SA 和一条重协商中的新 SA），混用会让「站点 up 但哪条 SA 在承载」变得无法回答。
type SAState uint8

const (
	SAIdle        SAState = iota // 未开始
	SASAInitSent                 // 发起方：已发 IKE_SA_INIT，等响应
	SAAuthSent                   // 发起方：已发 IKE_AUTH，等响应
	SAHalfOpen                   // 响应方：已回 IKE_SA_INIT 响应，等 IKE_AUTH（★占配额，见 cookie.go）
	SAEstablished                // 双方：认证通过
	SARekeying                   // 重协商进行中（旧 SA 仍在承载流量）
	SADeleting                   // 已发 D(IKE)，等响应
	SADead                       // 可回收
)

func (s SAState) String() string {
	switch s {
	case SAIdle:
		return "Idle"
	case SASAInitSent:
		return "SaInitSent"
	case SAAuthSent:
		return "AuthSent"
	case SAHalfOpen:
		return "HalfOpen"
	case SAEstablished:
		return "Established"
	case SARekeying:
		return "Rekeying"
	case SADeleting:
		return "Deleting"
	case SADead:
		return "Dead"
	}
	return fmt.Sprintf("SAState(%d)", uint8(s))
}

// allocTxMID 给一条**不等响应**的单发请求（D(IKE) / D(ESP)）分配 Message ID。
//
// ★不能直接用 nextTxMID：它只在收到响应时才前进（onResponse 里 `= ex.mid+1`），
// 所以只要有未完成的出向交换，nextTxMID 就恒等于 pending.mid。此时发的 D(IKE)
// 会与在途的 CREATE_CHILD_SA 共用同一个 MID —— 对端已把该 MID 记为已处理，
// 于是把删除**当成重传**、回放旧响应，删除被静默忽略：本端拆干净了，对端留一条
// 幽灵 SA 继续往没人接收的隧道灌业务流量，直到 DPD 判死（最长约 4 分钟）。
func (sa *IKESA) allocTxMID() uint32 {
	mid := sa.nextTxMID
	if sa.pending != nil && sa.pending.mid >= mid {
		mid = sa.pending.mid + 1
	}
	sa.nextTxMID = mid + 1
	return mid
}

// authenticated 报告这条 SA 是否已通过 IKE_AUTH（对端确实持有 PSK）。
//
// 三个"是"都在认证之后：Established 自不必说；Rekeying 是重协商在途、旧 SA 仍承载流量；
// Deleting 是本端已发 D(IKE) 等响应——此时对端仍可能有在途的合法 INFORMATIONAL 要处理。
// 认证之前的 Idle/SaInitSent/AuthSent/HalfOpen 一律为否：**密钥就绪不等于身份已验**，
// 响应方回完 IKE_SA_INIT 就已持有可用的 SK 密钥，但那把密钥不含任何 PSK 成分。
func (s SAState) authenticated() bool {
	return s == SAEstablished || s == SARekeying || s == SADeleting
}

// exchangeKind 标记一次**由本端发起**的交换在等什么响应。
//
// 存在的理由：收到响应时必须知道该走哪条处理分支。只看 Exchange Type 不够——
// CREATE_CHILD_SA 既可能是换 Child SA 也可能是换 IKE SA，两者的密钥派生完全不同，
// 而报文里唯一的区别是 SA 载荷的 Protocol ID（把判定寄托在对端回什么，等于让对端
// 决定本端走哪条代码路径）。
type exchangeKind uint8

const (
	exNone exchangeKind = iota
	exSAInit
	exAuth
	exRekeyChild // CREATE_CHILD_SA：换 Child SA
	exRekeyIKE   // CREATE_CHILD_SA：换 IKE SA
	exDPD        // INFORMATIONAL：空 SK{}
	exDelete     // INFORMATIONAL：D(IKE) 或 D(ESP)
)

// exchange 一次**未完成的出向请求**。窗口固定为 1，所以每条 IKE SA 至多挂一个。
//
// ★raw 是已经编码/加密好的完整报文，重传时**原样重发**。
// 绝不重新构造：GCM 的显式 nonce 来自 txIVCounter，重新加密会换一个 nonce，
// 而同一份明文用同一把密钥配两个 nonce 并不危险——真正致命的是反过来（nonce 复用）。
// 但重新构造还有第二个问题：AUTH 之类的载荷若因时间戳/随机补齐产生差异，
// 对端会把两条报文当成两次不同的请求。原样重发是唯一没有副作用的做法。
type exchange struct {
	kind   exchangeKind
	et     ExchangeType
	mid    uint32
	raw    []byte
	tries  int       // 已发送次数（首发算 1）
	nextAt time.Time // 下次重传时刻

	// 下面是"发出去时的上下文"，收到响应才用得上。
	// 放在 exchange 里而不是 IKESA 上：并发两个交换是不可能的（窗口 1），
	// 但把上下文挂在交换上能让"响应到了却找不到当初发的是什么"变成编译期不可能。
	childNi  []byte    // CREATE_CHILD_SA 的 Ni
	childDH  DHPrivate // PFS 时的临时 DH 私钥
	childNew *ChildSA  // 待建/待替换的新 Child SA（已分配好入向 SPI）
	childOld uint32    // 被替换的旧入向 SPI；0 = 新建而非 rekey
	ikeNew   *IKESA    // 换 IKE SA 时的新 SA 骨架
}

// ChildSA 一条已协商（或协商中）的 Child SA。
//
// ★InSPI/OutSPI 的语义必须背下来：
//   - InSPI  = **本端入向**，即本端在 SA 提案里告诉对端「请你用这个 SPI 发给我」；
//   - OutSPI = 对端给的那个，本端发包时填。
//
// 两者写反的后果：两端都往**自己**的入向 SPI 上发包，谁也收不到，
// 但 IKE 层一切正常、界面显示 up、日志无任何错误。
type ChildSA struct {
	SiteID        string
	InSPI, OutSPI uint32
	Spec          SuiteSpec // ESP 套件（PRFID==0）
	PFS           bool

	CreatedAt  time.Time
	SoftExpire time.Time // 到点触发 rekey
	HardExpire time.Time // 到点必须消失

	// rekeying 标记本端已对这条 SA 发起重协商。
	// ★这是 TEMPORARY_FAILURE 判定的唯一依据：对端同时也来换同一条 SA 时，
	// 回 TEMPORARY_FAILURE 让它退避重试，比实现 RFC §2.8.1 的 nonce 比大小 + 双 SA
	// 收敛逻辑简单一个数量级，且 RFC 明确允许。
	rekeying bool

	// retiring/retireAt：被新 SA 取代后进入**延迟删除**。
	// ★不能立刻拆入向 SA：对端在途的报文会被丢，表现为「每次重协商掉几个包」——
	// 这种偶发丢包在业务侧看是随机的，最难归因。
	retiring bool
	retireAt time.Time

	installed bool // 是否已推给 ipsec.Protector
}

// IKESA 一条 IKE SA 的完整运行态。
type IKESA struct {
	SiteID string

	// SPIi/SPIr 按 IKE 头里的原始位置存放，**不按本端角色调换**。
	// 密钥派生的 seed 里也是原样拼接（keys.go 会复述这条）。
	SPIi, SPIr [8]byte

	// LocalIsInit 本端是否为**该 IKE SA 的原始发起方**。
	//
	// ★这一个 bool 同时决定三件事，而且三件事都在出错时给出同一句无用的报错：
	//  ① I 标志位（原始响应方后来自己发 INFORMATIONAL 请求时 I 仍为 0）；
	//  ② 密钥方向（出向用 SK_ei 还是 SK_er）；
	//  ③ Child SA 密钥取 KEYMAT 的哪一半。
	// 写反的症状统一是「解密失败」，两端日志都只有这一句。
	LocalIsInit bool

	Spec  SuiteSpec
	Suite *Suite
	Keys  *IKEKeys
	State SAState

	// Local/Peer 是本 SA 当前收发用的地址。
	// ★Peer 以**实际观测到的源地址**为准而非配置里的值：对端在 NAT 后时，
	// 配置里的地址根本收不到包。NAT 检测通过后还会切到 4500 端口（见 nat.go）。
	Local netip.AddrPort
	Peer  netip.AddrPort

	PeerNATed  bool // 对端在 NAT 后
	LocalNATed bool // 本端在 NAT 后（决定要不要发 keepalive）

	// ── Message ID（双向各自独立计数，RFC 7296 §2.2）──
	//
	// ★同一个数值可以出现在四条不同报文里（我方请求/我方响应/对方请求/对方响应），
	// 靠 **I 位**消歧。所以这里是两个独立计数器，不是一个。
	nextTxMID   uint32 // 本端下一个**请求**用的 MID
	expectRxMID uint32 // 期待对端下一个**请求**的 MID

	// ── 响应缓存（RFC 7296 §2.1）──
	//
	// ★只有交换的发起方重传；响应方**永不主动重传**，但必须能对重复请求
	// **原样回放**上一条响应。重新计算是灾难性的：GCM 的显式 nonce 会被复用，
	// 同一把密钥下 nonce 复用直接摧毁 GCM 的机密性与完整性（不是"稍微弱一点"，
	// 是可以恢复认证密钥的级别）。所以这里缓存的是**字节**，不是"重建响应所需的材料"。
	lastRespMID uint32
	lastRespRaw []byte
	hasLastResp bool

	// txIVCounter 本端出向的 GCM 显式 nonce 计数器，每 SA 每方向单调递增。
	// ★禁止用随机数：8 字节随机 nonce 在生日界下 2^32 条报文就有碰撞风险，
	// 而计数器是零成本的确定性保证。
	txIVCounter uint64

	// initMsgRaw/respMsgRaw = RFC 7296 §2.15 的 RealMessage1 / RealMessage2。
	// ★必须是**收发时的原始字节**，且 COOKIE / INVALID_KE_PAYLOAD 重试后要更新成
	// **重发的那一条**（见 initiator.go 的 resendSAInit）。用第一条算 AUTH 是
	// PSK 路径上排名靠前的经典错误，症状仍然只有一句「认证失败」。
	initMsgRaw []byte
	respMsgRaw []byte

	ni, nr []byte    // IKE_SA_INIT 的两个 nonce（值，不含载荷头）
	dh     DHPrivate // 本端 DH 私钥；密钥派生完即置 nil（不再需要，且尽早丢弃）

	children map[uint32]*ChildSA // key = 本端入向 SPI

	createdAt  time.Time
	softExpire time.Time
	hardExpire time.Time
	lastSeen   time.Time // DPD 计时基准；ESP 收包也会经 Engine.Touch 刷新

	// lastKeepalive 上次发 NAT keepalive 的时刻（本端在 NAT 后才用）。
	lastKeepalive time.Time

	halfOpenUntil   time.Time  // 响应方 half-open 超时时刻
	halfOpenIP      netip.Addr // 半开配额销账用（按源 IP 计数）
	countedHalfOpen bool

	pending *exchange // 本端未完成的出向请求（窗口固定 1）

	cookieRetries int // COOKIE 重发次数
	keRetries     int // INVALID_KE_PAYLOAD 重发次数

	rekeying   bool // 本端已对**这条 IKE SA** 发起重协商
	retiring   bool // 已被取代，等延迟删除
	retireAt   time.Time
	deleteSent bool
}

// newIKESA 建一条空 SA 骨架。
func newIKESA(siteID string, localIsInit bool, now time.Time) *IKESA {
	return &IKESA{
		SiteID:      siteID,
		LocalIsInit: localIsInit,
		State:       SAIdle,
		children:    make(map[uint32]*ChildSA),
		createdAt:   now,
		lastSeen:    now,
	}
}

// localSPI 本端那半 SPI。
//
// ★这是收包路由的索引键。规则推导一遍就不会记错：
// 对端发来的报文，其 I 位描述的是**该 SA 的原始发起方**——
//   - 本端是发起方 → 对端是响应方 → 对端所有报文 I=0 → 本端 SPI 在 SPIi 位置；
//   - 本端是响应方 → 对端是发起方 → 对端所有报文 I=1 → 本端 SPI 在 SPIr 位置。
//
// 于是「按 I 位取另一半」恰好总能取到本端的 SPI，见 engine.go 的 lookupSA。
func (s *IKESA) localSPI() [8]byte {
	if s.LocalIsInit {
		return s.SPIi
	}
	return s.SPIr
}

// EncKeyOut 出向加密密钥。i 方向 = 原始发起方 → 响应方，**与本次交换谁发起无关**。
func (s *IKESA) EncKeyOut() []byte {
	if s.LocalIsInit {
		return s.Keys.SKei
	}
	return s.Keys.SKer
}

// EncKeyIn 入向解密密钥。
func (s *IKESA) EncKeyIn() []byte {
	if s.LocalIsInit {
		return s.Keys.SKer
	}
	return s.Keys.SKei
}

// IntegKeyOut 出向完整性密钥（combined 模式下为 nil，DecryptSK/EncryptSK 会校验形态）。
func (s *IKESA) IntegKeyOut() []byte {
	if s.LocalIsInit {
		return s.Keys.SKai
	}
	return s.Keys.SKar
}

// IntegKeyIn 入向完整性密钥。
func (s *IKESA) IntegKeyIn() []byte {
	if s.LocalIsInit {
		return s.Keys.SKar
	}
	return s.Keys.SKai
}

// flags 组装 IKE 头标志位。
//
// ★I 位只看 LocalIsInit（原始角色），不看本次交换谁发起。
// 原始响应方发 DPD 请求时 I 仍为 0——写成"我发起我就置 I"会让对端的
// MID 消歧彻底错乱，表现为 DPD 请求被当成重传丢弃、隧道最终被判死。
func (s *IKESA) flags(response bool) Flags {
	var f Flags
	if s.LocalIsInit {
		f |= FlagInitiator
	}
	if response {
		f |= FlagResponse
	}
	return f
}

// header 构造一个属于本 SA 的 IKE 头。Length 由 Encode/EncryptSK 回填。
func (s *IKESA) header(et ExchangeType, mid uint32, response bool) Header {
	return Header{
		SPIi:         s.SPIi,
		SPIr:         s.SPIr,
		Version:      Version,
		ExchangeType: et,
		Flags:        s.flags(response),
		MessageID:    mid,
	}
}

// nextIV 取下一个出向 GCM 显式 nonce。
//
// ★计数器接近回绕时**直接拆 SA**而不是回绕：回绕意味着 nonce 复用，
// 而 nonce 复用不是"安全性下降"，是 GCM 的认证密钥可被恢复。
// 隧道断掉会被立刻发现并重连，静默复用则永远不会被发现。
func (s *IKESA) nextIV() (uint64, error) {
	if s.txIVCounter >= 1<<63 {
		return 0, errors.New("ike: 出向 IV 计数器接近回绕，拒绝继续加密（nonce 复用会摧毁 GCM 的机密性，必须重协商 SA）")
	}
	v := s.txIVCounter
	s.txIVCounter++
	return v, nil
}

// cacheResponse 记下最后一条响应的完整字节，供对端重传时原样回放。
func (s *IKESA) cacheResponse(mid uint32, raw []byte) {
	s.lastRespMID = mid
	s.lastRespRaw = append([]byte(nil), raw...)
	s.hasLastResp = true
}

// replayResponse 若 mid 命中缓存则返回可原样重发的字节。
func (s *IKESA) replayResponse(mid uint32) ([]byte, bool) {
	if s.hasLastResp && s.lastRespMID == mid {
		return s.lastRespRaw, true
	}
	return nil, false
}

// spiHex 供状态回报与日志使用（SPI 是"真的协商过"最硬的可视证据：
// 单端伪造不出与对端交叉相等的一对值）。
func spiHex(spi [8]byte) string { return hex.EncodeToString(spi[:]) }

// childByOut 按对端 SPI 找 Child SA（处理对端发来的 D(ESP) 时用）。
func (s *IKESA) childByOut(outSPI uint32) *ChildSA {
	for _, c := range s.children {
		if c.OutSPI == outSPI {
			return c
		}
	}
	return nil
}

// activeChild 返回当前应当承载流量的那条 Child SA（未进入退休期的最新一条）。
func (s *IKESA) activeChild() *ChildSA {
	var best *ChildSA
	for _, c := range s.children {
		if c.retiring {
			continue
		}
		if best == nil || c.CreatedAt.After(best.CreatedAt) {
			best = c
		}
	}
	return best
}

// ── SPI 生成 ──

// randIKESPI 生成一个**非全零**的 8 字节 IKE SPI。
//
// 全零 SPIi 被 wire.Decode 直接丢弃（RFC 7296 §2.6），所以这里必须重试而不是
// 听天由命——概率虽为 2^-64，但"极小概率的静默失败"正是最难复现的那类 bug。
func randIKESPI(rnd io.Reader) ([8]byte, error) {
	var spi [8]byte
	for i := 0; i < 8; i++ {
		if _, err := io.ReadFull(rnd, spi[:]); err != nil {
			return spi, fmt.Errorf("ike: 生成 IKE SPI 失败（熵源不可用）: %w", err)
		}
		if spi != ([8]byte{}) {
			return spi, nil
		}
	}
	return spi, errors.New("ike: 连续 8 次取到全零 SPI，熵源异常")
}

// allocChildSPI 生成一个合法的 ESP SPI。
//
// ★必须排除 0 与 1..255（RFC 4303 保留值）。理由不是"标准这么写"，而是
// UDP 4500 上三类报文靠首字节区分：4 字节全零 = non-ESP marker（其后是 IKE），
// 单字节 0xFF = NAT keepalive，其余按 ESP 的 SPI 解读。SPI 落进保留区
// 会让对端把 ESP 报文误判成 IKE 报文并静默丢弃——数据面全断，控制面却一切正常。
func allocChildSPI(rnd io.Reader) (uint32, error) {
	var b [4]byte
	for i := 0; i < 16; i++ {
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return 0, fmt.Errorf("ike: 生成 ESP SPI 失败（熵源不可用）: %w", err)
		}
		v := binary.BigEndian.Uint32(b[:])
		if v > 255 {
			return v, nil
		}
	}
	return 0, errors.New("ike: 连续 16 次取到保留区 SPI（≤255），熵源异常")
}
