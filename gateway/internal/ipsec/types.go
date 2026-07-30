// Package ipsec 是白帝 IPSec 站点组网的**契约层**：只放跨包共享的类型与接口，不放协议实现。
//
// 依赖方向被刻意压成一条单向链，任何一环都不许反向 import：
//
//	ipsec（契约） ← ike（IKEv2 控制面） ← esp（ESP 数据面） ← site（编排） ← cmd/baidi-ipsec
//
// 这样 ike / esp 能各自独立编译与单测（协议实现最需要的就是能脱离进程跑），
// 也是本轮多人并行施工两两不撞车的前提：契约在这里定死，各包只往自己的文件里加。
//
// ★本包**不 import** ike/esp/site 中的任何东西。若某天发现需要反向引用，
// 那说明契约选错了位置，应把类型搬进契约层，而不是加一条反向依赖。
package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// ── 运行态 ──

// State 一条站点隧道的运行态。
//
// ★五态而非三态。现状只有 up/connecting/down，于是「管理员没启用」与
// 「启用了但协商失败」在界面上长得一模一样——那正是「接了真状态，用户仍然
// 不知道为什么连不上」的结局。down 是管理意图，failed 是故障，二者必须分开。
type State string

const (
	StateDown       State = "down"       // 管理员未启用（不是故障）
	StateConnecting State = "connecting" // 已启用，IKE 协商进行中
	StateUp         State = "up"         // Child SA 已装载，可承载流量
	StateRekeying   State = "rekeying"   // 重协商中（旧 SA 仍在承载）
	StateFailed     State = "failed"     // 启用了但协商/认证失败，见 LastError
)

// ── 站点配置（控制面权威，网关只消费）──

// Phase 一相加密套件。三个字段是控制台的自由字符串，
// 由 ike.SpecFromPhase 映射成 Transform ID；映射不出来就**装载期拒绝**，
// 绝不静默降级——静默降级造成的「控制台配了 A、实际跑了 B」是本项目最难排查的失败形态。
type Phase struct {
	Enc  string `json:"enc"`  // AES256-GCM / AES256-CBC / SM4-GCM / SM4-CBC
	Hash string `json:"hash"` // SHA256 / SM3
	DH   string `json:"dh"`   // group14 / group19 / sm2p256
}

// SiteConfig 一条站点到站点隧道的完整配置。这是控制面下发给网关的**唯一**输入；
// 网关不推导、不猜测、不从别处补齐（与客户端接入剖面同一姿态）。
type SiteConfig struct {
	ID        string
	Name      string
	GatewayID string // 哪台网关负责这条站点；不匹配本机则整条忽略（多网关下防两台抢同一条 SA）
	Enabled   bool   // 管理意图。与运行态彻底解耦：Enabled=true 不等于 State=up

	Peer         netip.AddrPort // 对端 IKE 落点（端口缺省 500）
	LocalSubnet  netip.Prefix   // TSi：本端受保护网段
	RemoteSubnet netip.Prefix   // TSr：对端受保护网段

	// LocalID/RemoteID 是 IKEv2 的 IDi/IDr。
	// ★必须用 FQDN 形态（如 gw-a.baidi）：NAT 场景下对端看到的是 NAT 后地址，
	// 用 IP 类型 ID 身份匹配必挂，且失败信息只有一句「认证失败」。
	LocalID  string
	RemoteID string

	Auth   string // 本轮只支持 "psk"；"cert"/"sm2cert" 装载期拒绝
	Suite  string // "standard"（RFC 码点）| "gm"（白帝私有码点，只承诺白帝↔白帝）
	Phase1 Phase  // IKE SA 提案
	Phase2 Phase  // Child SA（ESP）提案
	PFS    bool   // CREATE_CHILD_SA 是否带 KE

	IKELifetime  time.Duration // IKE SA 硬生存期（默认 4h）
	ESPLifetime  time.Duration // Child SA 硬生存期（默认 1h）
	DPDDelay     time.Duration // DPD 探测间隔（默认 30s）
	RetryInitial time.Duration // 协商失败后的首次重试间隔（默认 30s，指数退避至 5min）

	// PSK 预共享密钥**原文字节**。
	// ★口径固定：AUTH 计算里 prf(PSK, "Key Pad for IKEv2") 的 key 就是这段原文，
	// 不做任何编码转换。控制面若以 hex/base64 保存，必须在下发前解码完毕。
	// 空 PSK 能协商成功——那才是真事故，故 Validate 对空 PSK 直接拒绝启动该站点。
	PSK        []byte
	PSKVersion int // 版本号。网关据此判断要不要重新取密钥，避免 PSK 随策略每 15s 重传

	// PeerNATPort 对端的 **UDP 封装口**（ESP 的落点）。0 = 与本端的 -natt-port 相同。
	//
	// ★为什么需要这个字段：本实现只做 UDP 封装的 ESP（不做裸 ESP），而 RFC 3948
	// 把封装口定死为 4500、IKEv2 也**没有**通告对端封装端口的机制。于是实现只能
	// 按「两端端口号相同」推算——生产上两端都是 4500，这个假设永远成立。
	// 但只要有一端改了 -natt-port（NAT 环境或与既有 IPSec 共存时的常规需求），
	// 假设就崩了：ESP 被发到一个没人监听的端口，而 **IKE 协商照样全绿、隧道显示 up、
	// 字节数恒为 0、没有任何报错**。把它做成显式配置，是为了让这种拓扑至少可表达、
	// 可排查，而不是变成又一个静默失效。
	PeerNATPort uint16
}

// SiteState 网关回报给控制面的**实测**运行态。字段全部来自 IKE 状态机与 ESP 计数器，
// 没有任何一项是配置回显——回显配置正是旧实现「toggle 一下就显示 up」的根源。
type SiteState struct {
	SiteID    string `json:"siteId"`
	GatewayID string `json:"gatewayId"`
	State     State  `json:"state"`

	// SPI 是「真的协商过」最硬的可视证据：单端伪造不出与对端交叉相等的一对 SPI。
	IKESPIi     string `json:"ikeSpiI"`     // 16 hex（8 字节）
	IKESPIr     string `json:"ikeSpiR"`     // 16 hex
	ChildSPIIn  uint32 `json:"childSpiIn"`  // 本端入向（= 对端出向）
	ChildSPIOut uint32 `json:"childSpiOut"` // 本端出向（= 对端入向）

	Counters

	// NegotiatedProposal 实际协商定型的套件（如 "AES256-GCM16/PRF-HMAC-SHA256/ECP256"）。
	// 与配置意图分列展示：配的是 A、谈出来 B 时高亮，是「真的在谈判」最直观的证据。
	NegotiatedProposal string `json:"negotiatedProposal"`

	EstablishedAt int64 `json:"establishedAt"` // Unix 秒，0=未建立
	RekeyAt       int64 `json:"rekeyAt"`       // 预计软生存期到点
	ExpiresAt     int64 `json:"expiresAt"`     // 硬生存期到点
	ReportedAt    int64 `json:"reportedAt"`

	// LastError 可读中文原因（"对端 203.0.113.88:500 无响应（7 次重传超时）"）。
	// ★把 NO_PROPOSAL_CHOSEN 这类码点直接甩给用户等于没说，必须带上「谁不接受什么」。
	LastError   string `json:"lastError"`
	LastErrorAt int64  `json:"lastErrorAt"`
}

// Counters ESP 层的真实字节/包计数。UI 上的流量数字只允许来自这里。
type Counters struct {
	RxBytes    uint64 `json:"rxBytes"`
	TxBytes    uint64 `json:"txBytes"`
	PacketsIn  uint64 `json:"packetsIn"`
	PacketsOut uint64 `json:"packetsOut"`
}

// ── IKE ↔ ESP 的唯一接缝 ──

// ChildSAParams 一条 Child SA 装载所需的全部材料。
//
// ★这是 ike 与 esp 之间**唯一**的数据结构：ike 不 import esp，esp 也不 import ike 的状态机，
// 两边只在这个纯值对象上会合。方向依赖单向，两个包都能单独测。
type ChildSAParams struct {
	SiteID string

	// InSPI 本端入向 SPI（= 在 SA 提案里告诉对端「请用这个 SPI 发给我」）。
	// OutSPI 对端给的 SPI，本端出向使用。
	// ★SPI 生成必须排除 0 与 1..255（保留值），否则 UDP 4500 上无法与
	// non-ESP marker（4 字节全零）及 keepalive（单字节 0xFF）区分。
	InSPI  uint32
	OutSPI uint32

	// 算法用 IKEv2 Transform ID 表达（含私有段），由 esp 侧 ike.LookupEncr/LookupInteg 解析。
	// 用码点而不是字符串：协商结果本来就是码点，转字符串再转回来只会引入一次翻译错误。
	EncrID  uint16
	KeyBits int
	IntegID uint16

	// 密钥按方向切好，esp 侧不需要知道谁是 initiator。
	// ★GCM 类算法的密钥**末尾 4 字节是 salt**，长度已含在内。
	OutEncrKey, OutIntegKey []byte
	InEncrKey, InIntegKey   []byte

	LocalTS  netip.Prefix // 本端受保护网段（出向源、入向目的必须落在其中）
	RemoteTS netip.Prefix // 对端受保护网段

	Local netip.AddrPort // 本端 UDP-ESP 落点（4500）
	Peer  netip.AddrPort // 对端 UDP-ESP 落点（NAT 后以实测地址为准）

	CreatedAt  time.Time
	HardExpire time.Time
}

// Protector 是 ESP 数据面对外的全部能力：装载/拆除 Child SA + 逐包封装/解封。
// 由 esp 包实现，site 编排层与 ike 状态机都只面向这个接口。
type Protector interface {
	// Install 装载一条 Child SA（出向 + 入向）。同 InSPI 重复装载视为替换。
	Install(p ChildSAParams) error
	// Remove 按入向 SPI 拆除。
	// ★rekey 时不要立刻拆旧入向 SA：对端在途报文会被丢，表现为「重协商瞬间掉几个包」。
	Remove(inSPI uint32) error
	// Counters 回读实测计数（rekey 的字节阈值与控制面上报都用它）。
	Counters(inSPI uint32) Counters

	// Protect 按 SPD（目的地址落在哪条站点的 RemoteTS）选出向 SA 并封装。
	// ★没有匹配策略必须返回 ErrNoPolicy 并由上层**丢弃计数**，绝不允许原样明文发出去——
	// 「隧道建起来了、流量却没走隧道且全程无报错」是本项目历史上最迷惑人的失败形态。
	Protect(ipPkt []byte) (espPkt []byte, dst netip.AddrPort, err error)
	// Unprotect 解封入向 ESP 报文：查 SA → 验 ICV → 解密 → 反重放 → 内层 TS 校验。
	Unprotect(espPkt []byte, from netip.AddrPort) (ipPkt []byte, err error)
}

// ── 数据面管道 ──

// Datapath 受保护流量的两端：出向读明文 IP 包、入向写明文 IP 包。
//
// ★抽象它唯一的目的是**让数据面在无 root 下可被 go test 验证**。
// 生产实现是 TUN（建卡要 root），测试实现是内存管道与 gVisor netstack。
// 没有这层抽象，「真的加解密了」就只能靠人在有 root 的机器上肉眼跑一次，永远进不了 CI。
type Datapath interface {
	// ReadOutbound 读一个待保护的出向 IP 包到 buf，返回长度。
	ReadOutbound(buf []byte) (int, error)
	// WriteInbound 投递一个解封出来的入向 IP 包。
	WriteInbound(ipPkt []byte) error
	MTU() int
	Close() error
}

// ── UDP 通道（IKE 与 ESP 共用）──

// PacketKind UDP 4500 上三类报文的判别结果。
//
// 判别规则（RFC 3948）：首 4 字节全零 = non-ESP marker，其后是 IKE；
// 单字节 0xFF = NAT keepalive，直接丢弃；否则首 4 字节是 ESP 的 SPI（规定非零）。
type PacketKind uint8

const (
	KindIKE PacketKind = iota
	KindESP
	KindKeepalive
)

// Datagram 一个收发单元。Payload 对 IKE 是**不含 non-ESP marker** 的裸 IKE 报文，
// 对 ESP 是完整 ESP 报文（SPI 开头）。marker 的加减由 Transport 实现独占，
// ★上层永远看不到它——AUTH 签名字节串不含 marker，让 marker 泄漏到上层就是给自己埋雷。
type Datagram struct {
	Kind    PacketKind
	Local   netip.AddrPort // 本端收发地址（NAT 检测要用实际值，不是配置值）
	Remote  netip.AddrPort // 对端地址（NAT 后以实测为准）
	Payload []byte
}

// Transport IKE 与 ESP 共用的 UDP 通道。
//
// ★共用一条 socket 是硬要求而非优化：NAT 映射是按「五元组」建立的，
// ESP 若另开端口，NAT 后的对端根本收不到。生产实现同时监听 500 与 4500。
type Transport interface {
	Send(d Datagram) error
	// Recv 阻塞取下一个报文；通道关闭返回 ErrClosed。
	Recv() (Datagram, error)
	Close() error
}

// ── 后端抽象（为未来接 strongSwan 留位，本轮只实现纯 Go 后端）──

// Backend 一个 IPSec 后端。
//
// Apply 采用**全量声明式替换**而非增量 add/del：与 resource.Replace 已有的模式一致，
// 全量对账比增量幂等得多，也正好对得上 strongSwan vici 的声明式风格——
// 将来换后端时，控制面协议与回报格式零改动。
type Backend interface {
	Apply(ctx context.Context, sites []SiteConfig) error
	States(ctx context.Context) ([]SiteState, error)
	Close() error
}

// ── 错误 ──

var (
	// ErrClosed 通道/数据面已关闭。
	ErrClosed = errors.New("ipsec: 已关闭")
	// ErrNoPolicy 出向包没有匹配的 SPD 策略（必须丢弃并计数，不得明文发出）。
	ErrNoPolicy = errors.New("ipsec: 无匹配的 IPSec 策略")
	// ErrNoSA 入向 ESP 的 SPI 查不到 SA。
	ErrNoSA = errors.New("ipsec: 未知 SPI")
	// ErrAuth ESP 完整性校验失败（含 GCM 认证失败）。
	ErrAuth = errors.New("ipsec: ESP 完整性校验失败")
	// ErrReplay 序号落在反重放窗口之外或已收过。
	ErrReplay = errors.New("ipsec: ESP 重放")
	// ErrTSMismatch 解封后的内层 IP 包地址不在协商的流量选择器内（对端越权）。
	ErrTSMismatch = errors.New("ipsec: 内层地址越出流量选择器")
)

// ConfigError 装载期配置拒绝。
//
// ★必须 fail loud：站点置 failed 并把 Reason 原样回报控制面，让管理员在界面上看到
// 「group24 本实现不支持」，而不是网关默默跳过这条站点、界面上永远 connecting。
type ConfigError struct {
	SiteID string
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("站点 %s 配置不可用：%s（%s）", e.SiteID, e.Reason, e.Field)
}
