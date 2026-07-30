package store

import (
	"context"
	"errors"
)

// ErrIpsecSiteNotFound 目标站点不存在（启停 / 写 PSK 时用于回 404 而不是静默成功）。
// ★静默成功是这里最坏的行为：管理员以为 PSK 已经改了，实际什么都没写，
// 下一次协商仍用旧密钥，症状是「明明改了密钥两端还是通的」或反过来。
var ErrIpsecSiteNotFound = errors.New("ipsec site not found")

// ── IPSec 运行态与密钥材料（配置 / 运行态 / 密钥三分家）──
//
// 三类数据被刻意拆成三张表，边界与「谁是权威」一一对应：
//
//	ipsec_sites      配置    管理员权威，网关只读
//	ipsec_sa_state   运行态  网关权威，管理员写不进（15s 全量覆写）
//	ipsec_secrets    密钥    只写不读，加密落盘，只经 mTLS 口下发给owner 网关
//
// 混在一张表里会同时踩两个坑：①「管理员想让它开」与「它现在真的开着」共用一列，
// 于是协商失败在界面上与已建立无法区分；② 密钥与配置同结构体，一次忘加
// requireAdmin 的复制粘贴就能把密钥整表读走（这条洞在本项目真实发生过）。

// IpsecSAState 一条站点隧道的**实测**运行态，由承载它的网关经 mTLS 回报。
//
// ★字段全部来自 IKE 状态机与 ESP 计数器，没有任何一项是配置回显。
// 回显配置正是旧实现「toggle 一下界面就显示 up」的根源——那条审计里
// 「建立 IPSec 隧道 site-sh · ok」断言了一个从未发生的事实。
type IpsecSAState struct {
	SiteID string `json:"siteId"`
	// GatewayID 回报者。主键含它，是为了让「两台网关抢同一条站点」在界面上可见：
	// 双方各建一条 SA、互相 rekey/删除，表现为隧道抖动，而单主键会让第二台悄悄覆盖第一台。
	GatewayID string `json:"gatewayId"`

	// State 五态：down（管理员未启用）/ connecting / up / rekeying / failed。
	// ★down 是管理意图、failed 是故障，二者必须分开——只有三态时，
	// 「没开」与「开了但连不上」在界面上完全一样，用户永远不知道为什么连不上。
	State string `json:"state"`

	// SPI 是「真的协商过」最硬的可视证据：单端伪造不出与对端交叉相等的一对 SPI
	// （本端入向 == 对端出向）。自检脚本据此排除「控制面自己把 state 改成 up」。
	IKESPIi     string `json:"ikeSpiI"`     // 16 hex（8 字节）
	IKESPIr     string `json:"ikeSpiR"`     // 16 hex
	ChildSPIIn  uint32 `json:"childSpiIn"`  // 本端入向（= 对端出向）
	ChildSPIOut uint32 `json:"childSpiOut"` // 本端出向（= 对端入向）

	// ESP 层真实字节/包计数。UI 上的流量数字只允许来自这里。
	RxBytes    int64 `json:"rxBytes"`
	TxBytes    int64 `json:"txBytes"`
	PacketsIn  int64 `json:"packetsIn"`
	PacketsOut int64 `json:"packetsOut"`

	// NegotiatedProposal 实际协商定型的套件（如 "AES256-GCM16/PRF-HMAC-SHA256/ECP256"）。
	// 与配置意图分列展示：配 SM4-GCM 而实际降到别的套件，是「以为走了国密其实没走」
	// 的经典形态，只有两边都存才能在界面上对比出来。
	NegotiatedProposal string `json:"negotiatedProposal"`

	EstablishedAt int64 `json:"establishedAt"` // Unix 秒，0=未建立（不再是 "今天 08:02" 这种无法重算的中文相对串）
	RekeyAt       int64 `json:"rekeyAt"`       // 软生存期到点 → 界面上的「SA 剩余寿命」倒计时
	ExpiresAt     int64 `json:"expiresAt"`     // 硬生存期到点
	ReportedAt    int64 `json:"reportedAt"`    // 本行回报时刻（界面据此标注「数据延迟 ≤15s」）

	// LastError 可读中文原因，如「对端 203.0.113.88:500 无响应（7 次重传超时）」。
	// ★把 NO_PROPOSAL_CHOSEN 这类码点直接甩给用户等于没说，必须带上「谁不接受什么」。
	LastError   string `json:"lastError"`
	LastErrorAt int64  `json:"lastErrorAt"`
}

// IpsecSecret 一条站点 PSK 的**密文行**。明文只在 API 层短暂存在，绝不进 store。
//
// ★Cipher 是 AES-256-GCM 的输出，AAD 绑定 SiteID。不绑 AAD 的后果很具体：
// 把 A 站点的密文行直接剪贴到 B 站点，B 就用上了 A 的密钥——一次不需要任何密码学
// 突破的密钥转移，只要能写库就能做到。绑了 AAD 后剪贴过去解不开，会显式报错。
type IpsecSecret struct {
	SiteID string
	Alg    string // 恒为 "AES-256-GCM"；留字段是为了将来换算法时旧行还能被认出来
	Nonce  []byte // 12 字节，每次写入重新随机（GCM 的 nonce 复用是灾难性的）
	Cipher []byte // 密文 ‖ tag
	// Fingerprint PSK 的**带密钥**指纹（HMAC-SHA256(masterKey, psk) 的十六进制）。
	// ★刻意不用裸 SHA-256(psk)：PSK 可能是管理员手输的低熵口令，裸哈希的前缀
	// 足以离线爆破还原原文；HMAC 让没有密钥文件的人拿到指纹也无从下手。
	// 不掺 SiteID 是有意的——运维要靠「两端指纹相同」核对是否配了同一把密钥。
	Fingerprint string
	Version     int // 与 ipsec_sites.psk_version 同源（那里是权威，这里只是回读便利）
	UpdatedAt   string
}

// IpsecStore 是 IPSec 组网所需的全部读写能力（仅 *SQLiteStore 实现）。
//
// ★刻意**不并进** store.Store / store.Writer：那两个接口是全模块共享契约，
// 每个 handler 都拿得到。IPSec 这组方法里有「读 PSK 密文」这种只该被两个
// handler 调用的能力，单独成契约后「谁能碰密钥」在类型层面就是可枚举的，
// 而不是随 Store 一起发给全体。api 侧用类型断言取它（见 Server.ipsecStore）。
type IpsecStore interface {
	// IpsecSitesForGateway 只返回 gateway_id 精确等于给定 id 的站点（最小披露）。
	// 多网关部署时，成都网关不该知道上海网关的对端公网地址与内网网段。
	IpsecSitesForGateway(ctx context.Context, gatewayID string) ([]IpsecSite, error)

	SaveIpsecSite(ctx context.Context, s IpsecSite) (IpsecSite, error)
	// DeleteIpsecSite 连带删除该站点的密钥行与运行态行。
	// 不连带删的症状：站点在界面上消失了，ipsec_sa_state 里那行最后一次 up 的残影
	// 却永远留着，下次建同 id 的站点会「一建好就显示已连接」。
	DeleteIpsecSite(ctx context.Context, id string) error
	// SetIpsecEnabled 只改管理意图，不碰任何运行态列。返回改后的站点（未找到 → ErrIpsecSiteNotFound）。
	SetIpsecEnabled(ctx context.Context, id string, enabled bool) (IpsecSite, error)

	// SaveIpsecSecret 写入密文并把 ipsec_sites.psk_version 自增，返回新版本号（单事务）。
	// 版本号是网关判断「要不要重新取密钥」的唯一依据，与密文必须同进同退：
	// 版本涨了密文没换 → 网关取到旧密钥且认为是新的，AUTH 失败且原因指向对端。
	SaveIpsecSecret(ctx context.Context, sec IpsecSecret) (int, error)
	// IpsecSecret 取一条站点的密文行（解密在 api 层用 secret.Box 完成）。
	IpsecSecret(ctx context.Context, siteID string) (IpsecSecret, bool, error)

	IpsecSAStates(ctx context.Context) ([]IpsecSAState, error)
	// ReplaceIpsecSAStates 以**全量覆写**替换某网关名下的所有运行态行。
	// 全量而非增量：与 resource.Replace 同一姿态，对账比增量幂等得多，
	// 且网关不再回报的站点行会自然消失——增量更新会让被删站点的最后状态永久留存。
	ReplaceIpsecSAStates(ctx context.Context, gatewayID string, states []IpsecSAState) error
}
