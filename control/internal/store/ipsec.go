package store

import "context"

// IpsecPhase IKE 协商的一相 / 二相加密套件。
//
// 三个字段是控制台填进来的**自由字符串**，由网关侧 ike.SpecFromPhase 映射成
// IKEv2 Transform ID。映射不出来就在装载期拒绝并把原因回报控制面，绝不静默降级——
// 静默降级造成的「控制台配了 SM4-GCM、实际跑了 AES128」是无报错的假成功，
// 排障时没有任何线索指向这里。
//
// ★取值必须落在网关实现的集合内，否则站点永远 failed：
//   - Enc：AES256-GCM / AES256-CBC / SM4-GCM / SM4-CBC
//   - Hash：SHA256 / SM3
//   - DH：group14（MODP-2048）/ group19（ECP-256）/ sm2p256（国密曲线，私有码点）
type IpsecPhase struct {
	Enc  string `json:"enc"`  // AES256-GCM / AES256-CBC / SM4-GCM / SM4-CBC
	Hash string `json:"hash"` // SHA256 / SM3
	DH   string `json:"dh"`   // group14 / group19 / sm2p256
}

// IpsecSite 一条站点到站点的 IPSec 隧道配置（PRD 第 17 章 IPSec VPN 组网）。
//
// ★本结构体现在只承载**配置**（管理员意图），运行态一律去 ipsec_sa_state 表读。
// 二者混住一张表时，`status` 一列同时表达「管理员想让它开」和「它现在真的开着」，
// 于是「点了启用但协商失败」在界面上与「已建立」长得一模一样——正是本项目
// `apps.resource_id` 那种静默失效形态的翻版（UI 变绿、实际不通、全程无报错）。
//
// ★PSK 原文**不在这个结构体里**，物理分表存 ipsec_secrets（加密落盘）。
// 分表不是洁癖：GET /api/v1/ipsec 历史上曾漏掉 requireAdmin，只要密钥与配置同结构体，
// 任何一次忘加鉴权的复制粘贴都会把它一起泄出去。分表让「泄露」需要显式写代码。
type IpsecSite struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// GatewayID 承载这条站点的 IPSec 网关 id（= 该网关 mTLS 客户端证书的 CN，形如 ipsec-1）。
	// mTLS 下发端点按它做最小披露：成都网关不该知道上海网关的对端地址与密钥。
	//
	// ★为空表示「未指派网关」——没有任何网关会承载它。这在协议上是安全的（fail-closed），
	// 但对用户是静默失效：站点永远停在 connecting 且无报错。故 API 层对
	// 「enabled=true 且 gatewayId 为空」显式回一条 configWarning，别把它藏起来。
	GatewayID string `json:"gatewayId"`

	// Enabled 管理意图（toggle 只改这一个字段）。与运行态彻底解耦：
	// Enabled=true 只等于「已下发启用意图」，不等于隧道已建立。
	Enabled bool `json:"enabled"`

	Peer         string `json:"peer"`         // 对端网关公网地址（IKE 落点，端口缺省 500）
	LocalSubnet  string `json:"localSubnet"`  // TSi：本端受保护网段
	RemoteSubnet string `json:"remoteSubnet"` // TSr：对端受保护网段

	// LocalID / RemoteID 是 IKEv2 的 IDi / IDr。
	// ★必须用 FQDN 形态（如 hq.baidi）：NAT 场景下对端看到的是 NAT 后地址，
	// 用 IP 类型 ID 做身份匹配必挂，而失败信息只有一句「认证失败」，
	// 与另外五种 AUTH 失败根因完全无法区分。
	LocalID  string `json:"localId"`
	RemoteID string `json:"remoteId"`

	IkeVersion string     `json:"ikeVersion"` // IKEv2（强制）
	Auth       string     `json:"auth"`       // 本轮只支持 psk；cert/sm2cert 在网关装载期被拒
	Suite      string     `json:"suite"`      // standard（RFC 码点） | gm（白帝私有码点，只白帝↔白帝互通）
	Phase1     IpsecPhase `json:"phase1"`     // IKE SA 提案
	Phase2     IpsecPhase `json:"phase2"`     // Child SA（ESP）提案
	Pfs        bool       `json:"pfs"`        // CREATE_CHILD_SA 是否带 KE
	PqHybrid   bool       `json:"pqHybrid"`   // ML-KEM 后量子混合：字段保留，本轮网关未实现

	// PSKVersion 预共享密钥版本号，每次改 PSK 递增。
	// 网关侧策略里只带版本号，本地版本落后才去 GET …/{id}/psk 单取一次——
	// 让密钥不必随每 15s 的策略轮询重传，减少它出现在网络上的次数。
	PSKVersion int `json:"pskVersion"`

	// PeerNATPort 对端的 UDP 封装口（ESP 落点）。0 = 与本端 -natt-port 相同（生产恒为 4500）。
	//
	// ★只在对端用了非标准封装端口时才需要填。不填而对端确实改了的症状是
	// 「隧道显示 up、协商结果正常、字节数恒为 0、全程无报错」——因为 IKEv2
	// 没有通告对端封装端口的机制（RFC 3948 把它定死为 4500），实现只能按
	// 对称假设推算。详见 gateway/internal/ipsec/ike/nat.go 的 espEndpoints。
	PeerNATPort int `json:"peerNatPort,omitempty"`

	// HasPSK / PSKFingerprint 是**只写不读**语义下的唯一回显：
	// 管理员能确认「配过了」并核对两端是不是同一把，但拿不到原文。
	// 回显原文没有任何操作价值（配错了重设即可），只有泄露面。
	HasPSK         bool   `json:"hasPsk"`
	PSKFingerprint string `json:"pskFingerprint,omitempty"` // 前 8 位十六进制（见 secret.Box.Fingerprint）

	// ── 以下四列已冻结（Deprecated）──
	//
	// 它们是「运行态与配置混表」时代的遗物：status 由 toggle 直接写成 'up'、
	// rx_bytes/tx_bytes 是 2026-06 灌进库就再没变过的种子常量、last_up 同一列并存
	// "今天 08:02" 与 "2026-07-29 14:02" 两种不兼容格式（只有从没人真正消费过它，
	// 才可能长期不被发现）。
	//
	// 现在 SQLite 读路径**不再读这三列**，API 层把它们由 ipsec_sa_state 的实测值现算，
	// 纯粹为了不打碎尚未升级的控制台。新代码一律用 Enabled + SA 运行态，别再碰这里。
	Status  string `json:"status"`  // Deprecated：由 API 层按实测运行态现算
	RxBytes int64  `json:"rxBytes"` // Deprecated：同上
	TxBytes int64  `json:"txBytes"` // Deprecated：同上
	LastUp  string `json:"lastUp"`  // Deprecated：同上

	// 对象库引用（可选）：本端 / 对端网段引用地址对象（kind=cidr/ip/range），
	// 支撑「定义一次、多处复用」与对象库「被引用」反查；网段值仍是权威配置。
	LocalRef  string `json:"localRef,omitempty"`  // 地址对象 id → localSubnet
	RemoteRef string `json:"remoteRef,omitempty"` // 地址对象 id → remoteSubnet
}

// Ipsec 返回演示用的 IPSec 站点清单（内存种子；SQLiteStore 覆盖为落库版）。
//
// ★种子在本轮被整体修正过，两类改动都不是美化：
//
//  1. **套件改成网关真支持的组合**。原种子 site-sh 用 auth=cert、site-gz 用
//     auth=sm2cert + DH=group24 + PqHybrid=true——证书认证与 group24 本轮都不实现，
//     后量子混合只有字段没有实现。这些站点一旦被启用就会在装载期被拒、永久 failed。
//     **留一条永远红的站点比改种子更不诚实**：它把「本实现不支持」伪装成「对端有问题」。
//     现在三条种子分别覆盖 GCM+ECDH / 国密私有码点 / CBC+MODP 三条真实可跑的路径。
//
//  2. **假流量常量清零**（原来是 184_320_512 / 53_477_376 这种精确到字节的数字）。
//     运行态现在由网关实测回报，种子里放假数字就是在骗自己：控制台上那句
//     「已传 184 MB」从来不是统计值，是 2026-06 播种时搬进库的常量。
//
// Enabled 一律 false：种子对端是 RFC 5737 文档地址（203.0.113.0/24），永远不会应答。
// 默认启用只会得到三条 failed。管理员改成真实对端再手动启用，才是诚实的默认。
func (m *Memory) Ipsec(_ context.Context) ([]IpsecSite, error) {
	return []IpsecSite{
		{
			ID: "site-sh", Name: "上海分支", GatewayID: "ipsec-1", Enabled: false,
			Peer: "203.0.113.21", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.40.0.0/16",
			LocalID: "hq.baidi", RemoteID: "sh.baidi",
			IkeVersion: "IKEv2", Auth: "psk", Suite: "standard",
			Phase1: IpsecPhase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
			Phase2: IpsecPhase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
			Pfs:    true, PqHybrid: false,
		},
		{
			// 国密站点：SM4-GCM / HMAC-SM3 / sm2p256v1 走 IANA 私有使用段码点（1024+）。
			// 只承诺白帝↔白帝互通，与 GM/T 0022（IKEv1 血统 + 数字信封）无关，
			// 对外不可称「国密 IPSec」。PqHybrid 由 true 改 false——网关没有实现它。
			ID: "site-gz", Name: "广州分支（国密）", GatewayID: "ipsec-1", Enabled: false,
			Peer: "203.0.113.55", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.50.0.0/16",
			LocalID: "hq.baidi", RemoteID: "gz.baidi",
			IkeVersion: "IKEv2", Auth: "psk", Suite: "gm",
			Phase1: IpsecPhase{Enc: "SM4-GCM", Hash: "SM3", DH: "sm2p256"},
			Phase2: IpsecPhase{Enc: "SM4-GCM", Hash: "SM3", DH: "sm2p256"},
			Pfs:    true, PqHybrid: false,
		},
		{
			// CBC + HMAC + MODP-2048：与上面两条走完全不同的代码路径
			// （分组模式的 IV/填充/ICV 处理 vs AEAD），种子里各留一条才能真被走到。
			ID: "site-cd", Name: "成都分支", GatewayID: "ipsec-1", Enabled: false,
			Peer: "203.0.113.88", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.60.0.0/16",
			LocalID: "hq.baidi", RemoteID: "cd.baidi",
			IkeVersion: "IKEv2", Auth: "psk", Suite: "standard",
			Phase1: IpsecPhase{Enc: "AES256-CBC", Hash: "SHA256", DH: "group14"},
			Phase2: IpsecPhase{Enc: "AES256-CBC", Hash: "SHA256", DH: "group14"},
			Pfs:    false, PqHybrid: false,
		},
	}, nil
}
