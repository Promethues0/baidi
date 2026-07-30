package ipsec

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// 本文件是**装载期拒绝规则的唯一集中地**。
//
// 为什么要有这么一个地方：IPSec 的失败形态几乎全都是「无声的」。配错一个 DH 群、
// 漏填一个 PSK、把网段写成 10.1.2.3/24，协商要么在半路上炸出一句无头无尾的
// 「认证失败」，要么干脆"成功"了但流量不通。这类问题在现场排查一次的代价，远高于
// 在这里多写二十行校验。因此本文件的原则只有一条：
//
//	★ 本轮不支持的一律**明确拒绝并给出人话原因**，绝不静默降级。
//
// 「静默降级」的具体含义是：控制台配了 group24，网关发现不支持就悄悄换成 group14
// 接着跑。结果是界面显示 up、管理员以为跑的是 A、实际跑的是 B——这是本项目历史上
// 最难排查的失败形态（见 CLAUDE.md 里 `apps.resource_id` 与 `-route` 两条）。
//
// 拒绝的产物是 *ConfigError，会被编排层转成 SiteState{State: failed, LastError: 原因}
// 原样回报控制面。所以每条 Reason 都必须**带上管理员实际填的那个值**——
// 「DH 群不支持」等于没说，「phase1.dh=group24 本实现不支持（只支持 …）」才可排障。

// ── 缺省值 ──
//
// Validate 是 *SiteConfig 的指针方法，它**会就地补齐缺省值**（这也是 PLAN §1.5
// 把接收者定成指针的原因）。把「校验」和「补默认」放同一处是有意的：分开写必然
// 出现「校验时看到的是 0、运行时用的是默认值」的错位，那种 bug 只在边界条件下现形。
const (
	DefaultIKELifetime  = 4 * time.Hour    // IKE SA 硬生存期
	DefaultESPLifetime  = 1 * time.Hour    // Child SA 硬生存期
	DefaultDPDDelay     = 30 * time.Second // DPD 探测间隔
	DefaultRetryInitial = 30 * time.Second // 协商失败后的首次重试间隔
	DefaultIKEPort      = 500              // Peer 未带端口时的缺省 IKE 端口
)

// 生存期与探测间隔的合理区间。上下界不是洁癖，两侧都各有一种真实事故：
//   - 太短：ESP 生存期 1 分钟意味着每分钟一次 CREATE_CHILD_SA，隧道全天处于
//     rekey 抖动中，表现为「时通时不通」；
//   - 太长：24 小时以上的 IKE SA 让密钥泄露的暴露窗口无限拉长，且序号/字节
//     阈值先到时的行为路径反而更少被走到。
const (
	MinESPLifetime = 5 * time.Minute
	MinIKELifetime = 10 * time.Minute
	MaxLifetime    = 24 * time.Hour
	MinDPDDelay    = 5 * time.Second
	MaxDPDDelay    = 1 * time.Hour
	MinRetry       = 1 * time.Second
	MaxRetry       = 1 * time.Hour
)

// MaxIDLen ID 数据的长度上限。IDi/IDr 最终要塞进 IKE 载荷，长度字段是 16 位，
// 但真正的约束是可读性：253 是 FQDN 的规范上限，超过它基本可以断定是填错了字段
// （最常见的是把整段证书或一串 JSON 粘进来）。
const MaxIDLen = 253

// RecommendedPSKBytes 推荐的 PSK 最小长度。
//
// ★IKEv2 的 PSK 认证是**可离线爆破**的：抓到一次完整握手后，攻击者能在本地对
// AUTH 载荷做无限次尝试，不受任何在线速率限制。因此短 PSK 的实际强度远低于直觉。
// 这里不把它做成硬性拒绝（会一刀切掉演示环境里既有的短口令），而是提供 WeakPSK
// 让守护进程在日志里明确告警——降级必须看得见，但不该由校验层替管理员做决定。
const RecommendedPSKBytes = 20

// AuthPSK 本轮唯一支持的认证方式。
const AuthPSK = "psk"

// ExtraOptions 是控制面下发了、但 SiteConfig 里**没有对应字段**的开关。
//
// ★这个类型存在的唯一理由，是防止一种特别隐蔽的静默降级：控制面的站点记录里有
// ikeVersion / pqHybrid 两列，而契约层 SiteConfig 刻意不收它们（本实现只有 IKEv2、
// 没有后量子混合）。如果 DTO→SiteConfig 的转换直接把这两个字段丢掉，管理员在界面上
// 选了「IKEv1」或打开了「PQ 混合」，网关会**照常按 IKEv2 无 PQ 跑起来并显示 up**——
// 界面与实际彻底脱节，且没有任何一行报错。
//
// 所以转换层必须把这两个原始值装进 ExtraOptions 交给 ValidateWith 当面拒掉。
// 零值表示「控制面没下发这些字段」，此时跳过相关检查。
type ExtraOptions struct {
	// IKEVersion 控制面原样下发的版本字符串（"ikev2" / "IKEv1" / "2" …）。
	IKEVersion string
	// PqHybrid 后量子混合密钥交换开关。本实现完全没有实现，为 true 必须拒绝。
	PqHybrid bool
}

// ── 已知且明确不支持的取值 ──
//
// 说明分工：算法名→Transform 码点的**权威映射**在 ike.SpecFromPhase，那里对任何
// 不认识的值都会拒绝。本文件不重复那张表（契约层不许 import ike，见 types.go 包注释），
// 只额外拦下这几个「管理员最可能填、且填了以后错误信息最不知所云」的具体取值，
// 给出比「无法识别的 DH 群」更具体的一句话。
//
// 两处都拒才叫收口：这里漏掉的由 ike 兜底，只是原因说得笼统一些。
var unsupportedDH = map[string]string{
	"group1":     "MODP-768，强度早已不足，且本实现未实现 MODP-768",
	"group2":     "MODP-1024，强度不足（Logjam），本实现未实现",
	"group5":     "MODP-1536，本实现未实现",
	"group15":    "MODP-3072，本实现未实现",
	"group16":    "MODP-4096，本实现未实现",
	"group20":    "ECP-384，本实现未实现",
	"group21":    "ECP-521，本实现未实现",
	"group24":    "MODP-2048/256bit-POS，本实现未实现（它与 group14 不是同一个群，别互相替代）",
	"group25":    "ECP-192，本实现未实现",
	"group26":    "ECP-224，本实现未实现",
	"curve25519": "X25519（group31），本实现未实现",
	"group31":    "X25519，本实现未实现",
}

// unsupportedAuth 认证方式。★cert/sm2cert 是控制台既有选项，落地后必须**当面拒绝**，
// 绝不能悄悄退回 PSK：那等于用一把管理员以为不存在的密钥建了条隧道。
var unsupportedAuth = map[string]string{
	"cert":    "证书认证需要 RFC 7427 数字签名 AUTH 与 CERT/CERTREQ 载荷，本轮未实现",
	"rsasig":  "证书认证需要 RFC 7427 数字签名 AUTH 与 CERT/CERTREQ 载荷，本轮未实现",
	"pubkey":  "证书认证需要 RFC 7427 数字签名 AUTH 与 CERT/CERTREQ 载荷，本轮未实现",
	"sm2cert": "国密证书认证（GM/T 0022 血统）与 RFC 7296 不是同一套协议栈，本轮未实现",
	"eap":     "EAP 认证本轮未实现",
	"xauth":   "XAUTH 属 IKEv1 扩展，本实现只有 IKEv2",
}

// Validate 校验站点配置并就地补齐缺省值。返回 *ConfigError（可 errors.As 取 Field）。
//
// 不带 ExtraOptions 的便捷入口：调用方确实没有那两个字段时用它。
// ★DTO 转换层请一律用 ValidateWith，否则 ikeVersion/pqHybrid 会被静默吞掉。
func (c *SiteConfig) Validate() error { return c.ValidateWith(ExtraOptions{}) }

// ValidateWith 同 Validate，并额外拒绝控制面下发的不支持开关。
func (c *SiteConfig) ValidateWith(x ExtraOptions) error {
	// 顺序有讲究：先查"整条站点根本不该跑"的开关（ikeVersion/pqHybrid/auth），
	// 再查地址与身份，最后补缺省值。管理员一次只会看到第一条错误，
	// 所以要让最根本的那条先冒出来——先报"网段含主机位"再报"你选的是 IKEv1"
	// 会让人以为改完网段就能跑。
	if err := c.checkExtra(x); err != nil {
		return err
	}
	if err := c.checkIdentity(); err != nil {
		return err
	}
	if err := c.checkAuth(); err != nil {
		return err
	}
	if err := c.checkNetwork(); err != nil {
		return err
	}
	if err := c.checkCrypto(); err != nil {
		return err
	}
	return c.checkTimers()
}

// reject 造一条带站点 id、字段名与**实际取值**的拒绝。
//
// ★所有拒绝都必须走这里：ConfigError 的 Error() 会拼成
// 「站点 site-sh 配置不可用：<reason>（<field>）」，reason 里不带实际值的话，
// 管理员在界面上只能看到一句正确但无用的话。
func (c *SiteConfig) reject(field, format string, a ...any) error {
	return &ConfigError{SiteID: c.ID, Field: field, Reason: fmt.Sprintf(format, a...)}
}

func (c *SiteConfig) checkExtra(x ExtraOptions) error {
	if v := strings.TrimSpace(x.IKEVersion); v != "" && !isIKEv2(v) {
		return c.reject("ikeVersion",
			"ikeVersion=%q 不支持：本实现只有 IKEv2（RFC 7296 子集），IKEv1 是血统完全不同的另一套协议栈，无法降级兼容", v)
	}
	if x.PqHybrid {
		return c.reject("pqHybrid",
			"pqHybrid=true 不支持：后量子混合密钥交换（RFC 9370 / PPK）本实现完全未实现。"+
				"该开关在控制台是保留字段，打开它不会得到任何后量子保护，因此这里当面拒绝而不是忽略")
	}
	return nil
}

// isIKEv2 宽松地识别"这是 IKEv2"。控制面历史上写过 "ikev2"/"IKEv2"/"2"/"v2" 几种形态，
// 一律接受；其余（含空串以外的任何值）视为管理员真的选了别的版本。
func isIKEv2(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "ikev2", "ike_v2", "ike v2", "v2", "2":
		return true
	}
	return false
}

func (c *SiteConfig) checkIdentity() error {
	if strings.TrimSpace(c.ID) == "" {
		return (&SiteConfig{}).reject("id", "站点 id 为空：无法与控制面的记录对应，也就无法回报状态")
	}
	// ★GatewayID 为空必须拒绝，而不是"任意网关都可以跑"。
	// 多网关部署下，一条无主站点会被每台网关同时拿去建 SA，双方互相 rekey/删除，
	// 表现为隧道每隔几十秒抖一次——而每台网关自己的日志都显示"一切正常"。
	if strings.TrimSpace(c.GatewayID) == "" {
		return c.reject("gatewayId",
			"未指定归属网关：多网关部署下会有两台同时抢建同一条 SA，表现为隧道周期性抖动且两端日志都显示正常")
	}

	for _, f := range []struct {
		field, val string
	}{{"localId", c.LocalID}, {"remoteId", c.RemoteID}} {
		v := strings.TrimSpace(f.val)
		if v == "" {
			return c.reject(f.field, "%s 为空：IKEv2 的 IDi/IDr 是身份匹配的依据，缺了它对端只能报一句「认证失败」", f.field)
		}
		if len(v) > MaxIDLen {
			return c.reject(f.field, "%s 长度 %d 超过上限 %d：这个字段填的是身份标识（如 gw-a.baidi），不是证书或密钥",
				f.field, len(v), MaxIDLen)
		}
		// ★用 IP 形态的 ID 在 NAT 下必挂。
		// 症状：对端看到的源地址是 NAT 后的地址，与 IDi 里写的内网地址对不上，
		// 于是身份匹配失败，而 IKEv2 对认证失败的回复只有一个 AUTHENTICATION_FAILED
		// 码点——管理员拿到的就是一句无头无尾的「认证失败」，根本看不出是 ID 的问题。
		// 因此这里直接在装载期拦掉，而不是等运行时去猜。
		if _, err := netip.ParseAddr(v); err == nil {
			return c.reject(f.field,
				"%s=%q 是 IP 地址形态：NAT 场景下对端看到的是 NAT 后地址，IP 类型 ID 必然匹配失败，"+
					"且失败信息只有一句「认证失败」。请改用 FQDN 形态（如 gw-a.baidi）", f.field, v)
		}
	}
	return nil
}

func (c *SiteConfig) checkAuth() error {
	auth := strings.ToLower(strings.TrimSpace(c.Auth))
	if auth == "" {
		// 空 auth 不默认成 psk：默认成 psk 就意味着控制台上那个"认证方式"下拉框
		// 选什么都一样，界面从此开始骗人。
		return c.reject("auth", "auth 为空：本轮唯一支持的认证方式是 %q，请显式填写（不默认，避免界面选项形同虚设）", AuthPSK)
	}
	if reason, bad := unsupportedAuth[auth]; bad {
		return c.reject("auth",
			"auth=%q 不支持：%s。本轮唯一支持 %q；这里当面拒绝而不是退回 PSK——"+
				"静默退回等于用一把管理员以为不存在的密钥建了条隧道", auth, reason, AuthPSK)
	}
	if auth != AuthPSK {
		return c.reject("auth", "auth=%q 无法识别：本轮唯一支持 %q", auth, AuthPSK)
	}

	// ★空 PSK 是本文件里最重要的一条。
	// prf(PSK, "Key Pad for IKEv2") 对空 PSK 一样能算出结果，两端都空时 AUTH 校验
	// **完全通得过**——隧道会真的建起来、界面真的显示 up、流量真的加密传输，
	// 只是这条隧道的认证强度为零，任何人抓到一个 IKE_SA_INIT 就能冒充对端接进来。
	// 「配错了连不上」是小事故，「配错了连上了」才是真事故。
	if len(c.PSK) == 0 {
		return c.reject("psk",
			"PSK 为空：空 PSK 两端一样能协商成功、界面一样显示 up，但认证强度为零，"+
				"任何人都能冒充对端接进来。这是必须拒绝而不是告警的情形")
	}
	return nil
}

// WeakPSK 报告 PSK 是否短到值得在日志里告警（不构成拒绝）。
// 见 RecommendedPSKBytes 的说明：IKEv2 的 PSK 可被离线爆破，长度就是强度。
func (c *SiteConfig) WeakPSK() bool { return len(c.PSK) > 0 && len(c.PSK) < RecommendedPSKBytes }

func (c *SiteConfig) checkNetwork() error {
	// ── 对端落点 ──
	if !c.Peer.Addr().IsValid() {
		return c.reject("peer", "对端地址无效或为空：网关不会去猜对端在哪（策略权威在控制面）")
	}
	if c.Peer.Addr().IsUnspecified() {
		return c.reject("peer", "对端地址 %s 是通配地址（0.0.0.0/::），不能作为拨号目标", c.Peer.Addr())
	}
	if c.Peer.Addr().IsMulticast() {
		return c.reject("peer", "对端地址 %s 是组播地址，IKE 不能对组播发起协商", c.Peer.Addr())
	}
	if c.Peer.Port() == 0 {
		// 补缺省而不是拒绝：控制台上"对端地址"通常只填 IP，端口留空是常态。
		c.Peer = netip.AddrPortFrom(c.Peer.Addr(), DefaultIKEPort)
	}

	// ── 受保护网段 ──
	for _, f := range []struct {
		field string
		p     netip.Prefix
	}{{"localSubnet", c.LocalSubnet}, {"remoteSubnet", c.RemoteSubnet}} {
		if !f.p.IsValid() {
			return c.reject(f.field, "%s 无效或为空：它就是 TSi/TSr，没有它无从判断哪些流量该进隧道", f.field)
		}
		// ★含主机位的写法（10.1.2.3/24）意图不明确：是想保护整个 /24，还是只保护那一台？
		// 两种理解会产出完全不同的流量选择器，而对端只会回一个 TS_UNACCEPTABLE。
		// 与其替管理员选一个，不如把话说清楚让他改。
		if f.p.Masked() != f.p {
			return c.reject(f.field,
				"%s=%s 含主机位，意图不明确（要保护整段还是那一台？）：请写作 %s（整段）或 %s/%d（单机）",
				f.field, f.p, f.p.Masked(), f.p.Addr(), f.p.Addr().BitLen())
		}
	}
	if c.LocalSubnet.Addr().Is4() != c.RemoteSubnet.Addr().Is4() {
		return c.reject("remoteSubnet",
			"localSubnet=%s 与 remoteSubnet=%s 地址族不同（IPv4/IPv6 混配）：一条 Child SA 只有一对流量选择器，两端必须同族",
			c.LocalSubnet, c.RemoteSubnet)
	}
	// ★两端网段重叠 = 同一个地址既算"本地"又算"对端"。
	// 后果是出向 SPD 把本该走本地的流量塞进隧道（或反之），排查时看到的现象是
	// 「一部分内网地址莫名其妙不通」，而隧道状态一直是 up。
	if c.LocalSubnet.Overlaps(c.RemoteSubnet) {
		return c.reject("remoteSubnet",
			"localSubnet=%s 与 remoteSubnet=%s 重叠：同一地址既算本端又算对端，出向选路必然二义，"+
				"表现为部分内网地址莫名不通而隧道状态一直正常", c.LocalSubnet, c.RemoteSubnet)
	}
	return nil
}

func (c *SiteConfig) checkCrypto() error {
	// suite 只是"放不放行私有码点"的闸门，权威解释在 ike.SpecFromPhase。
	// 这里只拦空值与明显打错的值，避免把 ike 那张表抄第二遍（抄两遍必然有一天不同步）。
	switch strings.ToLower(strings.TrimSpace(c.Suite)) {
	case "", "standard", "gm":
	default:
		return c.reject("suite", "suite=%q 无法识别：只支持 \"standard\"（RFC 码点）与 \"gm\"（白帝私有码点，仅白帝↔白帝互通）", c.Suite)
	}

	// Phase1：IKE SA 必须做 DH，三项都得有。
	if strings.TrimSpace(c.Phase1.Enc) == "" {
		return c.reject("phase1.enc", "phase1.enc 为空：IKE SA 的加密算法没有缺省值，不填就无从构造提案")
	}
	if strings.TrimSpace(c.Phase1.Hash) == "" {
		return c.reject("phase1.hash", "phase1.hash 为空：它同时决定 PRF 与完整性算法，不填 AUTH 无从计算")
	}
	if strings.TrimSpace(c.Phase1.DH) == "" {
		return c.reject("phase1.dh", "phase1.dh 为空：IKE_SA_INIT 必须做一次 DH 交换，没有 DH 群就没有 SKEYSEED")
	}
	if err := c.checkDHName("phase1.dh", c.Phase1.DH); err != nil {
		return err
	}

	// Phase2：ESP 不协商 PRF；DH 只在 PFS 打开时才用。
	if strings.TrimSpace(c.Phase2.Enc) == "" {
		return c.reject("phase2.enc", "phase2.enc 为空：ESP 的加密算法没有缺省值")
	}
	if strings.TrimSpace(c.Phase2.Hash) == "" {
		return c.reject("phase2.hash", "phase2.hash 为空：它决定 ESP 的完整性算法（GCM 类套件下由 ike 侧置 NONE）")
	}
	if c.PFS {
		// ★PFS 打开却不给 DH 群，CREATE_CHILD_SA 就不会带 KE 载荷，
		// 结果是「界面上 PFS 是开的、实际没有前向保密」——又一次静默降级。
		if d := strings.TrimSpace(c.Phase2.DH); d == "" || strings.EqualFold(d, "none") {
			return c.reject("phase2.dh",
				"pfs=true 但 phase2.dh=%q：PFS 靠 CREATE_CHILD_SA 里的 KE 载荷实现，没有 DH 群就没有前向保密，"+
					"而界面上 PFS 开关仍是开的——这正是必须拒绝的静默降级", c.Phase2.DH)
		}
	}
	if d := strings.TrimSpace(c.Phase2.DH); d != "" && !strings.EqualFold(d, "none") {
		if err := c.checkDHName("phase2.dh", d); err != nil {
			return err
		}
	}
	return nil
}

func (c *SiteConfig) checkDHName(field, v string) error {
	key := strings.ToLower(strings.TrimSpace(v))
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, " ", "")
	if reason, bad := unsupportedDH[key]; bad {
		return c.reject(field,
			"%s=%q 不支持：%s。本实现支持 group14(MODP-2048) / group19(ECP-256) / sm2p256（后者仅 suite=gm）",
			field, v, reason)
	}
	return nil
}

func (c *SiteConfig) checkTimers() error {
	if c.IKELifetime == 0 {
		c.IKELifetime = DefaultIKELifetime
	}
	if c.ESPLifetime == 0 {
		c.ESPLifetime = DefaultESPLifetime
	}
	if c.DPDDelay == 0 {
		c.DPDDelay = DefaultDPDDelay
	}
	if c.RetryInitial == 0 {
		c.RetryInitial = DefaultRetryInitial
	}

	if c.IKELifetime < MinIKELifetime || c.IKELifetime > MaxLifetime {
		return c.reject("ikeLifetime", "ikeLifetime=%s 越界：允许区间 [%s, %s]（过短会让隧道全天处于重协商抖动，过长会拉长密钥泄露的暴露窗口）",
			c.IKELifetime, MinIKELifetime, MaxLifetime)
	}
	if c.ESPLifetime < MinESPLifetime || c.ESPLifetime > MaxLifetime {
		return c.reject("espLifetime", "espLifetime=%s 越界：允许区间 [%s, %s]",
			c.ESPLifetime, MinESPLifetime, MaxLifetime)
	}
	// ★Child SA 不能比它的父 IKE SA 活得久。
	// 反过来配的后果：ESP 还在传数据，父 IKE SA 已到期被拆，于是既没法 rekey 也没法
	// 发 Delete，隧道就那么静静地停在"上一秒还在通"的状态——两端计数器都不再增长，
	// 但状态显示依旧是 up。
	if c.ESPLifetime >= c.IKELifetime {
		return c.reject("espLifetime",
			"espLifetime=%s 不小于 ikeLifetime=%s：Child SA 比父 IKE SA 活得久时，父 SA 先到期，"+
				"既无法重协商也发不出 Delete，隧道会静默停摆而状态仍显示 up",
			c.ESPLifetime, c.IKELifetime)
	}
	if c.DPDDelay < MinDPDDelay || c.DPDDelay > MaxDPDDelay {
		return c.reject("dpdDelay", "dpdDelay=%s 越界：允许区间 [%s, %s]", c.DPDDelay, MinDPDDelay, MaxDPDDelay)
	}
	if c.RetryInitial < MinRetry || c.RetryInitial > MaxRetry {
		return c.reject("retryInitial", "retryInitial=%s 越界：允许区间 [%s, %s]", c.RetryInitial, MinRetry, MaxRetry)
	}
	return nil
}
