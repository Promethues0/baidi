// Package authpolicy 认证策略的**判定引擎**：由账号 + 请求上下文算出「这次登录要不要
// 二次认证、因为什么」。纯函数、无 IO——取数在 api 层（见 api/authpolicy.go），
// 与 internal/risk（终端环境判定）同一套路：判定权全在控制面，且判定本身可单测。
//
// # 这个包为什么存在
//
// auth_policies 这张表长期是全项目最典型的 config-only：有表、有落库、控制台可编辑，
// 但全库对 store.AuthPolicies() 的唯一调用是把它读出来给页面看。真正决定"要不要二次
// 认证"的是一行写死在 webauthn.go 里的启发式——`账号名以 ext 开头或含「外包」`。
// 于是出现这种局面：管理员在界面上关掉「弱密码增强」，登录行为一点变化都没有；
// 而一个叫 external.zhang 的正式员工被强制 MFA，谁也说不清是哪条策略干的。
//
// 现在每条**能判**的规则都在这里真实求值，**判不了**的两条被显式冻结（见 Capabilities）：
// 保存接口拒绝开启、控制台置灰并说明原因。这个包里没有"占位实现"。
//
// # 两条不可动摇的语义
//
//  1. **策略只能加强，不能削弱**。豁免规则（授信终端 / 可信网络）压制的只是本包算出的
//     策略性增强要求；「该账号已注册 passkey → 强制断言」在 api.secondFactor 里排在本包
//     之前求值，任何策略配置都碰不到它。用户自己注册了强认证因子，管理员的一条网段
//     豁免不该把它降级——那会让 passkey 变成"有时候要、有时候不要"，且不留痕迹。
//  2. **判不了就不判**。没有 IP 地理库就不做"异地登录"，没有域校验能力就不做"Windows 域"。
//     接一条永远命中不了（或凭空乱判）的规则，比没有这条规则更坏。
package authpolicy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// 规则 key：Capabilities、保存校验、前端置灰三处共用同一份标识，避免各写一份字符串。
const (
	KeyAlways         = "enhance.always"
	KeyWeakPwd        = "enhance.weakPwd"
	KeyOffHours       = "enhance.offHours"
	KeyGeoAnomaly     = "enhance.geoAnomaly"
	KeyTrustedDevice  = "exempt.trustedDevice"
	KeyTrustedNetwork = "exempt.trustedNetwork"
	KeyWinDomain      = "exempt.winDomain"
)

// 工作时段缺省值（策略未配时使用）。
const (
	defaultWorkStart = "09:00"
	defaultWorkEnd   = "18:00"
)

// Capability 一条规则的能力声明：能不能判、判据是什么、判不了是为什么。
//
// ★这份清单同时驱动三处，必须只有一个来源：
//   - 控制台把 Available=false 的开关置灰并显示 Reason（不是静默无效）；
//   - 保存接口拒绝开启 Available=false 的规则（前端被绕过也拦得住）；
//   - 控制台在每条规则旁显示 Effect，让管理员看得见"命中判据到底是什么"。
type Capability struct {
	Key       string `json:"key"`
	Kind      string `json:"kind"`  // enhance（命中即要求二次认证）| exempt（命中即豁免）
	Label     string `json:"label"` // 中文名，与控制台文案一致
	Available bool   `json:"available"`
	Effect    string `json:"effect"` // 生效说明：判据是什么、由谁提供
	Reason    string `json:"reason"` // 不可用原因（Available=false 时非空）
}

// Capabilities 返回全部规则的能力声明（顺序稳定，供前端按序渲染）。
func Capabilities() []Capability {
	return []Capability{
		{Key: KeyAlways, Kind: "enhance", Label: "范围内一律二次认证", Available: true,
			Effect: "命中本策略适用范围（组织含子树 / 用户组）的账号一律要求二次认证。取代了此前写死的「账号名以 ext 开头或含外包」启发式。"},
		{Key: KeyWeakPwd, Kind: "enhance", Label: "弱密码", Available: true,
			Effect: "判据为账号的口令强度标记（改密 / 建号时按明文判定并落库）。标记为「未知」的存量账号不命中——不可判定不等于不合规。"},
		{Key: KeyOffHours, Kind: "enhance", Label: "非工作时段", Available: true,
			Effect: "按服务器时间与本策略配置的工作日 + 工作时段判定，落在时段之外即命中。"},
		{Key: KeyGeoAnomaly, Kind: "enhance", Label: "异地登录", Available: false,
			Effect: "需要把源 IP 解析成地理位置，再与该账号的常用登录地比对。",
			Reason: "未接入 IP 地理库，白帝当前判不出「异地」。接一个假判据会给出错误的安全感，因此该开关不可用而不是静默无效。"},
		{Key: KeyTrustedDevice, Kind: "exempt", Label: "授信终端", Available: true,
			Effect: "判据为客户端登录时上报的设备指纹：该指纹曾以本账号上报过终端环境（posture），且最新判定为通过。★指纹由客户端自报、不是秘密，故只用于降低二次认证要求，绝不放宽授权。"},
		{Key: KeyTrustedNetwork, Kind: "exempt", Label: "可信网络", Available: true,
			Effect: "判据为请求真实源 IP（按 BAIDI_TRUSTED_PROXIES 信任边界取得）落在本策略配置的网段列表内。开启时必须至少配一个网段。"},
		{Key: KeyWinDomain, Kind: "exempt", Label: "Windows 域环境", Available: false,
			Effect: "需要校验终端确实加入了某个 AD 域（机器票据或域内证书）。",
			Reason: "白帝没有域校验能力：终端上报的六个基线键里没有域信息，也不校验机器票据。判不了就不判，该开关不可用。"},
	}
}

// MethodCapability 二次认证**方式**的能力声明（与 Capability 同一条纪律：
// 置灰与保存校验必须同源，都由这一份产出）。
// wave7 行动 4：此前抽屉里 sms/totp/radius/cert/http 全部可选、全部不生效——
// TOTP 真实现后，其余四种显式冻结而不是继续静默无效。
type MethodCapability struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Available bool   `json:"available"`
	Effect    string `json:"effect,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// SecondaryMethods 二次认证方式清单。
func SecondaryMethods() []MethodCapability {
	return []MethodCapability{
		{Key: "totp", Label: "TOTP 动态口令", Available: true,
			Effect: "RFC 6238 标准动态验证码，Google/微软 Authenticator、1Password 等通用。" +
				"用户在门户「安全设置」注册并确认后，登录即强制要求验证码（与 passkey 同级；" +
				"两者都注册时优先走抗钓鱼的 passkey）。不依赖可注册域名，裸 IP 部署也可用。"},
		{Key: "sms", Label: "短信", Available: false,
			Reason: "登录链路没有短信发码/验码实现。消息通道里的 sms 只是一次 webhook 转发" +
				"（用于告警通知），承担不了认证因子。"},
		{Key: "radius", Label: "RADIUS 动态令牌", Available: false,
			Reason: "RADIUS 协议未实现（认证源保存同样拒绝 radius 类型）。"},
		{Key: "cert", Label: "证书 / USB-Key", Available: false,
			Reason: "白帝没有终端证书/USB-Key 的校验能力。"},
		{Key: "http", Label: "HTTP(S) 令牌", Available: false,
			Reason: "无 HTTP 令牌服务对接实现。"},
	}
}

// MethodOf 按 key 取二次认证方式声明。
func MethodOf(key string) (MethodCapability, bool) {
	for _, m := range SecondaryMethods() {
		if m.Key == key {
			return m, true
		}
	}
	return MethodCapability{}, false
}

// CapabilityOf 按 key 取能力声明。
func CapabilityOf(key string) (Capability, bool) {
	for _, c := range Capabilities() {
		if c.Key == key {
			return c, true
		}
	}
	return Capability{}, false
}

// Input 一次登录决策的全部输入。取数由调用方完成，本包不做任何 IO。
type Input struct {
	Account string // 规范化账号（令牌主体口径）
	// Directory 该账号本次是被哪个用户目录认出来的：local 或外部认证源的 kind（ldap/ad/oidc）。
	// 它由登录链路当场得知（本地哈希命中 = local；外部源命中 = 该源 kind），
	// 不是猜的——策略按目录分组，猜错就会挑到另一个目录的策略。
	Directory string
	Now       time.Time
	// ClientIP 请求真实源 IP（api.clientIP 的结果，已过 X-Forwarded-For 信任边界）。
	// 无效地址 = 取不到来源，可信网络豁免一律不命中（fail-closed）。
	ClientIP netip.Addr
	// DeviceID 客户端自报的设备指纹（登录请求体 deviceId）；空 = 未知设备（浏览器登录常态）。
	DeviceID string
	// DeviceKnown 该指纹在本账号名下的设备台账里且状态为 **trusted**（store.trusted_devices）；
	// DeviceVerdict 是该设备最新的 posture 判定（allow / degrade / gray / block）。
	// 授信终端豁免要求两者同时成立：一台已批准但当前不合规的终端不叫"授信"，
	// 一台合规但尚未批准（pending）的终端也不叫"授信"。
	//
	// ★口径与敲门准入闸（api.deviceAdmissionGate）同源，都是 trusted_devices 的 status。
	// 此前这里的判据是"曾上报过 posture 即算授信"——那意味着任何终端只要上报一次
	// 就自动获得免二次认证的资格，管理员在终端管理页做的批准/吊销对它毫无影响。
	DeviceKnown   bool
	DeviceVerdict string
	// PwStrength 口令强度标记 auth.PwWeak | auth.PwStrong | auth.PwUnknown。
	PwStrength string
	// Subjects 组织/用户组 → 账号的展开索引（store.SubjectIndex）。策略适用范围靠它匹配，
	// 与资源授权的组织/组两维共用同一处子树展开——不另写一份。
	Subjects store.SubjectIndex
}

// Decision 一次决策的可解释结论。Reasons / ExemptReasons 直接进审计与前端提示，
// 所以措辞必须是"已经发生的事实"，不能是推测。
type Decision struct {
	PolicyID   string `json:"policyId"`
	PolicyName string `json:"policyName"`
	RequireMFA bool   `json:"requireMfa"`
	// Methods 这条策略声明的可接受二次认证方式（AuthPolicy.Secondary 原样带出）。
	//
	// ★它**不决定用哪个因子**（那由账号已注册的认证器决定，passkey > TOTP）。
	// 它唯一的执行语义是：非空时，legacy 演示验证码回落对这条策略覆盖的人**不成立**——
	// 「要求二次认证」不能由一个写死在代码里的 123456 来满足。见 api.secondFactor。
	Methods       []string `json:"methods"`
	Reasons       []string `json:"reasons"`       // 命中的全部条件（基础档 + 风险档，按此顺序）
	Exempted      bool     `json:"exempted"`      // 命中了条件、但被豁免（只可能是基础档）
	ExemptReasons []string `json:"exemptReasons"` // 命中的豁免条件
	// ExemptOverridden 豁免条件确实命中了，但因风险条件同时命中而**不生效**（FR-AUTH-21）。
	// ★必须单独表达：审计与提示要说得出「你确实在可信网络里，但口令是弱口令，仍要二次认证」，
	// 否则用户会觉得豁免坏了、管理员会觉得策略配错了。
	ExemptOverridden bool `json:"exemptOverridden,omitempty"`
	// RiskReasons 否决了豁免的那些风险条件（ExemptOverridden 为真时非空）。
	RiskReasons []string `json:"riskReasons,omitempty"`
}

// Summary 供审计与前端提示的一句话（已发生的事实，不含推测）。
func (d Decision) Summary() string {
	switch {
	case d.RequireMFA && d.ExemptOverridden:
		// 这一句是 FR-AUTH-21 在审计里的样子：豁免命中过、但被风险条件否决。
		return "命中「" + strings.Join(d.RiskReasons, "、") + "」，虽同时命中「" +
			strings.Join(d.ExemptReasons, "、") + "」但风险条件下豁免不生效，仍要求二次认证（策略「" +
			d.PolicyName + "」）"
	case d.RequireMFA:
		return "因「" + strings.Join(d.Reasons, "、") + "」要求二次认证（策略「" + d.PolicyName + "」）"
	case d.Exempted:
		return "命中「" + strings.Join(d.Reasons, "、") + "」，但因「" + strings.Join(d.ExemptReasons, "、") +
			"」豁免二次认证（策略「" + d.PolicyName + "」）"
	default:
		return ""
	}
}

// Evaluate 挑出适用策略并求值。无适用策略时返回零值（不要求二次认证）——
// 基线行为与本特性上线前一致：策略关掉/删掉，登录就回到"只看有没有 passkey"。
func Evaluate(pols []store.AuthPolicy, in Input) Decision {
	p, ok := Match(pols, in)
	if !ok {
		return Decision{}
	}
	d := Decision{PolicyID: p.ID, PolicyName: p.Name, Methods: trimAll(p.Secondary),
		Reasons: []string{}, ExemptReasons: []string{}}

	// ★两类条件必须分开收集，**豁免只作用于基础那一档**（FR-AUTH-21，7.6 验收原文：
	//   「When 登录命中条件（即便同时命中豁免规则），Then 在主认证之后强制完成一次
	//   增强认证方可上线」）。PRD 把它们建模成两件事：
	//     FR-AUTH-17 免二次认证 —— 授信终端 / 特定网络区域，免掉的是**基础**那一次；
	//     FR-AUTH-20 增强认证   —— 弱口令 / 异常时段等**风险已经出现**时强制追加。
	//
	//   改造前两者被塌缩成一个 RequireMFA 布尔，且豁免命中即 return —— 方向完全反了：
	//   正好在风险出现的那一刻，一条网段豁免把二次认证整个取消。出厂那条 AD 默认策略
	//   （ap-ad-default）恰好同时开着 TrustedNetwork(10.8.0.0/16) 与 WeakPwd+OffHours，
	//   于是任何 AD 账号只要源 IP 落在该网段，哪怕口令被判弱、哪怕凌晨三点登录，
	//   也一律单因素放行 —— 而管理员在策略卡上同时看到「弱口令增强」与「可信网络免二次」
	//   两个已启用标签，合理预期是前者更强。
	var baseReasons, riskReasons []string
	if p.Enhance.Always {
		baseReasons = append(baseReasons, "策略范围内账号一律二次认证")
	}
	// unknown 不命中：口令是在强度判定存在之前设的，判不了不等于弱。
	if p.Enhance.WeakPwd && in.PwStrength == auth.PwWeak {
		riskReasons = append(riskReasons, "账号口令为弱口令")
	}
	if p.Enhance.OffHours && offHours(p.Enhance, in.Now) {
		riskReasons = append(riskReasons, "非工作时段登录（"+workWindowText(p.Enhance)+"）")
	}
	// GeoAnomaly 不在这里求值：它是冻结能力，保存接口不允许开启，
	// 存量库里为 true 的行也已在迁移回填里清掉（backfillAuthPolicyScope）。
	d.Reasons = append(append([]string{}, baseReasons...), riskReasons...)
	if len(d.Reasons) == 0 {
		return d
	}

	if p.Exempt.TrustedDevice && in.DeviceKnown && in.DeviceVerdict == "allow" {
		d.ExemptReasons = append(d.ExemptReasons, "授信终端 "+shortDevice(in.DeviceID))
	}
	if p.Exempt.TrustedNetwork {
		if cidr, hit := matchNetwork(p.Exempt.Networks, in.ClientIP); hit {
			d.ExemptReasons = append(d.ExemptReasons, "可信网络 "+cidr)
		}
	}
	// WinDomain 同样是冻结能力，不参与求值。
	if len(d.ExemptReasons) > 0 {
		if len(riskReasons) == 0 {
			// 只命中基础档 → 豁免生效（FR-AUTH-17 的本意）。
			d.Exempted = true
			return d
		}
		// ★风险条件已命中：豁免**不生效**，但必须记下它曾命中——
		//   审计与前端提示要说得出「你确实在可信网络里，但因为口令是弱口令仍要二次认证」，
		//   否则用户会觉得豁免坏了、管理员会觉得策略配错了。
		d.ExemptOverridden = true
		d.RiskReasons = riskReasons
	}
	d.RequireMFA = true
	return d
}

// Match 挑出对该账号生效的策略：同目录、已启用的策略中，
// **先看适用范围命中者**（按优先级升序，小者先匹配，同优先级按 id 定序保证结果稳定），
// 都不命中再回落到该目录的默认策略。
//
// ★非默认策略的适用范围（ScopeOrgs/ScopeGroups）为空时匹配不到任何人：保存接口拒绝
// 这种配置，存量库里若有这样的行，控制台会显示「未绑定适用范围，不会命中任何账号」，
// 而不是让它看起来在生效。
func Match(pols []store.AuthPolicy, in Input) (store.AuthPolicy, bool) {
	var scoped []store.AuthPolicy
	var fallback store.AuthPolicy
	haveFallback := false
	for _, p := range pols {
		if !p.Enabled || p.Directory != in.Directory {
			continue
		}
		if p.IsDefault {
			if !haveFallback || p.Priority < fallback.Priority {
				fallback, haveFallback = p, true
			}
			continue
		}
		if covers(p, in) {
			scoped = append(scoped, p)
		}
	}
	if len(scoped) > 0 {
		sort.Slice(scoped, func(i, j int) bool {
			if scoped[i].Priority != scoped[j].Priority {
				return scoped[i].Priority < scoped[j].Priority
			}
			return scoped[i].ID < scoped[j].ID
		})
		return scoped[0], true
	}
	return fallback, haveFallback
}

// covers 报告策略的适用范围是否覆盖该账号（组织含子树 / 用户组）。
// 判定本体在 store.SubjectIndex.Covers 一处——认证策略、安全基线、资源授权
// 对"谁在这个组织里"必须是同一个答案。
func covers(p store.AuthPolicy, in Input) bool {
	return in.Subjects.Covers(in.Account, p.ScopeOrgs, p.ScopeGroups)
}

// matchNetwork 报告 ip 是否落在任一网段内，并回传命中的那一条（写进审计与提示）。
// 解析不了的网段条目跳过——保存接口已经拦过一次，这里再宽容一次是为了不让一条
// 脏数据把整条豁免变成"看起来没配"。
func matchNetwork(cidrs []string, ip netip.Addr) (string, bool) {
	if !ip.IsValid() {
		return "", false
	}
	ip = ip.Unmap()
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		if p.Masked().Contains(ip) {
			return c, true
		}
	}
	return "", false
}

// offHours 报告 now 是否落在工作时段之外（含非工作日）。
// 跨零点的时段（如 22:00-06:00）按"跨天"解释，这是排班场景的常见写法。
func offHours(e store.EnhanceRule, now time.Time) bool {
	days := e.WorkDays
	if len(days) == 0 {
		days = []int{1, 2, 3, 4, 5}
	}
	wd := int(now.Weekday())
	if wd == 0 {
		wd = 7 // time.Sunday=0 → ISO 的 7
	}
	onDay := false
	for _, d := range days {
		if d == wd {
			onDay = true
			break
		}
	}
	if !onDay {
		return true
	}
	start, ok1 := parseHM(orDefault(e.WorkStart, defaultWorkStart))
	end, ok2 := parseHM(orDefault(e.WorkEnd, defaultWorkEnd))
	if !ok1 || !ok2 || start == end {
		// 时段配错（保存接口已校验，这里是兜底）：宁可不判，也不要凭一个坏配置抬高认证要求。
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	if start < end {
		return cur < start || cur >= end
	}
	// 跨零点：工作时段是 [start,24:00) ∪ [00:00,end)
	return cur < start && cur >= end
}

func workWindowText(e store.EnhanceRule) string {
	days := e.WorkDays
	if len(days) == 0 {
		days = []int{1, 2, 3, 4, 5}
	}
	names := []string{"一", "二", "三", "四", "五", "六", "日"}
	var ds []string
	for _, d := range days {
		if d >= 1 && d <= 7 {
			ds = append(ds, "周"+names[d-1])
		}
	}
	return strings.Join(ds, "/") + " " + orDefault(e.WorkStart, defaultWorkStart) + "-" + orDefault(e.WorkEnd, defaultWorkEnd)
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// parseHM 解析 HH:MM 为「当天第几分钟」。
func parseHM(s string) (int, bool) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// shortDevice 截短设备指纹用于展示（指纹本身不敏感，但整串太长会淹没审计文案）。
func shortDevice(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12] + "…"
}

// Validate 保存一条策略前的语义校验。
//
// ★这里拦下的每一种形态，都是"存进去也不会生效"的配置。历史上这张表允许它们
// 静默入库，于是控制台看起来配得好好的、登录行为一点没变。
func Validate(p store.AuthPolicy) error {
	if p.Enhance.GeoAnomaly {
		c, _ := CapabilityOf(KeyGeoAnomaly)
		return fmt.Errorf("「%s」不可启用：%s", c.Label, c.Reason)
	}
	if p.Exempt.WinDomain {
		c, _ := CapabilityOf(KeyWinDomain)
		return fmt.Errorf("「%s」不可启用：%s", c.Label, c.Reason)
	}
	// 二次认证方式：未实现的方式拒绝入库（与冻结开关同一条纪律）。
	for _, m := range trimAll(p.Secondary) {
		mc, known := MethodOf(m)
		if !known {
			return fmt.Errorf("未知的二次认证方式「%s」", m)
		}
		if !mc.Available {
			return fmt.Errorf("「%s」不可选用：%s", mc.Label, mc.Reason)
		}
	}
	if p.Exempt.TrustedNetwork && len(trimAll(p.Exempt.Networks)) == 0 {
		return fmt.Errorf("启用「可信网络」豁免必须至少配置一个网段（CIDR），否则这条豁免永远不会命中")
	}
	for _, c := range p.Exempt.Networks {
		if strings.TrimSpace(c) == "" {
			continue
		}
		if _, err := netip.ParsePrefix(strings.TrimSpace(c)); err != nil {
			return fmt.Errorf("可信网段「%s」不是合法 CIDR（如 10.8.0.0/16）", c)
		}
	}
	if p.Enhance.OffHours {
		start, ok1 := parseHM(orDefault(p.Enhance.WorkStart, defaultWorkStart))
		end, ok2 := parseHM(orDefault(p.Enhance.WorkEnd, defaultWorkEnd))
		if !ok1 || !ok2 {
			return fmt.Errorf("工作时段须为 HH:MM 格式（如 09:00 / 18:30）")
		}
		if start == end {
			return fmt.Errorf("工作时段起止不能相同（那样「非工作时段」要么恒真要么恒假）")
		}
		for _, d := range p.Enhance.WorkDays {
			if d < 1 || d > 7 {
				return fmt.Errorf("工作日取值须为 1-7（1=周一 … 7=周日），收到 %d", d)
			}
		}
	}
	// 非默认策略必须绑定适用范围，否则它匹配不到任何账号——那就是一条"配了不生效"的策略。
	if !p.IsDefault && len(trimAll(p.ScopeOrgs)) == 0 && len(trimAll(p.ScopeGroups)) == 0 {
		return fmt.Errorf("非默认策略必须绑定适用范围（组织或用户组），否则它匹配不到任何账号")
	}
	return nil
}

func trimAll(ss []string) []string {
	out := []string{}
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
