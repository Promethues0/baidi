package store

import (
	"context"
	"strings"
)

// ── 认证策略（PRD 第 1 章 FR-INTRO-07/08、第 7 章 FR-AUTH-12，P0）──
//
// 认证策略按用户目录分组，声明可接受的二次认证方式，
// 并叠加自适应认证（免二次认证豁免、增强认证条件）。
//
// ★这张表曾经是全项目最典型的 config-only：有表、有落库、安全中心 UI 可编辑，
// 但全库对 AuthPolicies() 的唯一调用是"读出来给页面看"，登录链路一行不读；
// 真实的二次认证触发条件是 webauthn.go 里 `账号名以 ext 开头或含「外包」` 的字符串启发式。
// 现在 Enhance / Exempt 的每一条**可判定**规则都由 internal/authpolicy.Evaluate 在登录
// 链路上真实求值（见该包顶部说明），判不了的两条（GeoAnomaly / WinDomain）被显式冻结：
// 保存时拒绝开启、控制台置灰并给出原因——而不是留一个"配了不生效"的开关。

// ── 二次认证方式（AuthPolicy.Secondary）──
//
// ★这里曾经是 `PC` / `Mobile` 两个 AuthMethodSet，每个里面还有一个 Primary
// （主认证方式：local|ad|ldap|radius|oauth|sms|cert）。三样东西一起摘掉了
// （wave8 行动 13-②），因为它们**结构上就是同义反复或判不了**，不是"还没接线"：
//
//   - Primary：Evaluate/Match 的第一行就是 `p.Directory != in.Directory`——一条策略
//     只作用于**已经被该目录认出来的人**。对 directory=ad 的策略说"主认证用 ad"什么也没说；
//     说"主认证用 cert"更不可能生效——这个人已经拿 AD 口令进来了，策略才轮到匹配。
//     后端对它唯一的触碰是一处非空校验，零消费方；而页面把它渲染成策略属性，
//     管理员把 PC 端改成「证书 / USB-Key」（意图 = 关掉口令登录）后保存回 200、
//     卡片明晃晃写着证书认证，实际口令登录一次不落照常成功。
//   - **PC / 移动端分开配**这一维同样判不了：桌面端、移动端、浏览器三端走的是
//     **同一个** /portal/login，请求里没有任何端标识，loginCtx 里也没有这一维。
//     两栏并排显示会让人以为"移动端可以配得更严"，而两栏的内容对登录链路毫无区别。
//
// 「这个人该由哪个目录认」的真实决定点有两处，都已真实现：认证源配置本身，
// 以及登录时的认证域路由（wave8 行动 12，命中即只问该源）。

// ExemptRule 自适应 · 免二次认证的豁免触发条件。
//
// ★豁免只能压制**策略驱动**的增强认证，永远压不掉「该账号已注册 passkey → 强制断言」：
// 那条是账号自己选择的强认证，策略只能加强、不能削弱（见 api.secondFactor 的求值顺序，
// 以及 authpolicy_test.go 里钉住这条的用例）。
type ExemptRule struct {
	// TrustedDevice 授信终端豁免。判据：该指纹在本账号名下的设备台账（trusted_devices）里
	// 且状态为 **trusted**，且该设备最新 posture 判定为 allow。指纹由客户端在登录时
	// 随请求带上（deviceId）。授信状态与敲门准入闸（api.deviceAdmissionGate）同源。
	//
	// ★诚实边界：设备指纹不是秘密，客户端自报、可被伪造。所以它只用于**降低二次认证
	// 要求**，绝不用于放宽任何授权——授权闸始终在网关侧 resource.Authorize。
	TrustedDevice bool `json:"trustedDevice"`
	// TrustedNetwork 可信网络豁免。判据：请求源 IP（按 BAIDI_TRUSTED_PROXIES 信任边界
	// 取到的真实来源，见 api.clientIP）落在 Networks 任一网段内。
	TrustedNetwork bool `json:"trustedNetwork"`
	// Networks 可信网段 CIDR 列表。TrustedNetwork 开启时必须非空——
	// 空列表意味着这条豁免永远不可能命中，那正是"配了不生效"，保存时直接拒绝。
	Networks []string `json:"networks"`
	// WinDomain Windows 域环境豁免。**已冻结，不可开启**：白帝没有任何校验
	// "这台终端确实在某个 AD 域内"的能力（posture 六个基线键里没有域信息，
	// 也没有机器票据校验）。接一个假的判据比不接更坏——它会在真实域外终端上放行。
	WinDomain bool `json:"winDomain"`
}

// EnhanceRule 自适应 · 增强认证的强制触发条件（命中且未被豁免则要求二次认证）。
type EnhanceRule struct {
	// Always 该策略范围内的账号一律要求二次认证。
	// 它取代了此前写死在代码里的 riskyAccount()（账号名以 ext 开头或含「外包」）——
	// 同一条业务规则现在由管理员按**组织 / 用户组**配置（见 AuthPolicy.ScopeOrgs/ScopeGroups），
	// 而不是靠字符串匹配猜测谁是外包。
	Always bool `json:"always"`
	// WeakPwd 弱口令账号要求二次认证。判据：users.pw_strength = weak
	// （在改密/建号那一刻判定并落库，见 auth.PasswordStrength）。
	// unknown（存量行，明文不可得）**不命中**——不可判定不等于不合规。
	WeakPwd bool `json:"weakPwd"`
	// OffHours 非工作时段登录要求二次认证。判据：服务器时间不在 [WorkStart, WorkEnd)
	// 或不在 WorkDays 之内。
	OffHours  bool   `json:"offHours"`
	WorkStart string `json:"workStart"` // 工作时段起 HH:MM（空 = 09:00）
	WorkEnd   string `json:"workEnd"`   // 工作时段止 HH:MM（空 = 18:00）
	// WorkDays 工作日（1=周一 … 7=周日）。空 = 周一至周五。
	WorkDays []int `json:"workDays"`
	// GeoAnomaly 异地登录要求二次认证。**已冻结，不可开启**：白帝没有接入任何
	// IP 地理库，"异地"无从判起。接一条永远命中不了（或凭空乱判）的规则，
	// 等于给管理员一个假的安全感。
	GeoAnomaly bool `json:"geoAnomaly"`
}

// AuthPolicy 一条认证策略。
type AuthPolicy struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Directory string `json:"directory"` // 所属用户目录（认证源 key：local | ad | ldap | oidc）
	IsDefault bool   `json:"isDefault"` // 是否该目录的默认策略（自动生成，不可删除）
	Scope     string `json:"scope"`     // 适用范围的**文字说明**（展示用，不参与匹配）
	Priority  int    `json:"priority"`  // 优先级，数字小者先匹配；冲突以最小者为准
	Enabled   bool   `json:"enabled"`
	// Secondary 可接受的二次认证方式（可多选 / 可空）。可用集由
	// authpolicy.SecondaryMethods 声明：当前只有 totp 真实现；sms/radius/cert/http
	// 无登录链路实现，保存时拒绝、控制台置灰（与 GeoAnomaly/WinDomain 同一条冻结纪律）。
	//
	// ★**真实消费方**（否则它就是又一个装饰）：策略判定要二次认证、而该账号既没有
	// passkey 也没有 TOTP 时，列了方式的策略**不接受 legacy 演示验证码回落**，
	// 一律回「请先注册」。也就是说选中 totp 的语义是「这条策略覆盖的人，
	// 二次认证必须是真的第二因子，123456 不算」——裸 IP 演示站正是这条唯一生效的地方。
	// 留空 = 不额外约束（RP 未配置时仍可走 legacy 回落）。
	//
	// **它不决定"用哪个因子"**：那由账号已注册的认证器决定（passkey > TOTP，
	// 见 api.secondFactor 的求值顺序），策略只能加强不能削弱。
	Secondary []string `json:"secondary"`
	// ScopeOrgs / ScopeGroups 才是**真正参与匹配**的适用范围：组织（含子树）与用户组。
	// 展开走 store.SubjectIndex——与资源授权的组织/组两维共用同一处子树展开实现，
	// 不另写一份（另写必然分叉，分叉后"策略界面上圈到了人、登录时没生效"无处可查）。
	// 非默认策略两者皆空 = 匹配不到任何账号，保存时拒绝。
	ScopeOrgs   []string    `json:"scopeOrgs"`
	ScopeGroups []string    `json:"scopeGroups"`
	Exempt      ExemptRule  `json:"exempt"`  // 免二次认证豁免条件
	Enhance     EnhanceRule `json:"enhance"` // 增强认证触发条件
	// ★这里曾经有 AuthzApps（"默认授权应用"，自由文本）。已摘除（wave8 行动 13-③）：
	// 全仓零执行方，而策略卡把空值渲染成「不授权」、种子预置「默认授权全部应用」——
	// 两者都在暗示这条策略决定了能访问哪些应用。授权的唯一真相是**资源侧的主体清单**
	// （resources.allow_users/allow_groups/allow_orgs + JIT 授予），认证策略只管"怎么证明你是你"。
	// 数据库列 authz_apps 保留但恒写空串：删列要重建表，而这个字段本就没人读。
}

// ★已删除的字段：OneClick（一键上线：保存认证票据、下次免认证）。
// 它要求一整套设备绑定的长效免认证票据（签发 / 存储 / 吊销 / 与强制下线联动），
// 本轮不做；留着一个开关而背后什么都没有，就是这张表此前最被诟病的形态。
// 表里的 one_click 列因此冻结（不再读写），旧库直接可用，见 sqlite.go 建表注释。

// AuthPolicies 返回演示用的认证策略（内存种子；SQLiteStore 覆盖为落库版）。
//
// ★种子里出现的每一个开关都必须是**当前能真实生效**的：冻结的 GeoAnomaly / WinDomain
// 一律为 false，TrustedNetwork 必配网段。否则首启的库里就躺着几条"配了不生效"的策略。
func (m *Memory) AuthPolicies(_ context.Context) ([]AuthPolicy, error) {
	return []AuthPolicy{
		// 总部 AD 域
		{
			ID: "ap-ad-default", Name: "AD 域 · 默认策略", Directory: "ad", IsDefault: true,
			Scope: "总部 AD 域 · 全体用户", Priority: 100, Enabled: true,
			// Secondary 只列真实现的方式（totp）：sms/radius/cert/http 均无登录链路实现，
			// 已按能力声明冻结（authpolicy.SecondaryMethods），种子里不许出现。
			Secondary: []string{"totp"},
			// 授信终端 + 内网网段两条豁免与下面的增强条件配套：内网的合规终端照常单因素，
			// 换台没登记过的机器、或跑到办公网之外，才被抬到二次认证。
			Exempt: ExemptRule{TrustedDevice: true, TrustedNetwork: true, Networks: []string{"10.8.0.0/16"}},
			Enhance: EnhanceRule{
				WeakPwd: true, OffHours: true,
				WorkStart: "09:00", WorkEnd: "19:00", WorkDays: []int{1, 2, 3, 4, 5},
			},
			ScopeOrgs: []string{}, ScopeGroups: []string{},
		},
		// 本地用户目录。
		//
		// ★这条默认策略**刻意不开任何增强规则**：它覆盖包括 admin 在内的全部本地账号，
		// 而这些规则现在是真生效的——种子里开一个「非工作时段增强」，就等于让在线演示站
		// 每天 19:00 之后所有人都被抬到二次认证（演示口令 admin/baidi@123 直接走不通）。
		// 种子的职责是给出可用的起点，不是替管理员做加严决策。
		{
			ID: "ap-local-default", Name: "本地目录 · 默认策略", Directory: "local", IsDefault: true,
			Scope: "本地用户目录 · 全体用户", Priority: 100, Enabled: true,
			Secondary: []string{"totp"},
			Exempt:    ExemptRule{Networks: []string{}},
			Enhance:   EnhanceRule{WorkStart: "09:00", WorkEnd: "19:00", WorkDays: []int{1, 2, 3, 4, 5}},
			ScopeOrgs: []string{}, ScopeGroups: []string{},
		},
		// 外部协作 / 外包：此前是代码里的 riskyAccount() 字符串启发式，现在是一条按组织生效的策略。
		{
			ID: "ap-ext-strict", Name: "外包人员 · 一律二次认证", Directory: "local", IsDefault: false,
			Scope: "外包人员（组织，含子部门）", Priority: 10, Enabled: true,
			Secondary: []string{"totp"},
			// 外包账号不给任何豁免：这正是把它单列一条策略的意义。
			Exempt:  ExemptRule{Networks: []string{}},
			Enhance: EnhanceRule{Always: true, WeakPwd: true},
			// "ext" 是种子组织树里「外包人员」部门的 id（见 Memory.Users 的 OrgTree）。
			ScopeOrgs: []string{"ext"}, ScopeGroups: []string{},
		},
	}, nil
}

// AuthMethodSetLegacy 是 auth_policies 里 `pc` / `mobile` 两列的**落库形状**。
//
// ★保留它只为读写那两列（删列要重建表）。语义上两列已合并成 AuthPolicy.Secondary：
// 读时并集、写时 pc 存全量 / mobile 存空。这样旧版本控制面读到的仍是一份可用配置
// （它会把 pc 那份当 PC 端的），而不是一条二次认证方式为空的策略。
type AuthMethodSetLegacy struct {
	Secondary []string `json:"secondary"`
}

// mergeMethods 合并两端的方式清单（去重、保序）。
func mergeMethods(a, b []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, list := range [][]string{a, b} {
		for _, m := range list {
			m = strings.TrimSpace(m)
			if m == "" || seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
