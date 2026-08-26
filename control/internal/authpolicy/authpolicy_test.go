package authpolicy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// 一个"什么都不开"的本地默认策略：基线行为的参照物。
func defaultPolicy() store.AuthPolicy {
	return store.AuthPolicy{
		ID: "ap-local-default", Name: "本地默认", Directory: "local", IsDefault: true,
		Priority: 100, Enabled: true,
	}
}

// 作用于「外包人员」组织的加严策略。
func scopedPolicy(mut func(*store.AuthPolicy)) store.AuthPolicy {
	p := store.AuthPolicy{
		ID: "ap-ext", Name: "外包加严", Directory: "local", Priority: 10, Enabled: true,
		ScopeOrgs: []string{"ext"},
	}
	if mut != nil {
		mut(&p)
	}
	return p
}

// subjects 构造一份展开索引：ext 组织下有 ext.zhou，g-vendor 组里有 wang.qiang。
func subjects() store.SubjectIndex {
	return store.SubjectIndex{
		OrgAccounts:   map[string][]string{"ext": {"ext.zhou"}},
		GroupAccounts: map[string][]string{"g-vendor": {"wang.qiang"}},
	}
}

// workday 2026-08-10 是周一；09:00-18:00 为默认工作时段。
func at(hhmm string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", "2026-08-10 "+hhmm)
	if err != nil {
		panic(err)
	}
	return t
}

func baseInput(account string) Input {
	return Input{
		Account: account, Directory: "local", Now: at("10:00"),
		ClientIP: netip.MustParseAddr("203.0.113.7"), PwStrength: auth.PwStrong,
		Subjects: subjects(),
	}
}

// ── 增强规则：命中 → 要求 MFA；未命中 → 不要求 ──

func TestAlwaysRule(t *testing.T) {
	pols := []store.AuthPolicy{defaultPolicy(), scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always = true
	})}

	d := Evaluate(pols, baseInput("ext.zhou"))
	if !d.RequireMFA || d.PolicyID != "ap-ext" {
		t.Fatalf("范围内账号应要求二次认证：%+v", d)
	}
	if len(d.Reasons) != 1 || !strings.Contains(d.Summary(), "外包加严") {
		t.Fatalf("原因/摘要要能写进审计：%+v / %s", d.Reasons, d.Summary())
	}

	// 范围外的账号落到默认策略（没开任何增强规则）→ 不要求。
	if d := Evaluate(pols, baseInput("li.fang")); d.RequireMFA || d.PolicyID != "ap-local-default" {
		t.Fatalf("范围外账号不应被加严：%+v", d)
	}
}

func TestAlwaysRuleByGroup(t *testing.T) {
	p := scopedPolicy(func(p *store.AuthPolicy) {
		p.ScopeOrgs, p.ScopeGroups = nil, []string{"g-vendor"}
		p.Enhance.Always = true
	})
	if d := Evaluate([]store.AuthPolicy{defaultPolicy(), p}, baseInput("wang.qiang")); !d.RequireMFA {
		t.Fatal("用户组范围内的账号应被加严")
	}
	if d := Evaluate([]store.AuthPolicy{defaultPolicy(), p}, baseInput("ext.zhou")); d.RequireMFA {
		t.Fatal("不在该用户组的账号不应被加严")
	}
}

func TestWeakPwdRule(t *testing.T) {
	pols := []store.AuthPolicy{defaultPolicy(), scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.WeakPwd = true
	})}
	in := baseInput("ext.zhou")

	in.PwStrength = auth.PwWeak
	if d := Evaluate(pols, in); !d.RequireMFA {
		t.Fatal("弱口令账号应要求二次认证")
	}
	in.PwStrength = auth.PwStrong
	if d := Evaluate(pols, in); d.RequireMFA {
		t.Fatal("强口令账号不应要求二次认证")
	}
	// ★unknown 是"这条口令在强度判定存在之前就设好了"，不可判定 ≠ 不合规。
	in.PwStrength = auth.PwUnknown
	if d := Evaluate(pols, in); d.RequireMFA {
		t.Fatal("强度未知不应被当成弱口令")
	}
}

func TestOffHoursRule(t *testing.T) {
	pols := []store.AuthPolicy{defaultPolicy(), scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.OffHours = true
		p.Enhance.WorkStart, p.Enhance.WorkEnd = "09:00", "18:00"
		p.Enhance.WorkDays = []int{1, 2, 3, 4, 5}
	})}
	cases := []struct {
		when string
		want bool
	}{
		{"09:00", false}, // 起点算工作时段内
		{"12:30", false},
		{"18:00", true}, // 终点起算非工作时段
		{"23:30", true},
		{"05:00", true},
	}
	for _, c := range cases {
		in := baseInput("ext.zhou")
		in.Now = at(c.when)
		if got := Evaluate(pols, in).RequireMFA; got != c.want {
			t.Errorf("%s 应 requireMFA=%v", c.when, c.want)
		}
	}
	// 周日（2026-08-09 是周日）不在工作日内 → 命中
	in := baseInput("ext.zhou")
	in.Now = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	if !Evaluate(pols, in).RequireMFA {
		t.Error("非工作日应命中非工作时段")
	}
}

// 跨零点排班（22:00-06:00 为工作时段）：白天才是"非工作时段"。
func TestOffHoursCrossMidnight(t *testing.T) {
	pols := []store.AuthPolicy{scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.OffHours = true
		p.Enhance.WorkStart, p.Enhance.WorkEnd = "22:00", "06:00"
	})}
	for when, want := range map[string]bool{"23:00": false, "02:00": false, "12:00": true} {
		in := baseInput("ext.zhou")
		in.Now = at(when)
		if got := Evaluate(pols, in).RequireMFA; got != want {
			t.Errorf("跨零点时段 %s 应 requireMFA=%v", when, want)
		}
	}
}

// ── 豁免规则：命中时不要求 MFA，但决策里如实记下"命中了什么、被什么豁免" ──

func TestTrustedNetworkExempt(t *testing.T) {
	pols := []store.AuthPolicy{scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always = true
		p.Exempt.TrustedNetwork = true
		p.Exempt.Networks = []string{"10.8.0.0/16"}
	})}

	in := baseInput("ext.zhou")
	in.ClientIP = netip.MustParseAddr("10.8.2.31")
	d := Evaluate(pols, in)
	if d.RequireMFA || !d.Exempted {
		t.Fatalf("内网来源应被豁免：%+v", d)
	}
	if !strings.Contains(d.Summary(), "10.8.0.0/16") {
		t.Fatalf("豁免摘要应指出命中的网段：%s", d.Summary())
	}

	in.ClientIP = netip.MustParseAddr("203.0.113.7")
	if d := Evaluate(pols, in); !d.RequireMFA {
		t.Fatal("网段外来源不应被豁免")
	}
	// 源 IP 取不到（无效地址）→ 不给豁免，fail-closed。
	in.ClientIP = netip.Addr{}
	if d := Evaluate(pols, in); !d.RequireMFA {
		t.Fatal("取不到源 IP 时不应给豁免")
	}
}

func TestTrustedDeviceExempt(t *testing.T) {
	pols := []store.AuthPolicy{scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always = true
		p.Exempt.TrustedDevice = true
	})}
	in := baseInput("ext.zhou")
	in.DeviceID, in.DeviceKnown, in.DeviceVerdict = "FP-MAC-001", true, "allow"
	if d := Evaluate(pols, in); d.RequireMFA || !d.Exempted {
		t.Fatalf("已登记且合规的终端应被豁免：%+v", d)
	}
	// 已登记但终端不合规 → 不叫"授信"
	in.DeviceVerdict = "block"
	if d := Evaluate(pols, in); !d.RequireMFA {
		t.Fatal("终端不合规不应享受授信终端豁免")
	}
	// 从未上报过的设备（浏览器登录常态）→ 不给豁免
	in.DeviceKnown, in.DeviceVerdict, in.DeviceID = false, "", ""
	if d := Evaluate(pols, in); !d.RequireMFA {
		t.Fatal("未知设备不应享受授信终端豁免")
	}
}

// 豁免只在确实命中了增强条件时才有意义：没命中就什么都不该发生（不该记一条"豁免"）。
func TestExemptWithoutEnhanceIsNoop(t *testing.T) {
	pols := []store.AuthPolicy{scopedPolicy(func(p *store.AuthPolicy) {
		p.Exempt.TrustedNetwork = true
		p.Exempt.Networks = []string{"10.8.0.0/16"}
	})}
	in := baseInput("ext.zhou")
	in.ClientIP = netip.MustParseAddr("10.8.2.31")
	if d := Evaluate(pols, in); d.RequireMFA || d.Exempted || d.Summary() != "" {
		t.Fatalf("未命中增强条件时不该产生任何判定：%+v", d)
	}
}

// ── 策略选取 ──

func TestDisabledPolicyFallsBackToBaseline(t *testing.T) {
	pols := []store.AuthPolicy{defaultPolicy(), scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always = true
		p.Enabled = false
	})}
	if d := Evaluate(pols, baseInput("ext.zhou")); d.RequireMFA || d.PolicyID != "ap-local-default" {
		t.Fatalf("策略停用后应回到基线：%+v", d)
	}
	// 连默认策略都没有 → 零决策，行为与本特性上线前一致
	if d := Evaluate(nil, baseInput("ext.zhou")); d.RequireMFA || d.PolicyID != "" {
		t.Fatalf("无策略时应无判定：%+v", d)
	}
}

func TestDirectoryIsolation(t *testing.T) {
	p := scopedPolicy(func(p *store.AuthPolicy) {
		p.Directory = "ad"
		p.Enhance.Always = true
	})
	if d := Evaluate([]store.AuthPolicy{defaultPolicy(), p}, baseInput("ext.zhou")); d.RequireMFA {
		t.Fatal("别的用户目录的策略不该套到本地账号头上")
	}
}

func TestPriorityFirstMatchWins(t *testing.T) {
	lo := scopedPolicy(func(p *store.AuthPolicy) { p.ID, p.Priority, p.Enhance.Always = "ap-lo", 5, true })
	hi := scopedPolicy(func(p *store.AuthPolicy) { p.ID, p.Priority = "ap-hi", 50 })
	if d := Evaluate([]store.AuthPolicy{hi, lo, defaultPolicy()}, baseInput("ext.zhou")); d.PolicyID != "ap-lo" {
		t.Fatalf("优先级小者先匹配，取到的却是 %s", d.PolicyID)
	}
	// 未绑定适用范围的非默认策略匹配不到任何人（保存接口也会拒绝这种配置）
	orphan := store.AuthPolicy{ID: "ap-orphan", Directory: "local", Priority: 1, Enabled: true, Enhance: store.EnhanceRule{Always: true}}
	if d := Evaluate([]store.AuthPolicy{orphan, defaultPolicy()}, baseInput("ext.zhou")); d.PolicyID != "ap-local-default" {
		t.Fatalf("没绑定范围的策略不该命中任何账号，却取到 %s", d.PolicyID)
	}
}

// ── 冻结能力：判不了的规则既不求值、也存不进去 ──

func TestFrozenCapabilitiesNeverEvaluated(t *testing.T) {
	for _, key := range []string{KeyGeoAnomaly, KeyWinDomain} {
		c, ok := CapabilityOf(key)
		if !ok || c.Available {
			t.Fatalf("%s 应被声明为不可用", key)
		}
		if c.Reason == "" {
			t.Fatalf("%s 不可用必须给出原因（控制台要显示它）", key)
		}
	}
	// 即便库里被人为塞进 true，也不会产生任何判定（求值侧根本不看这两个字段）。
	p := scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.GeoAnomaly = true
		p.Exempt.WinDomain = true
	})
	if d := Evaluate([]store.AuthPolicy{p}, baseInput("ext.zhou")); d.RequireMFA || d.Exempted {
		t.Fatalf("冻结规则不该参与求值：%+v", d)
	}
}

func TestCapabilitiesAllDocumented(t *testing.T) {
	for _, c := range Capabilities() {
		if c.Label == "" || c.Effect == "" {
			t.Errorf("%s 缺少中文名或生效说明（控制台要按它渲染）", c.Key)
		}
		if c.Kind != "enhance" && c.Kind != "exempt" {
			t.Errorf("%s 的 kind 非法：%s", c.Key, c.Kind)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := scopedPolicy(func(p *store.AuthPolicy) { p.Enhance.Always = true })
	if err := Validate(ok); err != nil {
		t.Fatalf("合法策略不该被拒：%v", err)
	}
	if err := Validate(defaultPolicy()); err != nil {
		t.Fatalf("默认策略无需绑定范围：%v", err)
	}

	bad := []struct {
		name string
		p    store.AuthPolicy
		want string
	}{
		{"异地登录不可开", scopedPolicy(func(p *store.AuthPolicy) { p.Enhance.GeoAnomaly = true }), "IP 地理库"},
		{"Windows 域不可开", scopedPolicy(func(p *store.AuthPolicy) { p.Exempt.WinDomain = true }), "域校验"},
		{"可信网络必须配网段", scopedPolicy(func(p *store.AuthPolicy) { p.Exempt.TrustedNetwork = true }), "至少配置一个网段"},
		{"网段须合法", scopedPolicy(func(p *store.AuthPolicy) {
			p.Exempt.TrustedNetwork, p.Exempt.Networks = true, []string{"10.8.0.1"}
		}), "合法 CIDR"},
		{"非默认策略须绑范围", store.AuthPolicy{ID: "x", Directory: "local"}, "必须绑定适用范围"},
		{"工作时段格式", scopedPolicy(func(p *store.AuthPolicy) {
			p.Enhance.OffHours, p.Enhance.WorkStart = true, "9点"
		}), "HH:MM"},
		{"工作时段起止相同", scopedPolicy(func(p *store.AuthPolicy) {
			p.Enhance.OffHours, p.Enhance.WorkStart, p.Enhance.WorkEnd = true, "09:00", "09:00"
		}), "不能相同"},
		{"工作日取值", scopedPolicy(func(p *store.AuthPolicy) {
			p.Enhance.OffHours, p.Enhance.WorkDays = true, []int{0}
		}), "1-7"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			err := Validate(c.p)
			if err == nil {
				t.Fatal("应被拒绝")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("拒绝原因应说清问题，got %q want 含 %q", err.Error(), c.want)
			}
		})
	}
}

// FR-AUTH-21：**同时命中豁免与增强条件时仍需做增强认证**。
//
// PRD 7.6 验收原文：「When 登录命中条件（即便同时命中豁免规则），Then 在主认证之后
// 强制完成一次增强认证方可上线」。它把两件事分开建模：
//   FR-AUTH-17 免二次认证 —— 授信终端 / 特定网络，免掉的是**基础**那一次；
//   FR-AUTH-20 增强认证   —— 弱口令 / 异常时段等**风险已经出现**时强制追加。
//
// 改造前两者被塌缩成一个 RequireMFA 布尔、豁免命中即 return，方向完全反了：
// 正好在风险出现的那一刻，一条网段豁免把二次认证整个取消。而出厂那条 AD 默认策略
// 恰好同时开着 TrustedNetwork(10.8.0.0/16) 与 WeakPwd+OffHours。
func TestRiskConditionsOverrideExemption(t *testing.T) {
	// 与出厂 ap-ad-default 同形：豁免与风险增强同时开着。
	pols := []store.AuthPolicy{scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.WeakPwd = true
		p.Exempt.TrustedNetwork = true
		p.Exempt.Networks = []string{"10.8.0.0/16"}
		p.Exempt.TrustedDevice = true
	})}

	in := baseInput("ext.zhou")
	in.ClientIP = netip.MustParseAddr("10.8.2.31") // 在可信网段内
	in.PwStrength = auth.PwWeak                    // 但口令是弱口令

	d := Evaluate(pols, in)
	if !d.RequireMFA {
		t.Fatal("弱口令 + 可信网络：风险条件已命中，豁免不得生效——" +
			"否则正好在风险出现的那一刻把二次认证整个取消（FR-AUTH-21）")
	}
	if d.Exempted {
		t.Error("被风险条件否决时不应标记为 Exempted（那会让审计写成「已豁免」）")
	}
	if !d.ExemptOverridden {
		t.Error("必须记下「豁免曾命中但被否决」：否则用户会以为豁免坏了、管理员会以为策略配错了")
	}
	sum := d.Summary()
	for _, want := range []string{"弱口令", "10.8.0.0/16", "豁免不生效"} {
		if !strings.Contains(sum, want) {
			t.Errorf("摘要要同时说清风险条件、命中的豁免、以及豁免为何不生效；缺 %q：%s", want, sum)
		}
	}

	// 授信终端同理（另一条豁免路径，不能只修一条）。
	in2 := baseInput("ext.zhou")
	in2.PwStrength = auth.PwWeak
	in2.DeviceKnown, in2.DeviceVerdict, in2.DeviceID = true, "allow", "f47b0508"
	if d := Evaluate(pols, in2); !d.RequireMFA || !d.ExemptOverridden {
		t.Errorf("授信终端 + 弱口令同样要求二次认证：%+v", d)
	}
}

// 反例：只命中**基础**档（Always）时，豁免照常生效——FR-AUTH-17 的本意，行为不能被改坏。
func TestExemptionStillWorksForBaseRequirement(t *testing.T) {
	pols := []store.AuthPolicy{scopedPolicy(func(p *store.AuthPolicy) {
		p.Enhance.Always = true // 基础档
		p.Enhance.WeakPwd = true
		p.Exempt.TrustedNetwork = true
		p.Exempt.Networks = []string{"10.8.0.0/16"}
	})}
	in := baseInput("ext.zhou")
	in.ClientIP = netip.MustParseAddr("10.8.2.31")
	in.PwStrength = auth.PwStrong // 风险条件**未**命中
	d := Evaluate(pols, in)
	if d.RequireMFA || !d.Exempted {
		t.Fatalf("只命中基础档时豁免必须照常生效（FR-AUTH-17）：%+v", d)
	}
	if d.ExemptOverridden {
		t.Error("没有风险条件命中，不该标记为「豁免被否决」")
	}
}
