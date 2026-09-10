package authpolicy

import (
	"net/netip"
	"testing"
	"time"

	"baidi.dev/control/internal/store"
)

// 防自锁闸（PRD FR-ADMIN-20）的判定内核：Blocked 与 EvaluateLockout。
//
// 这两个函数的每一条取舍都能把闸的结论整个翻过来，而翻过来之后**两边都不报错**：
// 判松了 = 一条策略把全部管理员永久挡在管理台外而保存回 200；
// 判紧了 = 一条完全合理的加严策略永远存不下去，管理员只会以为系统在随机拒绝他。

// alwaysPolicy 一条"范围内一律二次认证、只收 TOTP"的本地默认策略。
func alwaysPolicy(mut func(*store.AuthPolicy)) store.AuthPolicy {
	p := store.AuthPolicy{
		ID: "ap-local-default", Name: "本地默认", Directory: "local", IsDefault: true,
		Priority: 100, Enabled: true, Secondary: []string{"totp"},
		Enhance: store.EnhanceRule{Always: true},
	}
	if mut != nil {
		mut(&p)
	}
	return p
}

func lockoutInput() Input {
	return Input{Account: "admin", Directory: "local", Subjects: subjects()}
}

func TestBlockedMirrorsSecondFactorBranches(t *testing.T) {
	cases := []struct {
		name     string
		dec      Decision
		rp       bool
		want     bool
		whyIfNot string
	}{
		{"不要求二次认证 → 进得去", Decision{}, true, false, ""},
		{"要求二次认证 + RP 已配置 → needEnroll，进不去",
			Decision{RequireMFA: true}, true, true, ""},
		{"要求二次认证 + RP 未配置 + 策略点名了方式 → legacy 回落不成立，进不去",
			Decision{RequireMFA: true, Methods: []string{"totp"}}, false, true, ""},
		{"要求二次认证 + RP 未配置 + 策略没点名方式 → 回落 legacy 演示验证码，进得去",
			Decision{RequireMFA: true}, false, false,
			"这一格判成 true 的话，裸 IP 演示站上任何一条加严策略都再也存不下去——" +
				"而那里 123456 回落是真的通的"},
	}
	for _, c := range cases {
		if got := Blocked(c.dec, c.rp); got != c.want {
			t.Errorf("%s：Blocked=%v want %v %s", c.name, got, c.want, c.whyIfNot)
		}
	}
}

// 豁免命中与否取决于管理员**将来**从哪个网络登录，保存那一刻无从知道。
// 按"他一定会在办公网里"求值，就会把「回家之后再也登不进来」算成安全。
func TestEvaluateLockoutIgnoresTrustedNetworkExemption(t *testing.T) {
	p := alwaysPolicy(func(p *store.AuthPolicy) {
		p.Exempt = store.ExemptRule{TrustedNetwork: true, Networks: []string{"10.0.0.0/8"}}
	})
	in := lockoutInput()
	in.ClientIP = netip.MustParseAddr("10.1.2.3")
	in.Now = time.Now()

	// 登录链路：在可信网络里，豁免生效（基础档才有资格被豁免）。
	if d := Evaluate([]store.AuthPolicy{p}, in); !d.Exempted || d.RequireMFA {
		t.Fatalf("登录链路在可信网络里应豁免，实得 %+v", d)
	}
	// 防自锁闸：豁免一律按不命中判。
	if d := EvaluateLockout([]store.AuthPolicy{p}, in); !d.RequireMFA {
		t.Fatalf("防自锁闸必须忽略可信网络豁免（管理员可能在任何网络登录），实得 %+v", d)
	}
}

// 授信终端豁免同理：指纹由客户端自报，且"他届时会不会带着那台机器"无从知道。
func TestEvaluateLockoutIgnoresTrustedDeviceExemption(t *testing.T) {
	p := alwaysPolicy(func(p *store.AuthPolicy) {
		p.Exempt = store.ExemptRule{TrustedDevice: true}
	})
	in := lockoutInput()
	in.DeviceID, in.DeviceKnown, in.DeviceVerdict = "fp-1", true, "allow"

	if d := Evaluate([]store.AuthPolicy{p}, in); !d.Exempted {
		t.Fatalf("登录链路带着授信终端应豁免，实得 %+v", d)
	}
	if d := EvaluateLockout([]store.AuthPolicy{p}, in); !d.RequireMFA {
		t.Fatalf("防自锁闸必须忽略授信终端豁免，实得 %+v", d)
	}
}

// 非工作时段是**可等待**的：管理员等到上班时间就进得去，不构成自锁。
// 若闸直接用 time.Now() 求值，同一条策略白天存得下去、晚上存不下去——
// 那种"随机拒绝"比拦错更难查。
func TestEvaluateLockoutTreatsOffHoursAsWaitable(t *testing.T) {
	p := store.AuthPolicy{
		ID: "ap-local-default", Name: "本地默认", Directory: "local", IsDefault: true,
		Priority: 100, Enabled: true, Secondary: []string{"totp"},
		Enhance: store.EnhanceRule{OffHours: true, WorkStart: "09:00", WorkEnd: "18:00",
			WorkDays: []int{1, 2, 3, 4, 5}},
	}
	in := lockoutInput()
	in.Now = time.Date(2024, 1, 6, 3, 0, 0, 0, time.UTC) // 周六凌晨三点

	if d := Evaluate([]store.AuthPolicy{p}, in); !d.RequireMFA {
		t.Fatalf("周六凌晨登录该被抬到二次认证，实得 %+v", d)
	}
	if d := EvaluateLockout([]store.AuthPolicy{p}, in); d.RequireMFA {
		t.Fatalf("非工作时段增强不该被判成自锁（等到上班就能进），实得 %+v", d)
	}
}

// 工作日只配了周日时，构造出的"窗内时刻"也必须真的落在窗内——
// 基准日算错一天，这条策略就会被误判成锁死。
func TestInWorkWindowLandsInsideWindow(t *testing.T) {
	for _, wd := range []int{1, 2, 3, 4, 5, 6, 7} {
		e := store.EnhanceRule{OffHours: true, WorkStart: "10:30", WorkEnd: "12:00", WorkDays: []int{wd}}
		got := inWorkWindow(e)
		if offHours(e, got) {
			t.Fatalf("工作日=%d 时构造的时刻 %v 仍被判成非工作时段", wd, got)
		}
	}
}

// 弱口令是**存量事实**（users.pw_strength），当事人登不进来也就改不了口令——
// 对他而言这条规则与「一律二次认证」一样躲不开，闸必须照样判成锁死。
func TestEvaluateLockoutCountsWeakPasswordAsUnavoidable(t *testing.T) {
	p := alwaysPolicy(func(p *store.AuthPolicy) {
		p.Enhance = store.EnhanceRule{WeakPwd: true}
	})
	in := lockoutInput()
	in.PwStrength = "weak"
	if d := EvaluateLockout([]store.AuthPolicy{p}, in); !d.RequireMFA {
		t.Fatalf("弱口令标记为 weak 的账号必须判成会被挡住，实得 %+v", d)
	}
	// unknown（存量行）不命中——不可判定不等于弱。
	in.PwStrength = "unknown"
	if d := EvaluateLockout([]store.AuthPolicy{p}, in); d.RequireMFA {
		t.Fatalf("口令强度未知不该命中弱密码规则，实得 %+v", d)
	}
}

// 没有任何策略命中时返回零值：闸据此判"进得去"，与登录链路一致。
func TestEvaluateLockoutNoPolicy(t *testing.T) {
	if d := EvaluateLockout(nil, lockoutInput()); d.RequireMFA || d.PolicyID != "" {
		t.Fatalf("无适用策略应返回零值决策，实得 %+v", d)
	}
}
