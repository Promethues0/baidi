package upgrade

import (
	"strings"
	"testing"
)

// 升级包的 component 字段**参与判定**（wave11 行动 18-②）。
//
// 改造前 CheckPackage 的签名是 `(m, currentControl, rules, comp)`：component 被
// ParseManifest 解析、校验（必须是 control|gateway）、写进审计正文，然后就被丢掉——
// 无论包是给谁的，"当前版本"一律取控制面的。下面第一条用例是**实测复现过的**那个形态。

func gwManifest(version string) Manifest {
	return Manifest{Product: "baidi", Component: ComponentGateway, Version: version,
		SHA256: strings.Repeat("ab", 32)}
}

func ctlManifest(version string) Manifest {
	return Manifest{Product: "baidi", Component: ComponentControl, Version: version,
		SHA256: strings.Repeat("ab", 32)}
}

// TestGatewayPackageJudgedAgainstGateways 分离式部署下最典型的一次误判。
//
// 控制面已经升到 0.4.0、网关还停在 0.3.0，管理员传一个 component=gateway 的 0.4.0 包：
// 改造前拿控制面版本去比 → cmp==0 → **阻断**并回「升级包版本与当前运行版本相同，无需升级」。
// 一次完全必要的网关升级被系统劝退，而理由里那个"当前运行版本"说的是另一个组件。
//
// ★变异检验：把 checkGatewayPackage 的分流去掉（CheckPackage 恒走 checkControlPackage），
// 这条立刻红在「不该阻断」那一行。
func TestGatewayPackageJudgedAgainstGateways(t *testing.T) {
	comp := Components{Control: "0.4.0", Gateways: map[string]string{"gw-1": "0.3.0"}}
	c := CheckPackage(gwManifest("0.4.0"), DefaultRules(), comp)
	if c.Blocked {
		t.Fatalf("网关还在 0.3.0，这次网关升级必须放行；实际被拦：%v", c.Reasons)
	}
	for _, r := range c.Reasons {
		if strings.Contains(r, "无需升级") {
			t.Errorf("不许拿控制面的版本去判网关包：%q", r)
		}
	}
}

// TestGatewayPackageBlockedWhenAllGatewaysAlreadyThere 方向相反的那一半也要对：
// 全部网关都已是目标版本时才叫"无需升级"，而判据是网关自己的版本、不是控制面的。
func TestGatewayPackageBlockedWhenAllGatewaysAlreadyThere(t *testing.T) {
	// 控制面故意比网关低——改造前这组数据会被判成一次合法升级（方向正好相反）。
	comp := Components{Control: "0.3.0", Gateways: map[string]string{
		"gw-1": "0.4.0", "gw-2": "0.4.0"}}
	c := CheckPackage(gwManifest("0.4.0"), DefaultRules(), comp)
	if !c.Blocked {
		t.Fatalf("全部网关都已是 0.4.0，应判「无需升级」；实际放行")
	}
	joined := strings.Join(c.Reasons, " | ")
	if !strings.Contains(joined, "gw-1") || !strings.Contains(joined, "gw-2") {
		t.Errorf("要点名是哪几台已经到位：%q", joined)
	}
}

// TestGatewayPackageRollingUpgradeAllowed 滚动升级的正常中间态：有的升了有的没升。
// 因为一台已到位就整体阻断的话，多网关部署第二台开始就再也升不了。
func TestGatewayPackageRollingUpgradeAllowed(t *testing.T) {
	comp := Components{Control: "0.4.0", Gateways: map[string]string{
		"gw-1": "0.4.0", "gw-2": "0.3.0"}}
	c := CheckPackage(gwManifest("0.4.0"), DefaultRules(), comp)
	if c.Blocked {
		t.Fatalf("还有一台没升，必须放行：%v", c.Reasons)
	}
	if !strings.Contains(strings.Join(c.Warnings, " | "), "gw-1") {
		t.Errorf("已到位的那台要列进警告，好让人知道这次实际动的是谁：%v", c.Warnings)
	}
}

// TestGatewayDowngradeBlockedAndNamed 任一台会被降级就拦住，并点名是哪台。
// 网关是数据面：降级下去起不来就是那一路业务全断，不是"页面少个绿点"。
func TestGatewayDowngradeBlockedAndNamed(t *testing.T) {
	comp := Components{Control: "0.4.0", Gateways: map[string]string{
		"gw-1": "0.5.0", "gw-2": "0.3.0"}}
	c := CheckPackage(gwManifest("0.4.0"), DefaultRules(), comp)
	if !c.Blocked {
		t.Fatal("有网关会被降级，必须拦")
	}
	if !strings.Contains(strings.Join(c.Reasons, " | "), "gw-1") {
		t.Errorf("要点名会被降级的那台：%v", c.Reasons)
	}
	// 显式允许降级后放行，但必须留一条警告——放行不等于这件事不危险。
	r := DefaultRules()
	r.AllowDowngrade = true
	c2 := CheckPackage(gwManifest("0.4.0"), r, comp)
	if c2.Blocked {
		t.Fatalf("显式允许降级后应放行：%v", c2.Reasons)
	}
	if !strings.Contains(strings.Join(c2.Warnings, " | "), "gw-1") {
		t.Errorf("允许降级仍要警告并点名：%v", c2.Warnings)
	}
}

// TestGatewayPackageBlockedWhenNothingJudgeable 判不出来就不许说"可以升"。
//
// 两种形态各判一次：一台网关都没注册 / 注册了但全部报不出可解析的语义版本。
// 这与本项目对"探不到"的一贯处置一致——把不可判定当成"没问题"，
// 得到的是一次看起来通过了、实际谁也没验的校验。
func TestGatewayPackageBlockedWhenNothingJudgeable(t *testing.T) {
	t.Run("没有已注册网关", func(t *testing.T) {
		c := CheckPackage(gwManifest("0.4.0"), DefaultRules(), Components{Control: "0.4.0"})
		if !c.Blocked {
			t.Fatal("没有网关可判时必须拦")
		}
		if !strings.Contains(strings.Join(c.Reasons, " "), "没有任何网关") {
			t.Errorf("理由要说清是"+`"`+"没网关"+`"`+"而不是"+`"`+"版本不对"+`"`+"：%v", c.Reasons)
		}
	})
	t.Run("全部不可判定", func(t *testing.T) {
		comp := Components{Control: "0.4.0", Gateways: map[string]string{
			"gw-1": "",        // 旧网关不上报
			"gw-2": "a9ae190", // 改造前 build.sh 注进去的 git 短哈希
		}}
		c := CheckPackage(gwManifest("0.4.0"), DefaultRules(), comp)
		if !c.Blocked {
			t.Fatal("一台可判定的网关都没有时必须拦")
		}
		joined := strings.Join(c.Reasons, " ")
		if !strings.Contains(joined, "gw-1") || !strings.Contains(joined, "gw-2") {
			t.Errorf("要逐台点名，好让人知道去哪台机器上看：%q", joined)
		}
	})
}

// TestGatewayUnknownDoesNotSilentlyNarrowConclusion 部分不可判定时：结论照给，
// 但必须当面声明它**不覆盖**那几台。
//
// 一个悄悄缩小了范围的结论比没有结论更坏——管理员会以为"校验通过"是对全部网关说的。
func TestGatewayUnknownDoesNotSilentlyNarrowConclusion(t *testing.T) {
	comp := Components{Control: "0.4.0", Gateways: map[string]string{
		"gw-1": "0.3.0", "gw-2": ""}}
	c := CheckPackage(gwManifest("0.4.0"), DefaultRules(), comp)
	if c.Blocked {
		t.Fatalf("还有一台可判定且能升，应放行：%v", c.Reasons)
	}
	joined := strings.Join(c.Warnings, " | ")
	if !strings.Contains(joined, "gw-2") || !strings.Contains(joined, "不覆盖") {
		t.Errorf("必须声明结论不覆盖不可判定的那几台：%v", c.Warnings)
	}
}

// TestGatewayMinSourceAndHopsJudgedPerGateway 包自带的 minSource 与管理员配的
// 强制跳跃链路，对网关包都必须**逐台**判：只判控制面的话，一台低版本网关会被直升。
func TestGatewayMinSourceAndHopsJudgedPerGateway(t *testing.T) {
	m := gwManifest("2.0.0")
	m.MinSource = "1.5.0"
	comp := Components{Control: "2.0.0", Gateways: map[string]string{
		"gw-1": "1.5.0", "gw-2": "1.0.0"}}
	c := CheckPackage(m, DefaultRules(), comp)
	if !c.Blocked || c.NextHop != "1.5.0" {
		t.Fatalf("有网关低于包要求的起跳版本，应拦并指出先升到哪：blocked=%v next=%q", c.Blocked, c.NextHop)
	}
	if !strings.Contains(strings.Join(c.Reasons, " "), "gw-2") {
		t.Errorf("要点名是哪台太低：%v", c.Reasons)
	}

	r := DefaultRules()
	r.Hops = []Hop{{Below: "1.0.0", Next: "1.5.0"}}
	c2 := CheckPackage(gwManifest("2.0.0"), r, Components{
		Control: "2.0.0", Gateways: map[string]string{"gw-1": "0.9.0"}})
	if !c2.Blocked || c2.NextHop != "1.5.0" {
		t.Fatalf("强制跳跃链路应逐台生效：blocked=%v next=%q reasons=%v", c2.Blocked, c2.NextHop, c2.Reasons)
	}
}

// TestControlPackageUnaffected 控制面包的判定与改造前逐字一致——
// 这次改的是"按组件分流"，不是"把控制面那条路也改了"。
func TestControlPackageUnaffected(t *testing.T) {
	comp := Components{Control: "0.3.0", Gateways: map[string]string{"gw-1": "0.3.0"}}
	if c := CheckPackage(ctlManifest("0.4.0"), DefaultRules(), comp); c.Blocked {
		t.Fatalf("控制面 0.3.0 → 0.4.0 应放行：%v", c.Reasons)
	}
	if c := CheckPackage(ctlManifest("0.3.0"), DefaultRules(), comp); !c.Blocked {
		t.Fatal("同版本应判「无需升级」")
	}
	if c := CheckPackage(ctlManifest("0.2.0"), DefaultRules(), comp); !c.Blocked {
		t.Fatal("降级应被拦")
	}
}

// TestNotInjectedCurrentVersionIsBlockedWithActionableReason 当前版本"未注入"时
// fail-closed，且理由必须指向**换一个交付件**而不是"版本号写错了"。
//
// 两句话会把人送去完全不同的地方：后者让人反复检查自己粘的 manifest，
// 而真正要做的是用 deploy/build.sh 重新构建。
func TestNotInjectedCurrentVersionIsBlockedWithActionableReason(t *testing.T) {
	c := CheckPackage(ctlManifest("0.4.0"), DefaultRules(), Components{Control: ""})
	if !c.Blocked {
		t.Fatal("当前版本不可判定时必须拒绝——判不出是升还是降")
	}
	joined := strings.Join(c.Reasons, " ")
	if !strings.Contains(joined, "未注入") || !strings.Contains(joined, "build.sh") {
		t.Errorf("理由要说清"+`"`+"这个二进制没有版本身份"+`"`+"以及怎么补：%q", joined)
	}
}

// TestUnparseableGatewayVersionIsUnknownNotStale 改造前最刺眼的那条：
// deploy/build.sh 注进去的 git 短哈希 ParseVersion 必失败，而失败与
// 「解析出来了但确实不等于目标」被合并成同一条 stale 警告——
// 于是**每一台按脚本装出来的网关**都常年挂着「版本将与控制面不一致」，
// 一条永远为真的告警等于没有告警。
func TestUnparseableGatewayVersionIsUnknownNotStale(t *testing.T) {
	comp := Components{Gateways: map[string]string{
		"gw-hash": "a9ae190", // 语义上不可判定
		"gw-old":  "0.3.0",   // 确定不一致
	}}
	c := CheckUpgrade("0.3.0", "0.4.0", DefaultRules(), comp)
	// ★分类判据用「须同步升级」而不是「不一致」：不可判定那条的正文里恰好也
	// 引用了"版本不一致"四个字（它在说"这不等于版本不一致"），按子串分会分反。
	var stale, unknown string
	for _, w := range c.Warnings {
		switch {
		case strings.Contains(w, "须同步升级"):
			stale = w
		case strings.Contains(w, "不可判定"):
			unknown = w
		}
	}
	if stale == "" || unknown == "" {
		t.Fatalf("两类必须各成一条，得到：%v", c.Warnings)
	}
	if strings.Contains(stale, "gw-hash") {
		t.Errorf("解析不出版本的网关不能被说成「版本不一致」：%q", stale)
	}
	if !strings.Contains(unknown, "gw-hash") || !strings.Contains(unknown, "a9ae190") {
		t.Errorf("不可判定那条要点名并回显它究竟报了什么（那是找回根因的唯一线索）：%q", unknown)
	}
	if strings.Contains(unknown, "gw-old") {
		t.Errorf("确定不一致的网关不该混进不可判定那条：%q", unknown)
	}
}

// TestWarningsAreStableAcrossRuns 文案顺序不随 map 迭代序抖。
// 页面上每次刷新换个说法，会让人以为系统状态在变。
func TestWarningsAreStableAcrossRuns(t *testing.T) {
	comp := Components{Gateways: map[string]string{
		"gw-a": "0.3.0", "gw-b": "0.3.0", "gw-c": "0.3.0", "gw-d": "0.3.0"}}
	first := strings.Join(CheckUpgrade("0.3.0", "0.4.0", DefaultRules(), comp).Warnings, "|")
	for i := 0; i < 50; i++ {
		if got := strings.Join(CheckUpgrade("0.3.0", "0.4.0", DefaultRules(), comp).Warnings, "|"); got != first {
			t.Fatalf("第 %d 次的文案与首次不同：\n%s\n%s", i, first, got)
		}
	}
}
