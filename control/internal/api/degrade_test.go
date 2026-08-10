package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/store"
)

// ── 风险分档执行方（degrade / gray / block）的同构测试 ──
//
// 这一族测试守的是同一件事：**页面上显示的那一档，就是网关此刻正在执行的那一档**。
// degrade 的两个判定点（网关策略下发 / 客户端剖面）若分叉，症状与组织授权分叉时一模一样：
//   - 剖面窄、网关宽 → 用户"有权限却没有路由"，无任何报错；
//   - 剖面宽、网关窄 → 流量接管进隧道再被拒，表现成时通时不通。
// 所以每个场景都**同时**断言两侧。

// gatewayAuthorizeWithDeny 逐字复刻数据面 gateway/internal/resource.(*Registry).Authorize
// 的当前实现（DenyUsers 先判 → 允许集合）。
//
// ★为什么是复刻而不是 import：control 与 gateway 是两个独立 module（Go 版本都不同）。
// 复刻的代价是"网关改了这里没跟着改"，故刻意只有几行、与源实现逐句对应。
func gatewayAuthorizeWithDeny(user, role string, allowUsers, allowRoles, denyUsers []string) bool {
	hit := func(ss []string, v string) bool {
		for _, s := range ss {
			if strings.EqualFold(s, v) {
				return true
			}
		}
		return false
	}
	if len(denyUsers) > 0 && hit(denyUsers, user) {
		return false
	}
	if len(allowUsers) > 0 && hit(allowUsers, user) {
		return true
	}
	if len(allowRoles) > 0 && hit(allowRoles, role) {
		return true
	}
	return len(allowUsers) == 0 && len(allowRoles) == 0
}

// gwView 拉一次网关策略，返回某资源下发的允许/否决集合。
func (f *isoFixture) gwView(resID string) (allowUsers, allowRoles, denyUsers []string) {
	f.t.Helper()
	code, out := doJSON(f.t, f.h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if code != http.StatusOK {
		f.t.Fatalf("gateways/policy http %d", code)
	}
	arr, _ := out["resources"].([]any)
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok || m["id"] != resID {
			continue
		}
		if m["sensitivity"] != nil {
			f.t.Fatalf("下发给网关的资源不该带 sensitivity（数据面不解释敏感度，只执行 denyUsers）：%v", m)
		}
		return strSlice(m["allowUsers"]), strSlice(m["allowRoles"]), strSlice(m["denyUsers"])
	}
	f.t.Fatalf("资源 %s 未下发给网关", resID)
	return nil, nil, nil
}

// gwAllows 网关侧此刻是否放行（同构断言的一半）。
func (f *isoFixture) gwAllows(user, role, resID string) bool {
	f.t.Helper()
	au, ar, du := f.gwView(resID)
	return gatewayAuthorizeWithDeny(user, role, au, ar, du)
}

// profileApp 拉一次剖面，返回该应用的磁贴与"是否真的排出了路由"。
// 只看 Accessible 不够：决定"点开能不能用"的是 resmap + routes 那两条。
func (f *isoFixture) profileApp(user, role, appID string, apps store.AppBundle) (ProfileApp, bool, ClientProfile) {
	f.t.Helper()
	rs, err := f.st.Resources(context.Background())
	if err != nil {
		f.t.Fatalf("Resources: %v", err)
	}
	p := f.s.buildProfile(context.Background(), user, role, apps, rs)
	a, ok := findApp(p, appID)
	if !ok {
		f.t.Fatalf("剖面里找不到应用 %s", appID)
	}
	host, _, _ := strings.Cut(a.Backend, ":")
	routed := a.Accessible && p.Resmap[a.Backend] == a.ResourceID && hasRoute(p.Routes, host+"/32")
	return a, routed, p
}

// reportPosture 以该账号的名义落一条终端报告（绕过 handler 直接写库，
// 免得测试还要拼一整套基线才能造出某一档判定）。
func (f *isoFixture) reportPosture(account, device, disposal string, reasons ...string) {
	f.t.Helper()
	if err := f.st.SavePostureReport(context.Background(), store.PostureReport{
		User: account, Device: device, Platform: "macOS", OS: "macOS 14",
		Verdict: disposal, Score: 10, Level: "medium", Reasons: reasons, TS: time.Now().Unix(),
	}); err != nil {
		f.t.Fatalf("SavePostureReport: %v", err)
	}
}

// degradeFixture 一高敏一普通两个资源 + 两个桥接应用，都对 role=user 开放。
// 降权前两者皆可达，降权后只有高敏那个消失——「降权而非全断」的最小可证场景。
func degradeFixture(f *isoFixture) store.AppBundle {
	f.t.Helper()
	for _, res := range []map[string]any{
		{"id": "r-high", "name": "财务核算系统", "backend": "10.20.3.21:443",
			"allowRoles": []string{"user"}, "sensitivity": store.SensitivityHigh},
		{"id": "r-normal", "name": "OA 协同办公", "backend": "10.20.1.10:8080",
			"allowRoles": []string{"user"}, "sensitivity": store.SensitivityNormal},
	} {
		if code, out := f.saveResource(res); code != http.StatusOK {
			f.t.Fatalf("保存资源 %v http %d: %v", res["id"], code, out)
		}
	}
	return store.AppBundle{Apps: []store.App{
		{ID: "app-high", Name: "财务核算系统", Addr: "10.20.3.21:443", Mode: "web",
			Category: "finance", Status: "running", ResourceID: "r-high"},
		{ID: "app-normal", Name: "OA 协同办公", Addr: "10.20.1.10:8080", Mode: "web",
			Category: "office", Status: "running", ResourceID: "r-normal"},
	}}
}

// ★核心用例：降权摘掉高敏资源，普通资源纹丝不动，且两侧同真同假。
func TestDegradeDropsHighSensitivityOnBothSides(t *testing.T) {
	f := newIsoFixture(t)
	apps := degradeFixture(f)

	// 前置：合规状态下两个资源都可达
	if !f.gwAllows("li.fang", "user", "r-high") || !f.gwAllows("li.fang", "user", "r-normal") {
		t.Fatal("前置失败：降权前两个资源在网关侧都应放行")
	}
	if _, routed, _ := f.profileApp("li.fang", "user", "app-high", apps); !routed {
		t.Fatal("前置失败：降权前高敏应用应排出路由")
	}

	f.reportPosture("li.fang", "MAC-1", store.DisposalDegrade, "系统完整性保护未开启")

	// 网关侧：高敏资源的 denyUsers 含该账号 → 拒；普通资源不受影响 → 放行
	_, _, deny := f.gwView("r-high")
	if len(deny) == 0 || !strings.EqualFold(deny[0], "li.fang") {
		t.Fatalf("高敏资源应下发 denyUsers=[li.fang]，实得 %v", deny)
	}
	if _, _, ndeny := f.gwView("r-normal"); len(ndeny) != 0 {
		t.Fatalf("普通资源不该有 denyUsers（降权只摘高敏），实得 %v", ndeny)
	}
	gwHigh := f.gwAllows("li.fang", "user", "r-high")
	gwNormal := f.gwAllows("li.fang", "user", "r-normal")

	// 剖面侧：高敏磁贴不可访问、无 resmap/route，且标了 Degraded；普通应用照常
	high, highRouted, p := f.profileApp("li.fang", "user", "app-high", apps)
	normal, normalRouted, _ := f.profileApp("li.fang", "user", "app-normal", apps)

	if gwHigh || highRouted {
		t.Fatalf("降权后高敏资源两侧都应拒绝：网关=%v 剖面路由=%v", gwHigh, highRouted)
	}
	if !gwNormal || !normalRouted {
		t.Fatalf("★降权不是全断：普通资源两侧都应照常放行，网关=%v 剖面路由=%v", gwNormal, normalRouted)
	}
	if !high.Degraded {
		t.Fatal("高敏磁贴应标 degraded=true，否则用户会以为是权限没批而反复提交申请")
	}
	if normal.Degraded {
		t.Fatal("普通磁贴不该标 degraded")
	}
	// 隧道相关的东西一条都不能少：降权不断连
	if len(p.Routes) == 0 || p.Resmap["10.20.1.10:8080"] != "r-normal" {
		t.Fatalf("降权后隧道路由表不该被清空：routes=%v resmap=%v", p.Routes, p.Resmap)
	}
	// 高敏后端的 /32 必须消失（否则终端把流量接管进隧道，再被网关拒 → 时通时不通）
	if hasRoute(p.Routes, "10.20.3.21/32") {
		t.Fatalf("高敏后端不该再进 routes：%v", p.Routes)
	}
}

// 用户必须知道为什么打不开——剖面 warnings 第一条就是降权说明（含 risk reason）。
// 降权而用户不知情会产生「明明有权限却打不开」的迷惑失败形态。
func TestDegradeWarnsTheUser(t *testing.T) {
	f := newIsoFixture(t)
	apps := degradeFixture(f)
	f.reportPosture("li.fang", "MAC-1", store.DisposalDegrade, "系统完整性保护未开启")

	_, _, p := f.profileApp("li.fang", "user", "app-high", apps)
	if len(p.Warnings) == 0 {
		t.Fatal("降权后剖面必须带告警")
	}
	w := p.Warnings[0] // 客户端「应用」页只 toast 第一条，降权说明必须排第一
	for _, want := range []string{"因终端合规降级", "财务核算系统", "系统完整性保护未开启"} {
		if !strings.Contains(w, want) {
			t.Fatalf("降权告警应含 %q，实得 %q", want, w)
		}
	}
	if !strings.Contains(w, "隧道未断开") {
		t.Fatalf("告警须说明这是降权不是断连，否则用户会去重连隧道：%q", w)
	}
	// ★恢复那句话必须与客户端实现相符：网关那半自动，客户端那半要重连。
	// baidi-tun 的路由在 tunnel_start 那一刻定死（tunnel.ts 的 startedOpts），
	// 降级期间建立的隧道里根本没有高敏资源的 VIP /32——只写「自动恢复」的话，
	// 用户得到的是「已接入、提示已恢复、财务系统还是打不开」，且毫无线索。
	if !strings.Contains(w, "重新接入") {
		t.Fatalf("告警须说明降级期间建立的隧道要重连才拿得回路由：%q", w)
	}

	// 反例：合规用户不该看到这条告警（无中生有的降权提示同样是误导）
	f2 := newIsoFixture(t)
	apps2 := degradeFixture(f2)
	_, _, p2 := f2.profileApp("li.fang", "user", "app-high", apps2)
	for _, w := range p2.Warnings {
		if strings.Contains(w, "因终端合规降级") {
			t.Fatalf("未降权的用户不该看到降权告警：%q", w)
		}
	}
}

// 恢复合规后**下一轮就回到全量**：展开每轮现算、不缓存，不需要任何人工操作。
func TestDegradeRecoveryRestoresFullAccessNextPoll(t *testing.T) {
	f := newIsoFixture(t)
	apps := degradeFixture(f)
	f.reportPosture("li.fang", "MAC-1", store.DisposalDegrade, "系统完整性保护未开启")
	if f.gwAllows("li.fang", "user", "r-high") {
		t.Fatal("前置失败：降权后高敏资源应被拒")
	}

	// 同一台设备重新上报合规（等价于用户修好终端后下一次 60s 周期上报）
	f.reportPosture("li.fang", "MAC-1", store.DisposalAllow)

	if !f.gwAllows("li.fang", "user", "r-high") {
		_, _, deny := f.gwView("r-high")
		t.Fatalf("恢复合规后下一轮下发即应放行，denyUsers 仍为 %v", deny)
	}
	high, routed, p := f.profileApp("li.fang", "user", "app-high", apps)
	if !routed || high.Degraded {
		t.Fatalf("恢复合规后剖面应立即排回路由：%+v", high)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "因终端合规降级") {
			t.Fatalf("恢复合规后不该再有降权告警：%q", w)
		}
	}
}

// 降权否决**压过有效 JIT 授予**：终端已经不合规了，一张审批单不该把高敏的门重新打开。
// 两侧必须同时否决——只有一侧生效就是"门户显示可访问、隧道那边照拒"。
func TestDegradeBeatsActiveJitGrant(t *testing.T) {
	f := newIsoFixture(t)
	apps := degradeFixture(f)
	ctx := context.Background()

	req, err := f.st.CreateAccessRequest(ctx, store.AccessRequest{
		ID: "req-deg", User: "li.fang", ResourceID: "r-high", ResourceName: "财务核算系统",
		Reason: "月结对账", TTLMinutes: 60,
	})
	if err != nil {
		t.Fatalf("建申请: %v", err)
	}
	if _, _, err := f.st.DecideAccessRequest(ctx, req.ID, "approved", "已核实", "admin", 0); err != nil {
		t.Fatalf("审批: %v", err)
	}
	f.reportPosture("li.fang", "MAC-1", store.DisposalDegrade, "磁盘未加密")

	gwOK := f.gwAllows("li.fang", "user", "r-high")
	_, routed, _ := f.profileApp("li.fang", "user", "app-high", apps)
	if gwOK || routed {
		au, _, du := f.gwView("r-high")
		t.Fatalf("降权应压过 JIT 授予，两侧都拒：网关=%v 剖面路由=%v（allowUsers=%v denyUsers=%v）",
			gwOK, routed, au, du)
	}
}

// 灰度观察：**访问权一字不改**，但每轮策略下发留一条 observing 审计。
// gray 若改变访问权，管理员就再没有"只看不动"的档位可用了。
func TestGrayKeepsAccessAndWritesObservingAudit(t *testing.T) {
	f := newIsoFixture(t)
	apps := degradeFixture(f)
	f.reportPosture("wang.qiang", "WIN-1", store.DisposalGray, "主机防火墙未开启")

	// 触发一轮策略下发（网关轮询）
	if code, _ := doJSON(t, f.h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil); code != http.StatusOK {
		t.Fatalf("gateways/policy http %d", code)
	}
	if !f.gwAllows("wang.qiang", "user", "r-high") {
		t.Fatal("灰度观察不得改变访问权：高敏资源仍应放行")
	}
	if _, _, deny := f.gwView("r-high"); len(deny) != 0 {
		t.Fatalf("灰度账号不该进 denyUsers：%v", deny)
	}
	high, routed, p := f.profileApp("wang.qiang", "user", "app-high", apps)
	if !routed || high.Degraded {
		t.Fatalf("灰度账号剖面应与合规时一致：%+v", high)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "因终端合规降级") {
			t.Fatalf("灰度账号不该收到降权告警：%q", w)
		}
	}

	// observing 审计：管理员据此在监控中心看到"正在观察"
	n, sample := countAudit(t, f, "observing", "wang.qiang")
	if n == 0 {
		t.Fatal("灰度账号每轮策略下发应记一条 observing 审计")
	}
	if !strings.Contains(sample, "灰度观察") || !strings.Contains(sample, "主机防火墙未开启") {
		t.Fatalf("observing 审计应写明档位与命中原因：%q", sample)
	}
	if !strings.Contains(sample, "访问权未变更") {
		t.Fatalf("审计措辞只能陈述已发生的事实（未做任何收缩）：%q", sample)
	}

	// 节流：紧接着再拉一轮不该再记（30s 轮询 × 多网关会把审计冲成噪声）
	if code, _ := doJSON(t, f.h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil); code != http.StatusOK {
		t.Fatal("第二轮策略下发失败")
	}
	if n2, _ := countAudit(t, f, "observing", "wang.qiang"); n2 != n {
		t.Fatalf("observing 审计应按 %v 节流，两轮之间不该重复记（%d → %d）", grayObserveInterval, n, n2)
	}
}

// 回归：block 的行为一个字节都没变——并入撤销名单（撤窗 + 断隧道），而不是走 denyUsers。
// 这条守的是"给 degrade 加执行方时没把 block 改坏"。
func TestBlockBehaviourUnchanged(t *testing.T) {
	f := newIsoFixture(t)
	degradeFixture(f)
	f.reportPosture("li.fang", "MAC-1", store.DisposalBlock, "磁盘未加密")

	code, out := doJSON(t, f.h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("gateways/policy http %d", code)
	}
	found := false
	for _, it := range toSlice(out["revoked"]) {
		m, _ := it.(map[string]any)
		if m != nil && normUser(str(m["user"])) == "li.fang" {
			found = true
		}
	}
	if !found {
		t.Fatalf("block 用户必须进撤销名单（撤窗 + 断隧道），实得 revoked=%v", out["revoked"])
	}
	// block 不借道 denyUsers：它是全断，不是"摘掉高敏"
	if _, _, deny := f.gwView("r-high"); len(deny) != 0 {
		t.Fatalf("block 走撤销名单而非 denyUsers（denyUsers 是降权专用），实得 %v", deny)
	}
	// 也不该被误算成降权
	if deg, _ := f.s.degradeStateOf(context.Background(), "li.fang"); deg {
		t.Fatal("已阻断的账号不应同时显示为已降权")
	}
}

// 混合设备（一台 degrade + 一台 block）：两侧必须都按「跨设备取最差」判成 block。
//
// ★这是两侧口径最容易分叉的地方：网关那份名单的原始查询是"任一设备命中"，
// 剖面那份是"跨设备取最差"。不对齐的话，这个人会同时进降权名单与撤销名单——
// 他实际被全断了，客户端却提示「高敏资源已暂停访问」，把用户引向完全错误的排查方向。
func TestDegradeAndBlockOnDifferentDevicesResolvesToBlock(t *testing.T) {
	f := newIsoFixture(t)
	degradeFixture(f)
	f.reportPosture("li.fang", "MAC-1", store.DisposalDegrade, "系统完整性保护未开启")
	f.reportPosture("li.fang", "WIN-2", store.DisposalBlock, "磁盘未加密")

	if _, _, deny := f.gwView("r-high"); len(deny) != 0 {
		t.Fatalf("已被阻断的账号不该同时进降权名单：%v", deny)
	}
	if deg, _ := f.s.degradeStateOf(context.Background(), "li.fang"); deg {
		t.Fatal("剖面侧同样不该判成降权（最差判定是 block）")
	}
	// 全断这条路仍然照常走
	_, out := doJSON(t, f.h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	hit := false
	for _, it := range toSlice(out["revoked"]) {
		if m, _ := it.(map[string]any); m != nil && normUser(str(m["user"])) == "li.fang" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("最差判定 block 的账号必须进撤销名单：%v", out["revoked"])
	}
}

// 同理，一台 gray、一台 degrade 的账号执行的是 degrade，不该再记 observing 审计
//（审计只记已发生的事实：他被降权了，不是"只在观察"）。
func TestGrayNotAuditedWhenWorseDispositionApplies(t *testing.T) {
	f := newIsoFixture(t)
	degradeFixture(f)
	f.reportPosture("wang.qiang", "WIN-1", store.DisposalGray, "主机防火墙未开启")
	f.reportPosture("wang.qiang", "WIN-2", store.DisposalDegrade, "客户端版本过低")

	if code, _ := doJSON(t, f.h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil); code != http.StatusOK {
		t.Fatal("策略下发失败")
	}
	if n, sample := countAudit(t, f, "observing", "wang.qiang"); n != 0 {
		t.Fatalf("已被降权的账号不该记「正在观察」：%q", sample)
	}
	if !strings.EqualFold(firstDeny(f), "wang.qiang") {
		t.Fatal("该账号应按 degrade 执行（进高敏资源的 denyUsers）")
	}
}

func firstDeny(f *isoFixture) string {
	f.t.Helper()
	_, _, deny := f.gwView("r-high")
	if len(deny) == 0 {
		return ""
	}
	return deny[0]
}

// 敏感度非法取值必须当面拒绝，不静默收敛成 normal：
// 静默收敛的结果是管理员以为标了高敏，而降权对这个资源根本不生效。
func TestSaveResourceRejectsBadSensitivity(t *testing.T) {
	f := newIsoFixture(t)
	code, out := f.saveResource(map[string]any{
		"id": "r-bad", "name": "拼错的敏感度", "backend": "10.20.9.9:80", "sensitivity": "High",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("非法 sensitivity 应 400，实得 %d: %v", code, out)
	}
	// 不填 = 未标注 = normal（与改造前行为一致）
	if code, out := f.saveResource(map[string]any{
		"id": "r-plain", "name": "未标注", "backend": "10.20.9.9:80",
	}); code != http.StatusOK {
		t.Fatalf("不填 sensitivity 应放行，实得 %d: %v", code, out)
	}
	rs, _ := f.st.Resources(context.Background())
	for _, r := range rs {
		if r.ID == "r-plain" && r.Sensitivity != store.SensitivityNormal {
			t.Fatalf("未标注资源应落 normal，实得 %q", r.Sensitivity)
		}
	}
}

// countAudit 数某账号某判定的审计条数，并返回其中一条的事件文案。
func countAudit(t *testing.T, f *isoFixture, verdict, account string) (int, string) {
	t.Helper()
	b, err := f.st.Audit(context.Background())
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	n, sample := 0, ""
	for _, e := range b.Logs {
		if e.Verdict == verdict && normUser(e.User) == normUser(account) {
			n++
			sample = e.Event
		}
	}
	return n, sample
}

func toSlice(v any) []any {
	arr, _ := v.([]any)
	return arr
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
