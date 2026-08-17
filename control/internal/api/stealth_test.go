package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
)

// ── wave8 行动 7：SPA 隐身真实态回执 ──
//
// 被修的坏形态：网关页写死「端口扫描全程超时 / 攻击面 = 0」，`/diag` 只要有网关
// 在线就恒 pass——而参考部署根本不开 -pf，未敲门的连接会先完成 TCP 三次握手。

// gatewayTokenFor 给指定网关 id 签一张 role=gateway 令牌（多网关用例要用不同身份）。
func gatewayTokenFor(id string) string {
	return testKeys.Sign(auth.Claims{Sub: id, Role: "gateway", Name: id}, tokenTTL)
}

func ptrBool(b bool) *bool { return &b }
func ptrInt(n int) *int    { return &n }

// TestStealthReceiptStates 六种形态逐条：结论、攻击者视角、armed 判定。
func TestStealthReceiptStates(t *testing.T) {
	cases := []struct {
		name       string
		proxyAddr  string
		reported   bool
		state      gwStealthState
		wantStatus string
		wantArmed  bool
		// wantScan 攻击者视角里必须出现的**该态独有**的锚点。
		// ★不能只查 "open"/"不可判定"：那几个词被三四态共用，把各态的 ScannerView
		// 互相调换位置用例一条都不会红，而它们各自带着不同的修复指引。
		wantScan string
	}{
		{
			name: "旧网关未上报", proxyAddr: "10.0.0.5:18443", reported: false,
			wantStatus: StealthUnreported, wantScan: "升级该网关二进制",
		},
		{
			name: "明确未开 -pf（参考部署的默认形态）", proxyAddr: "10.0.0.5:18443", reported: true,
			state: gwStealthState{Wanted: false, Backend: "nftables(Linux)", Root: true,
				Ruleset: ptrBool(false)},
			wantStatus: StealthOff, wantScan: "accept-then-close",
		},
		{
			// ★写探测用例时才发现的一态：规则集装着 + 没带 -pf = 全员连不上。
			// 症状比"没有隐身"严重得多，而它此前在任何页面上都与"一切正常"同形。
			name: "规则集装着但没带 -pf（全员连不上）", proxyAddr: "10.0.0.5:18443", reported: true,
			state: gwStealthState{Wanted: false, Backend: "nftables(Linux)", Root: true,
				Ruleset: ptrBool(true), GuardedPort: ptrInt(18443)},
			wantStatus: StealthOrphanRuleset, wantScan: "teardown",
		},
		{
			name: "开了 -pf 但规则集不在（最危险）", proxyAddr: "10.0.0.5:18443", reported: true,
			state: gwStealthState{Wanted: true, Backend: "nftables(Linux)", Root: true,
				Ruleset: ptrBool(false), Detail: "内核里没有 table inet baidi"},
			wantStatus: StealthNoRuleset, wantScan: "baidi-nft.sh setup",
		},
		{
			name: "开了 -pf 但非 root 探不到", proxyAddr: "10.0.0.5:18443", reported: true,
			state: gwStealthState{Wanted: true, Backend: "nftables(Linux)", Root: false,
				Ruleset: nil, Detail: "非 root 运行，读不到内核规则集"},
			wantStatus: StealthUnknown, wantScan: "不等于生效",
		},
		{
			name: "规则集保护了别的端口", proxyAddr: "10.0.0.5:18444", reported: true,
			state: gwStealthState{Wanted: true, Backend: "nftables(Linux)", Root: true,
				Ruleset: ptrBool(true), GuardedPort: ptrInt(18443)},
			wantStatus: StealthPortMismatch, wantScan: "PROXY_PORT",
		},
		{
			name: "真生效", proxyAddr: "10.0.0.5:18443", reported: true,
			state: gwStealthState{Wanted: true, Backend: "nftables(Linux)", Root: true,
				Ruleset: ptrBool(true), GuardedPort: ptrInt(18443)},
			wantStatus: StealthArmed, wantArmed: true, wantScan: "不是外部扫描结果",
		},
		{
			// 端口解析不出来（网关没上报隧道口）→ **不报错配**：不可判定不报警，
			// 否则运维会去追一个不存在的错配。
			name: "隧道口未上报时不误报端口错配", proxyAddr: "", reported: true,
			state: gwStealthState{Wanted: true, Backend: "nftables(Linux)", Root: true,
				Ruleset: ptrBool(true), GuardedPort: ptrInt(18443)},
			wantStatus: StealthArmed, wantArmed: true, wantScan: "不是外部扫描结果",
		},
		{
			// ★复核挖出来的假绿：规则集在、却找不到那条默认 DROP。此前落进 default
			// 判成 armed，摘要还写「未授权源的报文在内核被丢弃」——而它的语义恰恰是
			// **没有任何东西在丢包**。
			name: "规则集在但没有默认 DROP 规则", proxyAddr: "10.0.0.5:18443", reported: true,
			state: gwStealthState{Wanted: true, Backend: "nftables(Linux)", Root: true,
				Ruleset: ptrBool(true), GuardedPort: nil},
			wantStatus: StealthNoDropRule, wantScan: "flush 过这条链",
		},
		{
			// ★参考部署的真实形态：非 root（探不到）+ 没开 -pf。此前直接断言
			// 「未启用、端口 open」——而机器上可能装着规则集（那就是全员连不上），
			// 方向与后果两句全反。现在必须是不可判定，且把两种可能都说出来。
			name: "非 root 且没开 -pf（参考部署形态，两种相反可能）", proxyAddr: "10.0.0.5:18443", reported: true,
			state: gwStealthState{Wanted: false, Backend: "nftables(Linux)", Root: false,
				Ruleset: nil, Detail: "非 root 运行，读不到内核规则集"},
			wantStatus: StealthUnknown, wantScan: "两种相反的可能",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := stealthReceiptOf("gw-1", c.proxyAddr, gwStealthInfo{State: c.state}, c.reported)
			if r.Status != c.wantStatus {
				t.Fatalf("状态应为 %q，得到 %q（%s）", c.wantStatus, r.Status, r.Summary)
			}
			if r.Armed() != c.wantArmed {
				t.Fatalf("Armed() 应为 %v，得到 %v", c.wantArmed, r.Armed())
			}
			if !strings.Contains(r.ScannerView, c.wantScan) {
				t.Fatalf("攻击者视角应含 %q，得到 %q", c.wantScan, r.ScannerView)
			}
			if r.Summary == "" {
				t.Fatal("每一态都要有人话结论")
			}
		})
	}
}

// TestStealthArmedOnlyForRealRuleset **只有实测在位才算生效**。
// 这是本行动的核心不变式：不可判定、未上报、未开启一律不算。
func TestStealthArmedOnlyForRealRuleset(t *testing.T) {
	notArmed := []gwStealthInfo{
		{State: gwStealthState{Wanted: true, Root: true}},                                                    // ruleset nil
		{State: gwStealthState{Wanted: true, Root: true, Ruleset: ptrBool(false)}},                           // 明确不在
		{State: gwStealthState{Wanted: false, Root: true, Ruleset: ptrBool(true)}},                           // 规则集在但没开 -pf（全员连不上）
		{State: gwStealthState{Wanted: true, Root: false}},                                                   // 非 root
		{State: gwStealthState{Wanted: true, Root: true, Ruleset: ptrBool(true), GuardedPort: ptrInt(9999)}}, // 端口错配
		{State: gwStealthState{Wanted: true, Root: true, Ruleset: ptrBool(true), GuardedPort: nil}},          // 规则集在但没有 drop 规则
	}
	for i, info := range notArmed {
		if r := stealthReceiptOf("gw", "10.0.0.5:18443", info, true); r.Armed() {
			t.Errorf("第 %d 种形态不该算生效：%+v → %s", i, info.State, r.Summary)
		}
	}
}

// TestStealthWarningsCoverEveryNonArmedState 每一种非生效态都要有告警文案。
// ★「未启用」也必须有——那正是参考部署的默认形态，沉默会让页面上那句
// 「攻击面 = 0」继续成立。
func TestStealthWarningsCoverEveryNonArmedState(t *testing.T) {
	// ★每态钉一个**该态独有**的锚点，而不是只断言"有一条"。
	// 复核实测过：只断言条数与网关名时，把 off 那条换成
	// 「网关「%s」内核态隐身已生效，攻击面为 0。」全量用例照样绿——
	// 而这些串是后端下发、页面原样渲染的，被塞回去的恰好是本行动要杀掉的那句原话。
	all := map[string]string{
		StealthUnreported:    "版本较旧",
		StealthOff:           "三次握手",
		StealthNoRuleset:     "对全世界可见",
		StealthNoDropRule:    "没有默认 DROP 规则",
		StealthOrphanRuleset: "全部合法用户都连不上",
		StealthPortMismatch:  "未被隐身保护",
		StealthUnknown:       "不可判定",
	}
	for st, anchor := range all {
		// 带上 Summary：unknown 那条的告警直接引用它（两处各写一份结论必有一处说错）。
		w := stealthWarnings([]StealthReceipt{{GatewayID: "gw-1", Status: st,
			ProxyAddr: "10.0.0.5:18443", Summary: "（摘要）不可判定"}})
		if len(w) != 1 {
			t.Errorf("形态 %q 应产生 1 条告警，得到 %d 条", st, len(w))
			continue
		}
		if !strings.Contains(w[0], "gw-1") {
			t.Errorf("形态 %q 的告警要点名网关：%s", st, w[0])
		}
		if !strings.Contains(w[0], anchor) {
			t.Errorf("形态 %q 的告警应含该态独有的 %q，得到：%s", st, anchor, w[0])
		}
		// 任何一条告警都不该出现"已生效/攻击面为 0"这类反向措辞。
		for _, bad := range []string{"已生效", "攻击面为 0", "攻击面 = 0"} {
			if strings.Contains(w[0], bad) {
				t.Errorf("形态 %q 的告警出现了反向措辞 %q：%s", st, bad, w[0])
			}
		}
	}
	// 生效态一条都不该有（常态零噪声）。
	if w := stealthWarnings([]StealthReceipt{{GatewayID: "gw-1", Status: StealthArmed}}); len(w) != 0 {
		t.Errorf("生效时不该告警：%v", w)
	}
}

// TestGatewayPageCarriesStealthReceipt 网关页真下发回执（接线断言）。
// ★只测纯函数的话，把 handleGateway 里那几行删掉用例照样全绿（wave8 行动 2 的教训）。
func TestGatewayPageCarriesStealthReceipt(t *testing.T) {
	h := newTestServer(t)
	code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443", "spa": "10.0.0.5:18201",
		// ★要造「确定未启用」就必须明确说规则集不在：只说 wanted=false 的话
		// Ruleset 为 nil = 探不到 = 不可判定（机器上可能装着规则集，那是全员连不上）。
		"stealth": map[string]any{"wanted": false, "backend": "nftables(Linux)", "root": true,
			"ruleset": false},
	})
	if code != http.StatusOK {
		t.Fatalf("register http %d", code)
	}
	code, out := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /gateway http %d", code)
	}
	raw, _ := json.Marshal(out["stealth"])
	var rs []StealthReceipt
	if err := json.Unmarshal(raw, &rs); err != nil {
		t.Fatalf("解析回执失败：%v", err)
	}
	if len(rs) != 1 || rs[0].Status != StealthOff {
		t.Fatalf("应下发一条 off 回执，得到 %+v", rs)
	}
	if out["stealthArmed"].(float64) != 0 {
		t.Fatalf("未开 -pf 不该计入生效台数，得到 %v", out["stealthArmed"])
	}
	ws, _ := out["stealthWarnings"].([]any)
	if len(ws) != 1 {
		t.Fatalf("未启用应产生一条告警（沉默会让「攻击面 = 0」继续成立），得到 %v", ws)
	}
}

// TestStealthUnreportedNotOverwrittenByOldGateway 旧网关的心跳不得抹掉已有实测态。
// 与 nat/reach 同一条三态纪律：nil（字段缺席）不覆盖不清空。
func TestStealthUnreportedNotOverwrittenByOldGateway(t *testing.T) {
	h := newTestServer(t)
	// 先报一次真生效
	doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443",
		"stealth": map[string]any{"wanted": true, "backend": "nftables(Linux)", "root": true,
			"ruleset": true, "guardedPort": 18443},
	})
	// 再来一次不带 stealth 字段的心跳（旧网关形态）
	doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443",
	})
	_, out := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if got := out["stealthArmed"].(float64); got != 1 {
		t.Fatalf("缺字段的心跳把已有实测态抹掉了，stealthArmed=%v", got)
	}
}

// TestDiagStealthFailsOnMissingRuleset 「开了 -pf 但规则集不在」必须 fail，不是 warn。
// 它比"压根没开"更坏：管理侧看着像配好了，实际一点保护都没有。
func TestDiagStealthFailsOnMissingRuleset(t *testing.T) {
	h := newTestServer(t)
	doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443",
		"stealth": map[string]any{"wanted": true, "backend": "nftables(Linux)", "root": true,
			"ruleset": false, "detail": "内核里没有 table inet baidi"},
	})
	spa := diagCheck(t, getDiag(t, h), "spa")
	if spa["status"] != "fail" {
		t.Fatalf("规则集缺失应 fail，得到 %v（%v）", spa["status"], spa["summary"])
	}
	if h := spa["hint"].(string); !strings.Contains(h, "baidi-nft.sh") {
		t.Fatalf("提示要给出可执行的修复命令，得到 %q", h)
	}
}

// TestDiagStealthPassOnlyWhenAllArmed 全部实测生效才 pass。
func TestDiagStealthPassOnlyWhenAllArmed(t *testing.T) {
	h := newTestServer(t)
	armed := map[string]any{"wanted": true, "backend": "nftables(Linux)", "root": true,
		"ruleset": true, "guardedPort": 18443}
	doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443", "stealth": armed,
	})
	spa := diagCheck(t, getDiag(t, h), "spa")
	if spa["status"] != "pass" {
		t.Fatalf("全部实测生效应 pass，得到 %v（%v）", spa["status"], spa["summary"])
	}
	// 即便 pass，也必须说清这是网关自报而非外部扫描。
	if hint := spa["hint"].(string); !strings.Contains(hint, "外部扫描") && !strings.Contains(hint, "外网侧") {
		t.Fatalf("pass 时仍要点明「不是外部扫描结果」，得到 %q", hint)
	}

	// 再加一台未开的：立刻不能再 pass。
	doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayTokenFor("gw-b"), map[string]any{
		"id": "gw-b", "proxy": "10.0.0.6:18443",
		"stealth": map[string]any{"wanted": false, "backend": "nftables(Linux)", "root": true},
	})
	spa = diagCheck(t, getDiag(t, h), "spa")
	if spa["status"] == "pass" {
		t.Fatalf("有一台没生效就不该 pass，得到 %v", spa)
	}
	if m := spa["metric"].(string); !strings.Contains(m, "内核态隐身生效 1 / 在线 2") {
		t.Fatalf("指标应分开报生效台数与在线台数，得到 %q", m)
	}
}

// TestStealthReceiptsSkipOfflineGateways 离线网关的隐身态是**陈旧读数**，不得计入。
//
// ★复核实测过：`stealthReceipts` 里那句 `if !gatewayFresh(...) { continue }`
// 此前零覆盖——删掉它，全量 api 用例（59s）仍然全绿。两个方向都坏：
// 一台上次报 armed、之后已下线数小时的网关会继续撑着 stealthArmed 与 /diag 的 pass
// （把陈旧读数当实测，正是本行动要消灭的东西）；反向则是一台早已下线的 off 网关
// 永远顶着一条红色告警。
func TestStealthReceiptsSkipOfflineGateways(t *testing.T) {
	s, h, _ := newFailServer(t)
	doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443",
		"stealth": map[string]any{"wanted": true, "backend": "nftables(Linux)", "root": true,
			"ruleset": true, "guardedPort": 18443},
	})
	if rs := s.stealthReceipts(); len(rs) != 1 || !rs[0].Armed() {
		t.Fatalf("刚注册时应有一条 armed 回执，得到 %+v", rs)
	}
	// 把心跳拨到窗口外（模拟这台网关已经下线很久）。
	s.mu.Lock()
	g := s.gateways["gw-a"]
	g.LastSeen = time.Now().Add(-2 * gatewayOnlineWindow).Unix()
	s.gateways["gw-a"] = g
	s.mu.Unlock()

	if rs := s.stealthReceipts(); len(rs) != 0 {
		t.Fatalf("离线网关的隐身态是陈旧读数，不该出现在回执里，得到 %+v", rs)
	}
	if c := s.checkStealth(); c.Status == "pass" {
		t.Fatalf("唯一那台网关已离线，隐身不该还报 pass：%+v", c)
	}
}

// TestDiagStealthSeverityPerState /diag 的严重度**逐态**钉住。
//
// ★复核实测过：此前只有 no-ruleset 一条用例，把 fail 分桶削成
// `case StealthNoRuleset:`（另两态落回 warn）全量用例照样绿。
// orphan-ruleset 的后果是**全部合法用户连不上**，降成 warn 就把一次全域故障
// 混进了「未启用隐身」那类黄色噪声里；port-mismatch 则是隧道口全世界可见。
func TestDiagStealthSeverityPerState(t *testing.T) {
	cases := []struct {
		name    string
		stealth map[string]any
		want    string
	}{
		{"生效", map[string]any{"wanted": true, "root": true, "ruleset": true, "guardedPort": 18443}, "pass"},
		{"确定未启用", map[string]any{"wanted": true, "root": true, "ruleset": false}, "fail"},
		{"规则集缺 drop 规则", map[string]any{"wanted": true, "root": true, "ruleset": true}, "fail"},
		{"端口错配", map[string]any{"wanted": true, "root": true, "ruleset": true, "guardedPort": 19999}, "fail"},
		{"规则集在但没带 -pf", map[string]any{"wanted": false, "root": true, "ruleset": true}, "fail"},
		{"没开 -pf 且无规则集", map[string]any{"wanted": false, "root": true, "ruleset": false}, "warn"},
		{"非 root 探不到", map[string]any{"wanted": true, "root": false}, "warn"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTestServer(t)
			doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
				"id": "gw-a", "proxy": "10.0.0.5:18443", "stealth": c.stealth,
			})
			spa := diagCheck(t, getDiag(t, h), "spa")
			if spa["status"] != c.want {
				t.Fatalf("应为 %q，得到 %q（%v）", c.want, spa["status"], spa["summary"])
			}
		})
	}
}

// TestDiagStealthUndecidedIsNotCalledOff 全是不可判定时，摘要**不得**下「未启用」的结论。
//
// ★反方向的违反同样是违反：一台真正 armed 但以非 root 运行的网关，
// 会被「%d 台未启用内核态隐身、端口表现为 open」当面说成没隐身。
func TestDiagStealthUndecidedIsNotCalledOff(t *testing.T) {
	h := newTestServer(t)
	doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-a", "proxy": "10.0.0.5:18443",
		"stealth": map[string]any{"wanted": true, "backend": "nftables(Linux)", "root": false},
	})
	spa := diagCheck(t, getDiag(t, h), "spa")
	sum := spa["summary"].(string)
	// 查的是**断言式**措辞，不是"未启用"这三个字——摘要里那句
	// 「不可判定不等于未启用」是对的，不该被误判成违规。
	for _, bad := range []string{"台在线网关未启用", "台在线网关确定未启用", "表现为 open"} {
		if strings.Contains(sum, bad) {
			t.Fatalf("全是不可判定时不得下 %q 这种确定结论：%s", bad, sum)
		}
	}
	if !strings.Contains(sum, "不可判定") {
		t.Fatalf("应如实说不可判定：%s", sum)
	}
	if m := spa["metric"].(string); !strings.Contains(m, "不可判定 1") {
		t.Fatalf("指标应单列不可判定台数，得到 %q", m)
	}
}

// TestStealthWarningAgreesWithSummary 告警与摘要**不得自相矛盾**。
//
// ★这条是部署到演示站实测时抓到的：unknown 那条告警原本写死「开启了 -pf」，
// 而复核后 unknown 同时覆盖 wanted 的两种取值，于是同一张卡片上
// summary 说「未开启 -pf」、告警说「开启了 -pf」。两处各写一份结论，
// 迟早有一处说错——现在告警直接引用 Summary。
func TestStealthWarningAgreesWithSummary(t *testing.T) {
	for _, wanted := range []bool{true, false} {
		r := stealthReceiptOf("gw-1", "10.0.0.5:18443", gwStealthInfo{State: gwStealthState{
			Wanted: wanted, Backend: "nftables(Linux)", Root: false, Ruleset: nil,
			Detail: "非 root 运行，读不到内核规则集",
		}}, true)
		if r.Status != StealthUnknown {
			t.Fatalf("探不到规则集应为 unknown，得到 %q", r.Status)
		}
		w := stealthWarnings([]StealthReceipt{r})
		if len(w) != 1 {
			t.Fatalf("应产生 1 条告警，得到 %d", len(w))
		}
		// 告警里出现的「开没开 -pf」必须与摘要一致。
		wantOn := strings.Contains(r.Summary, "已开启 -pf")
		gotOn := strings.Contains(w[0], "已开启 -pf")
		if wantOn != gotOn {
			t.Fatalf("wanted=%v 时告警与摘要对「开没开 -pf」说法不一致\n  摘要：%s\n  告警：%s",
				wanted, r.Summary, w[0])
		}
		if strings.Contains(w[0], "开启了 -pf") && !wanted {
			t.Fatalf("wanted=false 却在告警里说「开启了 -pf」：%s", w[0])
		}
	}
}
