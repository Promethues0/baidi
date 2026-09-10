package api

// 数据面回执通道（心跳捎带 events → 审计）与网关版本上报的接口测试。
// 走迁移期明文口（compat=true）+ 自签 gateway 令牌，复用 gwidentity_test.go 的基建——
// 这里验的是 JSON 契约与审计落库，不是 mTLS 握手。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// gwReceiptServer 构造控制面并把 store 一并交出（断言审计落库用）。
func gwReceiptServer(t *testing.T) (http.Handler, *store.SQLiteStore) {
	t.Helper()
	st := openTestSQLite(t)
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), st
}

func postJSONWithToken(h http.Handler, path, tok, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// dataplaneAudits 取当前库里 category=dataplane 的审计条目。
func dataplaneAudits(t *testing.T, st *store.SQLiteStore) []store.AuditEntry {
	t.Helper()
	b, err := st.Audit(t.Context())
	if err != nil {
		t.Fatalf("读审计失败：%v", err)
	}
	var out []store.AuditEntry
	for _, e := range b.Logs {
		if e.Category == "dataplane" {
			out = append(out, e)
		}
	}
	return out
}

// 心跳带 events：逐条落审计（category=dataplane，行为人=网关，措辞转述网关报告的事实），
// version 存进网关表并在 GET /api/v1/gateways 带出。
func TestGatewayRegisterEventsAuditedAndVersionExposed(t *testing.T) {
	h, st := gwReceiptServer(t)
	body := `{
		"id":"gw-1","proxy":":18443","spa":":18201","clients":1,"tunnels":2,"uptime":60,
		"version":"v9.9.9",
		"events":[
			{"ts":1754800000,"kind":"revoke-applied","detail":"已撤销用户 li.fang 的放行窗口：封禁敲门至 12:00:00、撤销放行 1 个源IP、切断 1 条隧道"},
			{"ts":1754800001,"kind":"policy-applied","detail":"资源授权策略已生效：资源数 3→4"}
		]
	}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}

	audits := dataplaneAudits(t, st)
	if len(audits) != 2 {
		t.Fatalf("dataplane 审计条数 %d，期望 2", len(audits))
	}
	// Audit 按 id 倒序返回：后写的 policy-applied 在前
	var revoke store.AuditEntry
	for _, e := range audits {
		if strings.Contains(e.Event, "li.fang") {
			revoke = e
		}
	}
	if !strings.Contains(revoke.Event, "网关 gw-1 报告：") {
		t.Errorf("审计措辞应转述网关报告的事实（网关 X 报告：…），实际：%q", revoke.Event)
	}
	if !strings.Contains(revoke.Event, "已撤销用户 li.fang 的放行窗口") {
		t.Errorf("审计应含撤销事实与用户，实际：%q", revoke.Event)
	}
	if revoke.User != "gw-1" {
		t.Errorf("行为人应为网关自身 gw-1，实际：%q", revoke.User)
	}

	// version 经 GET /api/v1/gateways 带出（admin 视角）
	adminTok := testKeys.Sign(auth.Claims{Sub: "admin", Role: "admin", Name: "admin"}, tokenTTL)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/gateways", nil)
	r.Header.Set("Authorization", "Bearer "+adminTok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("拉网关清单返回 %d", w.Code)
	}
	var resp struct {
		Gateways []GatewayDetail `json:"gateways"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析网关清单失败：%v", err)
	}
	if len(resp.Gateways) != 1 || resp.Gateways[0].Version != "v9.9.9" {
		t.Fatalf("网关清单应带 version=v9.9.9，实际：%+v", resp.Gateways)
	}
}

// 兼容：旧网关不带 version/events 的心跳必须照常成功（JSON 缺省零值），
// 不产生任何 dataplane 审计，version 落空串（前端显示 "—"）。
func TestGatewayRegisterWithoutEventsStillWorks(t *testing.T) {
	h, st := gwReceiptServer(t)
	body := `{"id":"gw-old","proxy":":18443","spa":":18201","clients":0,"tunnels":0,"uptime":5}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("旧网关心跳应照常成功，返回 %d：%s", w.Code, w.Body.String())
	}
	if audits := dataplaneAudits(t, st); len(audits) != 0 {
		t.Fatalf("不带 events 不应落 dataplane 审计，实际 %d 条", len(audits))
	}

	adminTok := testKeys.Sign(auth.Claims{Sub: "admin", Role: "admin", Name: "admin"}, tokenTTL)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/gateways", nil)
	r.Header.Set("Authorization", "Bearer "+adminTok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var resp struct {
		Gateways []GatewayDetail `json:"gateways"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析网关清单失败：%v", err)
	}
	if len(resp.Gateways) != 1 || resp.Gateways[0].Version != "" {
		t.Fatalf("旧网关 version 应为空串（前端降级显示 —），实际：%+v", resp.Gateways)
	}
}

// 解码前限体：多 GB 心跳（events/sessions 数组无界）不能先整包进内存再截断——
// 64 条截断只限制审计放大，拦不住解码期内存耗尽。超过 1 MiB 应明确 413，
// 而不是静默注册出一台零统计的网关。
func TestGatewayRegisterBodyTooLargeRejected(t *testing.T) {
	h, st := gwReceiptServer(t)
	// 1 MiB + 余量的合法 JSON：超限点在读取期就触发，与字段内容无关
	body := `{"id":"gw-1","version":"` + strings.Repeat("x", 1<<20+1024) + `"}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限心跳应 413，返回 %d", w.Code)
	}
	if audits := dataplaneAudits(t, st); len(audits) != 0 {
		t.Fatalf("被拒的心跳不应落任何 dataplane 审计，实际 %d 条", len(audits))
	}
	// 正常尺寸照常成功（回归护栏）
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), `{"id":"gw-1"}`); w.Code != http.StatusOK {
		t.Fatalf("正常心跳应 200，返回 %d：%s", w.Code, w.Body.String())
	}
}

// 安全事件（sec-deny）：审计 verdict=deny（不再一律 ok）+ 机读字段落攻击源统计；
// 回执类事件维持 verdict=ok；旧网关不带机读字段时审计照落、统计不炸。
func TestGatewaySecEventsVerdictAndAttackStats(t *testing.T) {
	h, st := gwReceiptServer(t)
	body := `{
		"id":"gw-1","proxy":":18443","spa":":18201",
		"events":[
			{"ts":1754800000,"kind":"sec-deny","detail":"SPA 敲门拒绝（令牌无效）","src":"203.0.113.9","cat":"knock-token","count":37},
			{"ts":1754800001,"kind":"policy-applied","detail":"资源授权策略已生效：资源数 3→4"},
			{"ts":1754800002,"kind":"sec-deny","detail":"旧网关形态：无机读字段"}
		]}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}
	byVerdict := map[string]int{}
	for _, e := range dataplaneAudits(t, st) {
		byVerdict[e.Verdict]++
	}
	if byVerdict["deny"] != 2 || byVerdict["ok"] != 1 {
		t.Fatalf("sec-deny 应落 deny、回执落 ok，实得 %v", byVerdict)
	}
	// 机读字段齐全的那条计入攻击源；缺字段的那条只留审计不进统计
	atk, err := st.AttackStats(t.Context(), 24)
	if err != nil {
		t.Fatal(err)
	}
	if atk.Sources != 1 || atk.Denies != 37 {
		t.Fatalf("攻击统计应只计入带机读字段的事件，实得 %+v", atk)
	}
	if len(atk.Top) != 1 || atk.Top[0].IP != "203.0.113.9" {
		t.Fatalf("TOP 应为上报来源，实得 %+v", atk.Top)
	}
	// 安全概览的隐身防线由同一份统计驱动
	code, out := doJSON(t, h, "GET", "/api/v1/overview", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("overview http %d", code)
	}
	am, _ := out["attack"].(map[string]any)
	if am == nil || am["denies"].(float64) != 37 {
		t.Fatalf("概览应带攻击统计，实得 %v", out["attack"])
	}
	found := false
	for _, raw := range out["defense"].([]any) {
		d := raw.(map[string]any)
		if d["key"] == "attack" {
			found = true
			top, _ := d["top"].([]any)
			if len(top) != 1 || !strings.Contains(top[0].(string), "203.0.113.9") {
				t.Fatalf("隐身防线 TOP 应含攻击源，实得 %v", top)
			}
		}
	}
	if !found {
		t.Fatal("防线应含 attack 格")
	}
}

// 网关并发到顶的拒绝：**落审计 deny，但绝不进攻击源统计**。
//
// ★判据是归因不是严重性。攻击源面板回答的是「谁在打我、要不要封他」，
// 而容量打满归因于我方网关的并发上限——把触发它的那个 IP 列进「攻击源 TOP5」，
// 管理员会去封一个正常用户，真正该做的是扩容。方向与「放行绝不进攻击源统计」同源。
// 同时拒绝本身必须留在审计里：用户确实没连上，这件事得查得到。
func Test容量拒绝落审计但不进攻击源统计(t *testing.T) {
	h, st := gwReceiptServer(t)
	body := `{
		"id":"gw-1","proxy":":18443","spa":":18201",
		"events":[
			{"ts":1754800000,"kind":"sec-deny","detail":"网关同时活跃隧道连接已达上限 1024，新连接被拒","src":"10.20.30.40","cat":"proxy-capacity","count":9},
			{"ts":1754800001,"kind":"sec-deny","detail":"SPA 敲门拒绝（令牌重放）","src":"203.0.113.9","cat":"knock-replay","count":4}
		]}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}
	// 两条都得在审计里，且都是 deny——容量拒绝不是"允许"，用户是真没连上。
	var capacitySeen bool
	byVerdict := map[string]int{}
	for _, e := range dataplaneAudits(t, st) {
		byVerdict[e.Verdict]++
		if strings.Contains(e.Event, "已达上限") {
			capacitySeen = true
			if e.Verdict != "deny" {
				t.Fatalf("容量拒绝的 verdict 应为 deny，实得 %q", e.Verdict)
			}
			if e.SrcIP != "10.20.30.40" {
				t.Fatalf("容量拒绝应记网关报来的源 IP，实得 %q", e.SrcIP)
			}
		}
	}
	if !capacitySeen {
		t.Fatal("容量拒绝没有落审计——网关一重启这件事就查不到了")
	}
	if byVerdict["deny"] != 2 {
		t.Fatalf("两条都应落 deny，实得 %v", byVerdict)
	}
	// 攻击统计里只能有敲门重放那一条。
	atk, err := st.AttackStats(t.Context(), 24)
	if err != nil {
		t.Fatal(err)
	}
	if atk.Sources != 1 || atk.Denies != 4 {
		t.Fatalf("容量拒绝混进了攻击源统计：%+v（应只含 knock-replay 的 4 次）", atk)
	}
	for _, top := range atk.Top {
		if top.IP == "10.20.30.40" {
			t.Fatalf("触发容量上限的正常用户被列进了攻击源 TOP：%+v——管理员会去封他，而该做的是扩容", atk.Top)
		}
	}
}

// 时钟超窗的敲门拒绝：落审计 deny，但**绝不进攻击源统计**（wave11 行动 11-①）。
//
// ★这一条与容量拒绝是同一族，但成因方向更刺眼：客户端保活每 15s 敲一次、
// 每轮敲全部落点，一台时钟偏了 31 秒的**正常员工机**一天稳定产出几千次超窗拒绝——
// 计进攻击源它必然是 TOP1，而此前它与真重放共用类别、中文名逐字写着
// 「敲门信封无效/重放」，管理员照着面板去封的是自己的员工。
// 真重放（knock-replay / knock-envelope 的 nonce 重复）照旧计入，本用例一起钉住。
func Test时钟超窗落审计但不进攻击源统计(t *testing.T) {
	h, st := gwReceiptServer(t)
	body := `{
		"id":"gw-1","proxy":":18443","spa":":18201",
		"events":[
			{"ts":1754800000,"kind":"sec-deny","detail":"SPA 敲门拒绝：敲门包时间戳比网关当前时间早 47 秒（超出允许的 ±30 秒）；多半是终端时钟慢了，也可能是延迟到达的旧包","src":"10.20.30.41","cat":"knock-clockskew","count":812},
			{"ts":1754800001,"kind":"sec-deny","detail":"SPA 敲门拒绝（信封无效/被动重放）","src":"203.0.113.9","cat":"knock-envelope","count":4}
		]}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}
	var skewSeen bool
	for _, e := range dataplaneAudits(t, st) {
		if strings.Contains(e.Event, "时间戳比网关当前时间早") {
			skewSeen = true
			if e.Verdict != "deny" {
				t.Fatalf("超窗拒绝的 verdict 应为 deny，实得 %q", e.Verdict)
			}
			// 偏移量必须原样进审计：这台机器一直连不上，运维要靠它知道该往哪调时钟。
			if !strings.Contains(e.Event, "47 秒") {
				t.Fatalf("超窗拒绝的审计正文应带实测偏移，实得 %q", e.Event)
			}
			if e.SrcIP != "10.20.30.41" {
				t.Fatalf("应记网关报来的源 IP，实得 %q", e.SrcIP)
			}
		}
	}
	if !skewSeen {
		t.Fatal("时钟超窗没有落审计——那台机器为什么连不上就再也查不到了")
	}
	atk, err := st.AttackStats(t.Context(), 24)
	if err != nil {
		t.Fatal(err)
	}
	if atk.Sources != 1 || atk.Denies != 4 {
		t.Fatalf("时钟超窗混进了攻击源统计：%+v（应只含 knock-envelope 的 4 次）", atk)
	}
	for _, top := range atk.Top {
		if top.IP == "10.20.30.41" {
			t.Fatalf("时钟不准的正常终端被列进攻击源 TOP：%+v——管理员会去封自己的员工，而该做的是给那台机器校时", atk.Top)
		}
	}
}

// 类别中文名是展示的唯一真相：新加的类别必须有名字，且不许再叫「重放」。
//
// ★没有名字时控制面原样显示 key（`attackCatLabel` 的兜底），页面上会出现一串英文——
// 那是给「新网关先于控制面升级」的过渡期留的，不是给同批新增的类别用的。
func Test时钟超窗类别有中文名且不写成重放(t *testing.T) {
	zh, ok := store.AttackCatZh["knock-clockskew"]
	if !ok {
		t.Fatal("knock-clockskew 缺中文名——页面会直接显示英文 key")
	}
	if strings.Contains(zh, "重放") {
		t.Fatalf("时钟偏差的中文名不许出现「重放」（那正是要消灭的错归因），实得 %q", zh)
	}
	if !strings.Contains(zh, "时钟") {
		t.Fatalf("中文名必须点名「时钟」，否则管理员不知道该去做什么，实得 %q", zh)
	}
}
