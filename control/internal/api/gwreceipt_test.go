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
