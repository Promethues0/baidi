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
