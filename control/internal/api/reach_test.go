package api

// 网关→后端可达性（wave7 行动 9）。钉三态与聚合方向：旧网关不报 ≠ 可达 ≠ 不可达；
// 多网关下"部分不可达"必须与"全可达"区分（落到那台网关的用户点开就炸）。

import (
	"net/http"
	"strings"
	"testing"
)

func TestReachAggregationAndDiag(t *testing.T) {
	h, _ := gwReceiptServer(t)

	// gw-1：res-oa 可达、res-db 不可达；gw-2：两个都可达
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), `{
		"id":"gw-1","proxy":":18443","spa":":18201",
		"reach":[{"id":"res-oa","ok":true,"ms":2,"ts":1754800000},
		         {"id":"res-db","ok":false,"err":"connection refused","ts":1754800000}]}`); w.Code != http.StatusOK {
		t.Fatalf("gw-1 注册 %d", w.Code)
	}
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), `{
		"id":"gw-2","proxy":":18443","spa":":18201",
		"reach":[{"id":"res-oa","ok":true,"ms":5,"ts":1754800000},
		         {"id":"res-db","ok":true,"ms":9,"ts":1754800000}]}`); w.Code != http.StatusOK {
		t.Fatalf("gw-2 注册 %d", w.Code)
	}
	// gw-old：旧网关，不带 reach 字段——不参与聚合，也不把任何资源拉成未知
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(),
		`{"id":"gw-old","proxy":":18444","spa":":18202"}`); w.Code != http.StatusOK {
		t.Fatalf("gw-old 注册 %d", w.Code)
	}

	code, out := doJSON(t, h, "GET", "/api/v1/resources/reach", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("reach http %d", code)
	}
	items, _ := out["items"].(map[string]any)
	oa := items["res-oa"].(map[string]any)
	db := items["res-db"].(map[string]any)
	if oa["status"] != "ok" {
		t.Fatalf("res-oa 两台都可达应 ok，实得 %v", oa)
	}
	if oa["ms"].(float64) != 2 {
		t.Fatalf("ms 应取最快的一次（2），实得 %v", oa["ms"])
	}
	if db["status"] != "partial" {
		t.Fatalf("res-db 一台不可达应 partial，实得 %v", db)
	}
	joined := strings.Join(anyToStrings(db["detail"]), " | ")
	if !strings.Contains(joined, "connection refused") || !strings.Contains(joined, "gw-2 可达") {
		t.Fatalf("detail 应逐网关带原因，实得 %s", joined)
	}

	// diag：partial 计入 badN → 整项 fail，明细里 res-db 是 warn
	code, d := doJSON(t, h, "GET", "/api/v1/diag", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("diag http %d", code)
	}
	var reach map[string]any
	for _, raw := range d["checks"].([]any) {
		c := raw.(map[string]any)
		if c["key"] == "backendReach" {
			reach = c
		}
	}
	if reach == nil {
		t.Fatal("diag 应含 backendReach 检查项")
	}
	if reach["status"] != "fail" || !strings.Contains(reach["summary"].(string), "点开") {
		t.Fatalf("有不可达资源应 fail 且指向症状，实得 %v", reach)
	}
}

// 三态：只有旧网关（无 reach）→ warn「未上报」；无网关 → skip。
func TestReachTriState(t *testing.T) {
	h, _ := gwReceiptServer(t)

	// 无网关：skip
	_, d := doJSON(t, h, "GET", "/api/v1/diag", adminToken(), nil)
	if st := diagCheckStatus(t, d, "backendReach"); st != "skip" {
		t.Fatalf("无网关应 skip，实得 %s", st)
	}

	// 只有旧网关：warn（未上报 ≠ 可达 ≠ 不可达）
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(),
		`{"id":"gw-old","proxy":":18444","spa":":18202"}`); w.Code != http.StatusOK {
		t.Fatal("注册失败")
	}
	_, d = doJSON(t, h, "GET", "/api/v1/diag", adminToken(), nil)
	if st := diagCheckStatus(t, d, "backendReach"); st != "warn" {
		t.Fatalf("旧网关未上报应 warn，实得 %s", st)
	}
	// 资源页视角：零聚合项（绝不显示"可达"）
	_, out := doJSON(t, h, "GET", "/api/v1/resources/reach", adminToken(), nil)
	if items, _ := out["items"].(map[string]any); len(items) != 0 {
		t.Fatalf("旧网关不应产生任何聚合项，实得 %v", items)
	}
}

func diagCheckStatus(t *testing.T, d map[string]any, key string) string {
	t.Helper()
	for _, raw := range d["checks"].([]any) {
		c := raw.(map[string]any)
		if c["key"] == key {
			return c["status"].(string)
		}
	}
	t.Fatalf("diag 缺检查项 %s", key)
	return ""
}

func anyToStrings(v any) []string {
	out := []string{}
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			if s2, ok := x.(string); ok {
				out = append(out, s2)
			}
		}
	}
	return out
}
