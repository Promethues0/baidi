package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 审计读取是 admin 专属：日志/链校验/导出对 role=user 一律 403。
func TestAuditEndpointsRequireAdmin(t *testing.T) {
	h := newTestServer(t)
	tok := userToken("li.fang")
	for _, path := range []string{"/api/v1/audit", "/api/v1/audit/verify", "/api/v1/audit/export"} {
		if code, _ := doJSON(t, h, "GET", path, tok, nil); code != http.StatusForbidden {
			t.Fatalf("user GET %s 应 403, got %d", path, code)
		}
	}
	if code, _ := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil); code != http.StatusOK {
		t.Fatal("admin 读审计应 200")
	}
}

// loginFrom 以指定 RemoteAddr/XFF 触发一次会落审计的动作（管理员登录失败）。
func loginFrom(t *testing.T, h http.Handler, remoteAddr, xff string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"wrong-password"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// 坏口令登录返回 200 + ok:false（凭据错误不暴露为状态码），审计仍会落一条 fail
	if rec.Code != http.StatusOK {
		t.Fatalf("坏口令登录应 200(ok:false), got %d", rec.Code)
	}
}

// latestSrcIP 取最新一条审计日志的源 IP。
func latestSrcIP(t *testing.T, h http.Handler) string {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读审计失败 %d", code)
	}
	logs := out["logs"].([]any)
	if len(logs) == 0 {
		t.Fatal("应有审计日志")
	}
	return logs[0].(map[string]any)["srcIp"].(string)
}

// 审计源 IP 信任边界：直连对端不在 BAIDI_TRUSTED_PROXIES（默认仅回环）内时，
// 伪造的 X-Forwarded-For 一律忽略；经信任代理转发时才采纳 XFF（取最右的非信任地址）。
func TestAuditSrcIPTrustBoundary(t *testing.T) {
	h := newTestServer(t)

	// 直连伪造 XFF：记 RemoteAddr，不记伪造值
	loginFrom(t, h, "203.0.113.9:41234", "6.6.6.6")
	if ip := latestSrcIP(t, h); ip != "203.0.113.9" {
		t.Fatalf("直连伪造 XFF 应记 RemoteAddr, got %q", ip)
	}
	// 经信任代理（默认 127.0.0.1/32）：采纳 XFF
	loginFrom(t, h, "127.0.0.1:9999", "198.51.100.7")
	if ip := latestSrcIP(t, h); ip != "198.51.100.7" {
		t.Fatalf("经信任代理应采纳 XFF, got %q", ip)
	}
	// 客户端在 XFF 前面塞了伪造段：只信最右的非信任地址（信任代理亲手追加的那段）
	loginFrom(t, h, "127.0.0.1:9999", "6.6.6.6, 198.51.100.7")
	if ip := latestSrcIP(t, h); ip != "198.51.100.7" {
		t.Fatalf("多段 XFF 应取最右非信任地址, got %q", ip)
	}
	// 经信任代理但 XFF 是脏值：回退 RemoteAddr，不把垃圾写进审计
	loginFrom(t, h, "127.0.0.1:9999", "not-an-ip")
	if ip := latestSrcIP(t, h); ip != "127.0.0.1" {
		t.Fatalf("脏 XFF 应回退 RemoteAddr, got %q", ip)
	}
}

// 链校验端点：正常库全链通过，checked 与落库条数一致。
func TestAuditVerifyEndpoint(t *testing.T) {
	h := newTestServer(t)
	loginFrom(t, h, "203.0.113.9:41234", "") // 制造 1 条审计
	code, out := doJSON(t, h, "GET", "/api/v1/audit/verify", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("verify 应 200, got %d", code)
	}
	if out["ok"] != true || out["checked"].(float64) < 1 || out["brokenAt"].(float64) != 0 {
		t.Fatalf("正常链应通过: %v", out)
	}
}

// CSV 导出：附件头 + BOM + 表头 + 数据行；category 过滤生效；非法 category 400。
func TestAuditExportCSV(t *testing.T) {
	h := newTestServer(t)
	loginFrom(t, h, "203.0.113.9:41234", "") // auth 类
	// admin 类：保存一条基线
	body := map[string]any{"name": "导出测试基线", "type": "onboarding", "disposal": "block", "status": "enabled",
		"platforms": []string{"macOS"},
		"checks":    []map[string]string{{"key": "disk_encrypted", "label": "磁盘已加密", "platform": "All", "severity": "high"}}}
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(), body); code != http.StatusOK {
		t.Fatal("保存基线失败")
	}

	export := func(query string) (*httptest.ResponseRecorder, string) {
		req := httptest.NewRequest("GET", "/api/v1/audit/export"+query, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		b, _ := io.ReadAll(rec.Body)
		return rec, string(b)
	}

	rec, csvBody := export("")
	if rec.Code != http.StatusOK {
		t.Fatalf("导出应 200, got %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "baidi-audit-") || !strings.Contains(cd, ".csv") {
		t.Fatalf("应带日期文件名附件头: %q", cd)
	}
	if !strings.HasPrefix(csvBody, "\xEF\xBB\xBF") {
		t.Fatal("应带 UTF-8 BOM")
	}
	if !strings.Contains(csvBody, "时间,类别,行为人,源IP,事件,判定") {
		t.Fatalf("应有表头: %q", csvBody[:100])
	}
	if !strings.Contains(csvBody, "管理员登录失败") || !strings.Contains(csvBody, "导出测试基线") {
		t.Fatalf("应含 auth 与 admin 两类记录: %s", csvBody)
	}

	// category 过滤：只剩 auth 行
	_, authOnly := export("?category=auth")
	if !strings.Contains(authOnly, "管理员登录失败") || strings.Contains(authOnly, "导出测试基线") {
		t.Fatalf("category=auth 应过滤掉 admin 行: %s", authOnly)
	}
	// 未来时间窗：只有表头
	_, empty := export("?from=2099-01-01&to=2099-01-02")
	if strings.Count(strings.TrimSpace(empty), "\n") != 0 || !strings.Contains(empty, "时间,") {
		t.Fatalf("未来时间窗应只有表头: %q", empty)
	}
	// 非法 category 400
	if rec, _ := export("?category=mirror"); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 category 应 400, got %d", rec.Code)
	}
	// 导出动作本身留痕（措辞记已发生的事实）
	_, out := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil)
	found := false
	for _, l := range out["logs"].([]any) {
		if ev, _ := l.(map[string]any)["event"].(string); strings.Contains(ev, "导出审计日志 CSV") {
			found = true
		}
	}
	if !found {
		t.Fatal("导出完成后应落一条审计")
	}
}

// CSV 公式注入：行为人一列就是攻击者可控的登录用户名，以 = + - @ 开头的
// 单元格在电子表格里会被当公式求值。导出必须加「强制文本」前缀中和。
func TestAuditExportNeutralizesFormulaInjection(t *testing.T) {
	h := newTestServer(t)
	payload := `=cmd|'/C calc'!A1`
	req := httptest.NewRequest("POST", "/api/v1/auth/login",
		strings.NewReader(`{"username":"`+payload+`","password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.9:41234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("坏口令登录应 200(ok:false), got %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/api/v1/audit/export", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	csvBody := string(body)
	if !strings.Contains(csvBody, ",'"+payload) {
		t.Fatalf("公式前缀单元格应被加 ' 中和: %s", csvBody)
	}
	if strings.Contains(csvBody, ","+payload) {
		t.Fatalf("导出不应含裸公式单元格: %s", csvBody)
	}
}

// csvCell 口径：危险首字符加前缀，正常值原样。
func TestCSVCell(t *testing.T) {
	for in, want := range map[string]string{
		"":           "",
		"2026-08-10": "2026-08-10",
		"管理员登录失败":    "管理员登录失败",
		"=1+1":       "'=1+1",
		"+SUM(A1)":   "'+SUM(A1)",
		"-2+3":       "'-2+3",
		"@fn":        "'@fn",
		"\tX":        "'\tX",
		"\rX":        "'\rX",
	} {
		if got := csvCell(in); got != want {
			t.Fatalf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}
