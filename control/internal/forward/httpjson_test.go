package forward

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// HTTP JSON 出口的真实往返：起 httptest 服务端，断言收到的载荷字段
// 与 store.AuditEntry 的 JSON 逐字段一致（含 seq/mac），凭据头真的注入了。
func TestHTTPForwarderRoundTrip(t *testing.T) {
	var mu sync.Mutex
	var body []byte
	var authHeader, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, authHeader, ctype = raw, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	f, err := NewHTTP(HTTPConfig{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer tok-1"}})
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	if err := f.Send(context.Background(), testRecords()); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if authHeader != "Bearer tok-1" {
		t.Errorf("凭据头未注入，实得 %q", authHeader)
	}
	if !strings.HasPrefix(ctype, "application/json") {
		t.Errorf("Content-Type 应为 json，实得 %q", ctype)
	}
	var got struct {
		Source  string           `json:"source"`
		Kind    string           `json:"kind"`
		Count   int              `json:"count"`
		Chain   string           `json:"chain"`
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("载荷不是合法 JSON: %v (%s)", err, body)
	}
	if got.Source != "baidi" || got.Kind != "audit" || got.Count != 2 || len(got.Records) != 2 {
		t.Fatalf("载荷头部不对: %+v", got)
	}
	if got.Chain == "" {
		t.Error("载荷应说明 seq/mac 是怎么算的，否则对接方不知道能拿它验真")
	}
	r0 := got.Records[0]
	// ★字段名必须与 GET /api/v1/audit 返回的条目完全一致（同一个 store.AuditEntry）。
	for k, want := range map[string]any{
		"time": "2026-08-11 09:15:04", "category": "admin", "user": "安全管理员",
		"srcIp": "10.0.0.9", "verdict": "ok", "seq": float64(41), "mac": "aa11bb22",
	} {
		if r0[k] != want {
			t.Errorf("记录字段 %s 期望 %v，实得 %v", k, want, r0[k])
		}
	}
}

// 非 2xx 必须报错，且把对端的状态码与响应片段带回去——
// 「发出去了但对面拒了」和「发成功了」必须能分开。
func TestHTTPForwarderNon2xxFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream index is read-only"))
	}))
	defer srv.Close()
	f, _ := NewHTTP(HTTPConfig{URL: srv.URL})
	err := f.Send(context.Background(), testRecords())
	if err == nil {
		t.Fatal("对端 502 时必须失败，否则队列会把这一批当成已送达而删掉")
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("错误信息应带对端状态码与响应片段，实得 %v", err)
	}
}

func TestHTTPForwarderConfigValidation(t *testing.T) {
	for name, cfg := range map[string]HTTPConfig{
		"缺 URL":     {},
		"协议不对":      {URL: "ftp://x/y"},
		"缺主机":       {URL: "http:///path"},
		"头含 CRLF":   {URL: "http://x/y", Headers: map[string]string{"X": "a\r\nY: b"}},
		"CA 不是 PEM": {URL: "https://x/y", CACert: "nope"},
	} {
		if _, err := NewHTTP(cfg); err == nil {
			t.Errorf("%s：应当被拒绝", name)
		}
	}
}

// 空批次不发请求（pump 不会给空批，但 Send 不该在空批上产生一次无意义的 POST）。
func TestHTTPForwarderEmptyBatchIsNoop(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	f, _ := NewHTTP(HTTPConfig{URL: srv.URL})
	if err := f.Send(context.Background(), nil); err != nil {
		t.Fatalf("空批不应报错: %v", err)
	}
	if hit {
		t.Error("空批不该产生请求")
	}
}
