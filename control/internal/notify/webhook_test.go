package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type capturedReq struct {
	Method  string
	Headers http.Header
	Body    map[string]any
}

// newCapturingWebhook 起一个记录请求的 httptest 服务端，status 为它的应答码。
func newCapturingWebhook(t *testing.T, status int, respBody string) (*httptest.Server, func() []capturedReq) {
	t.Helper()
	var mu sync.Mutex
	var got []capturedReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		m := map[string]any{}
		_ = json.Unmarshal(raw, &m)
		mu.Lock()
		got = append(got, capturedReq{Method: r.Method, Headers: r.Header.Clone(), Body: m})
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []capturedReq {
		mu.Lock()
		defer mu.Unlock()
		return append([]capturedReq{}, got...)
	}
}

func TestWebhook_成功投递并携带凭据头(t *testing.T) {
	srv, reqs := newCapturingWebhook(t, http.StatusOK, `{"ok":true}`)
	ch, err := NewWebhook(WebhookConfig{
		URL:     srv.URL + "/hook",
		Headers: map[string]string{"Authorization": "Bearer tok-123", "X-Env": "prod"},
	})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if err := ch.Send(context.Background(), []string{"soc@corp.example"}, "主题", "正文"); err != nil {
		t.Fatalf("发送应成功: %v", err)
	}
	got := reqs()
	if len(got) != 1 {
		t.Fatalf("应收到 1 次请求，实得 %d", len(got))
	}
	r := got[0]
	if r.Method != http.MethodPost {
		t.Errorf("方法 = %s", r.Method)
	}
	if r.Headers.Get("Authorization") != "Bearer tok-123" || r.Headers.Get("X-Env") != "prod" {
		t.Errorf("自定义头未透传：%v", r.Headers)
	}
	if !strings.HasPrefix(r.Headers.Get("Content-Type"), "application/json") {
		t.Errorf("Content-Type = %q", r.Headers.Get("Content-Type"))
	}
	if r.Body["subject"] != "主题" || r.Body["body"] != "正文" || r.Body["kind"] != "webhook" {
		t.Errorf("载荷 = %v", r.Body)
	}
	to, _ := r.Body["to"].([]any)
	if len(to) != 1 || to[0] != "soc@corp.example" {
		t.Errorf("载荷 to = %v", r.Body["to"])
	}
}

// 非 2xx 必须视为失败，并把对端状态码与响应片段带回来——
// 「发出去了但对面拒了」被记成成功，通道页就会长期显示绿色。
func TestWebhook_非2xx视为失败(t *testing.T) {
	srv, _ := newCapturingWebhook(t, http.StatusInternalServerError, `{"error":"upstream down"}`)
	ch, _ := NewWebhook(WebhookConfig{URL: srv.URL})
	err := ch.Send(context.Background(), nil, "s", "b")
	if err == nil {
		t.Fatal("★对端 500 却被当成发送成功")
	}
	if !errors.Is(err, ErrSendFailed) {
		t.Errorf("应归类为发送失败: %v", err)
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "upstream down") {
		t.Errorf("错误信息应含状态码与对端响应片段: %v", err)
	}
	if strings.ContainsAny(err.Error(), "\r\n") {
		t.Error("错误信息里含换行——它会进审计表 event 字段，会把导出的 CSV 撕成两行")
	}
}

// 短信通道就是 webhook：载荷用 mobiles + text，且**如实**标注 kind=sms。
func TestSMS_载荷是mobiles加text且如实标注(t *testing.T) {
	srv, reqs := newCapturingWebhook(t, http.StatusOK, "ok")
	ch, err := NewSMS(WebhookConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if err := ch.Send(context.Background(), []string{"13800000000"}, "【白帝】告警", "详情"); err != nil {
		t.Fatalf("发送应成功: %v", err)
	}
	b := reqs()[0].Body
	if b["kind"] != "sms" {
		t.Errorf("kind = %v，短信载荷必须自报家门", b["kind"])
	}
	mob, _ := b["mobiles"].([]any)
	if len(mob) != 1 || mob[0] != "13800000000" {
		t.Errorf("mobiles = %v", b["mobiles"])
	}
	if b["text"] != "【白帝】告警\n详情" {
		t.Errorf("text = %q", b["text"])
	}
	if _, has := b["subject"]; has {
		t.Error("短信载荷不该带 subject（对接方只会读 text）")
	}
}

// 短信没有号码 = 没发。不许当成功。
func TestSMS_无号码报错(t *testing.T) {
	srv, _ := newCapturingWebhook(t, http.StatusOK, "ok")
	ch, _ := NewSMS(WebhookConfig{URL: srv.URL})
	if err := ch.Send(context.Background(), nil, "s", "b"); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("应报「无收件人」，实得 %v", err)
	}
}

func TestWebhook_配置校验(t *testing.T) {
	cases := []struct {
		name string
		cfg  WebhookConfig
	}{
		{"空 URL", WebhookConfig{}},
		{"非 http 协议", WebhookConfig{URL: "ftp://x/y"}},
		{"file 协议", WebhookConfig{URL: "file:///etc/passwd"}},
		{"缺主机名", WebhookConfig{URL: "http:///path"}},
		{"头名含换行", WebhookConfig{URL: "https://x/y", Headers: map[string]string{"X-A\r\nB": "v"}}},
		{"头值含换行", WebhookConfig{URL: "https://x/y", Headers: map[string]string{"X-A": "v\r\nX-B: c"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewWebhook(c.cfg); err == nil {
				t.Fatal("应拒绝该配置")
			} else if !errors.Is(err, ErrNotConfigured) {
				t.Errorf("应归类为配置错误: %v", err)
			}
		})
	}
}

// 超时必须真生效：一个装死的对端不能把派发 goroutine 永久挂住。
func TestWebhook_超时(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// ★清理是 LIFO：先放行 handler，再关服务端。反过来的话 srv.Close 会等着
	// 那个还卡在 <-block 的 handler，测试直接挂到超时。
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(block) })
	ch, _ := NewWebhook(WebhookConfig{URL: srv.URL, Timeout: 200 * time.Millisecond})
	start := time.Now()
	if err := ch.Send(context.Background(), nil, "s", "b"); err == nil {
		t.Fatal("装死的对端应当超时报错")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("超时没生效，耗时 %v", el)
	}
}
