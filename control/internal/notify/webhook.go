package notify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ── Webhook 通道（以及"短信"——它就是 webhook）──

// WebhookConfig 通用 HTTP webhook 配置。
type WebhookConfig struct {
	// URL 目标地址，必须是 http/https。https 之外会打 WARN——
	// 载荷里带着凭据头与告警内容，明文 http 等于把两者都摊开。
	URL string
	// Headers 自定义请求头。凭据（Bearer token / 签名 key）放在这里，
	// 由调用方从加密表解出来后注入，**不落在通道配置 JSON 里**。
	Headers map[string]string
	// Timeout 单次请求上界，默认 10s。
	Timeout time.Duration
	// SMS 为真时按短信载荷组装（mobiles + text）。
	//
	// ★这个开关是本文件唯一的"短信"实现。它不是任何一家网关的协议——
	// 见包注释里那段说明，UI 上必须如实标注。
	SMS bool

	Logger *slog.Logger
	// Client 留空取带超时的默认客户端。抽成字段是为了测试能塞 httptest 的。
	Client *http.Client
}

// WebhookChannel 一条已校验的 webhook 通道。并发安全。
type WebhookChannel struct {
	cfg    WebhookConfig
	client *http.Client
	log    *slog.Logger
}

var _ Channel = (*WebhookChannel)(nil)

const defaultWebhookTimeout = 10 * time.Second

// maxWebhookErrBody 失败时回读多少响应体进错误信息。
// 够看清对面的错误码/文案即可——整包读回来会让一个返回 10MB HTML 错误页的网关
// 把内存和审计表一起撑爆。
const maxWebhookErrBody = 512

// NewWebhook 归一化并校验配置。
func NewWebhook(cfg WebhookConfig) (*WebhookChannel, error) {
	c := cfg
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultWebhookTimeout
	}
	c.URL = strings.TrimSpace(c.URL)
	if c.URL == "" {
		return nil, fmt.Errorf("webhook: 未填写 URL: %w", ErrNotConfigured)
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("webhook: URL %q 非法: %v: %w", c.URL, err, ErrNotConfigured)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("webhook: URL 协议须为 http/https，实得 %q: %w", u.Scheme, ErrNotConfigured)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("webhook: URL 缺少主机名: %w", ErrNotConfigured)
	}
	// ★头名/头值一律禁 CRLF：凭据是管理员填的，而"管理员填的"在库被改写之后
	// 就不再可信。Go 的 http 也会在写出时拒绝非法头，但那时错误信息指不出是哪一项。
	for k, v := range c.Headers {
		if k == "" || hasCRLF(k) || hasCRLF(v) {
			return nil, fmt.Errorf("webhook: 请求头 %q 的名称或取值非法（含换行符）: %w", k, ErrNotConfigured)
		}
	}
	if u.Scheme == "http" {
		c.Logger.Warn("webhook 通道使用明文 http：请求头里的凭据与告警内容都会明文过网线",
			"host", u.Host, "sms", c.SMS)
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: c.Timeout}
	}
	return &WebhookChannel{cfg: c, client: client, log: c.Logger}, nil
}

// NewSMS 构造"短信"通道。
//
// ★它返回的就是一个 WebhookChannel。这里不做任何短信网关协议——
// 用户需要自己搭一跳把这个 JSON 转成阿里云/腾讯云的请求。之所以这样而不是
// 假装支持某家网关：假实现配完之后看起来一切正常，真出事那天一条都收不到，
// 且没有任何报错。诚实的适配至少让"这一跳归你"是写在脸上的。
func NewSMS(cfg WebhookConfig) (*WebhookChannel, error) {
	cfg.SMS = true
	return NewWebhook(cfg)
}

// webhookPayload 通用载荷。字段刻意扁平：对接方多半是一段几十行的转发脚本。
type webhookPayload struct {
	Source  string   `json:"source"`
	Kind    string   `json:"kind"`
	To      []string `json:"to,omitempty"`
	Mobiles []string `json:"mobiles,omitempty"`
	Subject string   `json:"subject,omitempty"`
	Body    string   `json:"body,omitempty"`
	Text    string   `json:"text,omitempty"`
	TS      int64    `json:"ts"`
}

// Send POST 一条 JSON。非 2xx 一律视为失败并把对端的状态码与响应片段带回去——
// 「发出去了但对面拒了」和「发成功了」必须能分开，否则通道页会长期显示绿色。
func (p *WebhookChannel) Send(ctx context.Context, to []string, subject, body string) error {
	rcpt := trimAll(to)
	if p.cfg.SMS && len(rcpt) == 0 {
		// 短信没有号码就等于没发。邮件同理（见 SMTPChannel.Send）；
		// 通用 webhook 则允许空收件人——它的收件人可能就写在对面的机器人配置里。
		return ErrNoRecipients
	}
	pl := webhookPayload{Source: "baidi", Kind: string(KindWebhook), TS: time.Now().Unix()}
	if p.cfg.SMS {
		pl.Kind = string(KindSMS)
		pl.Mobiles = rcpt
		pl.Text = subject
		if body != "" {
			pl.Text += "\n" + body
		}
	} else {
		pl.To = rcpt
		pl.Subject = subject
		pl.Body = body
	}
	raw, err := json.Marshal(pl)
	if err != nil {
		return fmt.Errorf("webhook: 载荷序列化失败: %v: %w", err, ErrSendFailed)
	}

	cctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, p.cfg.URL, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("webhook: 构造请求失败: %v: %w", err, ErrSendFailed)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "baidi-control/notify")
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: 请求 %s 失败: %v: %w", p.cfg.URL, err, ErrSendFailed)
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookErrBody))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: 对端返回 %d %s：%s: %w",
			resp.StatusCode, http.StatusText(resp.StatusCode), oneLine(string(snippet)), ErrSendFailed)
	}
	// 把响应体读干净再丢，让连接能被复用（不然每条告警都新建一次 TCP+TLS）。
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// oneLine 把响应片段压成一行：它要进错误信息，最终会落到审计表的 event 字段里，
// 带换行会把审计导出的 CSV 撕成两行。
func oneLine(s string) string {
	s = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s))
	if s == "" {
		return "（对端未返回内容）"
	}
	return s
}

// certPoolFromPEM 用给定 PEM 构造**只含这一把**的根证书池。
func certPoolFromPEM(pemStr string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemStr)) {
		return nil, fmt.Errorf("notify: CA 证书不是有效的 PEM: %w", ErrNotConfigured)
	}
	return pool, nil
}
