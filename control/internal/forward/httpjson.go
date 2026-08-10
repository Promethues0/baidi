package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ── 通用 HTTP JSON 出口（SIEM / ELK / 自建收集器）──
//
// 载荷是一批记录，不是一条：审计是流式的，一条一个请求会让 HTTP 开销
// 远大于内容本身，而且对端限流时更容易整批失败。批量语义与队列的
// 「整批成功才出队」正好对齐。

const defaultHTTPTimeout = 15 * time.Second

// maxHTTPErrBody 失败时回读多少响应体进错误信息。够看清对面的错误码/文案即可——
// 整包读回来会让一个返回 10MB HTML 错误页的网关把内存和审计表一起撑爆。
const maxHTTPErrBody = 512

// HTTPConfig 通用 HTTP JSON 出口配置。
type HTTPConfig struct {
	// URL 目标地址，必须是 http/https。明文 http 会打 WARN。
	URL string
	// Headers 自定义请求头。凭据（Bearer token / API key）由调用方从加密表解出来
	// 后注入，**不落在出口配置 JSON 里**。
	Headers map[string]string
	// CACert 校验服务端证书用的 CA（PEM），仅 https 生效。留空用系统池；
	// 填了就只信这一把。与 syslog 同款：这里同样**没有**跳过校验的开关。
	CACert  string
	Timeout time.Duration

	Logger *slog.Logger
	// Client 留空取带超时的默认客户端。抽成字段是为了测试能塞 httptest 的。
	Client *http.Client
}

// HTTPForwarder 一条已校验的 HTTP JSON 出口。并发安全。
type HTTPForwarder struct {
	cfg    HTTPConfig
	client *http.Client
	log    *slog.Logger
}

var _ Forwarder = (*HTTPForwarder)(nil)

// httpPayload 外送载荷。
//
// ★records 里每一项就是 store.AuditEntry 的 JSON——与 `GET /api/v1/audit`
// 返回的日志条目逐字段相同（同一个结构体，见 Record 的类型别名）。
// 对接方按同一份字段写解析器即可，不必为"外送版"再写一套。
type httpPayload struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	SentAt int64  `json:"sentAt"`
	Count  int    `json:"count"`
	// Chain 说明 seq/mac 是什么，让对接方知道这两格可以拿来独立验真。
	Chain   string   `json:"chain"`
	Records []Record `json:"records"`
}

// chainNote 随载荷下发的链说明。写死在这里而不是让管理员配：它描述的是
// 代码里 auditMAC 的实际算法，管理员改不了也不该能改。
const chainNote = "HMAC-SM3(prev_mac‖ts‖category‖actor‖srcIp‖event‖verdict)，seq 为链内序号"

// NewHTTP 归一化并校验配置。
func NewHTTP(cfg HTTPConfig) (*HTTPForwarder, error) {
	c := cfg
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultHTTPTimeout
	}
	c.URL = strings.TrimSpace(c.URL)
	if c.URL == "" {
		return nil, fmt.Errorf("http 外送: 未填写 URL: %w", ErrNotConfigured)
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("http 外送: URL %q 非法: %v: %w", c.URL, err, ErrNotConfigured)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("http 外送: URL 协议须为 http/https，实得 %q: %w", u.Scheme, ErrNotConfigured)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("http 外送: URL 缺少主机名: %w", ErrNotConfigured)
	}
	// 头名/头值一律禁 CRLF：凭据是管理员填的，而"管理员填的"在库被改写之后就不再可信。
	for k, v := range c.Headers {
		if k == "" || strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("http 外送: 请求头 %q 的名称或取值非法（含换行符）: %w", k, ErrNotConfigured)
		}
	}
	if u.Scheme == "http" {
		c.Logger.Warn("审计外送使用明文 http：请求头里的凭据与全量审计正文都会明文过网线", "host", u.Host)
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: c.Timeout}
		if pemStr := strings.TrimSpace(c.CACert); pemStr != "" {
			pool, perr := certPoolFromPEM(pemStr)
			if perr != nil {
				return nil, perr
			}
			client.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			}
		}
	}
	return &HTTPForwarder{cfg: c, client: client, log: c.Logger}, nil
}

// Target 返回目标 URL（展示用；凭据在头里，不在 URL 里）。
func (p *HTTPForwarder) Target() string { return p.cfg.URL }

// Send POST 一批记录。非 2xx 一律视为失败并把对端的状态码与响应片段带回去——
// 「发出去了但对面拒了」和「发成功了」必须能分开，否则外送页会长期显示绿色。
func (p *HTTPForwarder) Send(ctx context.Context, batch []Record) error {
	if len(batch) == 0 {
		return nil
	}
	raw, err := json.Marshal(httpPayload{
		Source: "baidi", Kind: "audit", SentAt: time.Now().Unix(),
		Count: len(batch), Chain: chainNote, Records: batch,
	})
	if err != nil {
		return fmt.Errorf("http 外送: 载荷序列化失败: %v: %w", err, ErrSendFailed)
	}
	cctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, p.cfg.URL, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("http 外送: 构造请求失败: %v: %w", err, ErrSendFailed)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "baidi-control/audit-forward")
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("http 外送: 请求 %s 失败: %v: %w", p.cfg.URL, err, ErrSendFailed)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPErrBody))
		return fmt.Errorf("http 外送: 对端返回 %d %s：%s: %w",
			resp.StatusCode, http.StatusText(resp.StatusCode), oneLineOrPlaceholder(string(snippet)), ErrSendFailed)
	}
	// 把响应体读干净再丢，让连接能被复用（不然每一批都新建一次 TCP+TLS）。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return nil
}

func oneLineOrPlaceholder(s string) string {
	if v := oneLine(s); v != "" {
		return truncRunes(v, maxHTTPErrBody)
	}
	return "（对端未返回内容）"
}
