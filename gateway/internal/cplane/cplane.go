// Package cplane 是网关侧的控制面客户端：向 baidi-control 注册自身，并拉取资源授权策略。
//
// 机器身份优先走 mTLS 客户端证书（CA 身份迁移 阶段 2）：证书由控制面内部 CA 签发，
// 身份在传输层完成。此前是用共享密钥自签 role=gateway 令牌——而那把密钥同时能签
// role=admin，等于把控制面的签发能力放在被保护方手里。
// 未配置证书时回退自签令牌（迁移期兼容，收口后应彻底移除）。
package cplane

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"baidi.dev/gateway/internal/auth"
	"baidi.dev/gateway/internal/resource"
)

// Client 访问 baidi-control 的网关接口。
type Client struct {
	control    string
	gwID       string
	proxy, spa string
	secret     []byte
	mtls       bool // 已装载客户端证书：身份走 TLS，不再自签令牌
	httpc      *http.Client
}

// New 构造控制面客户端（共享密钥自签令牌，迁移期兼容形态）。
func New(control, gwID, proxy, spa string, secret []byte) *Client {
	return &Client{
		control: strings.TrimRight(control, "/"),
		gwID:    gwID,
		proxy:   proxy,
		spa:     spa,
		secret:  secret,
		httpc:   &http.Client{Timeout: 8 * time.Second},
	}
}

// NewMTLS 构造走 mTLS 客户端证书的控制面客户端。
// certFile/keyFile 是控制面签发给本网关的证书与私钥，caFile 是内部 CA 公证书。
func NewMTLS(control, gwID, proxy, spa, certFile, keyFile, caFile string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("载入网关客户端证书失败: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("载入 CA 证书失败: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("CA 证书解析失败: " + caFile)
	}
	return &Client{
		control: strings.TrimRight(control, "/"),
		gwID:    gwID, proxy: proxy, spa: spa, mtls: true,
		httpc: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
			}},
		},
	}, nil
}

// UsesMTLS 报告是否以客户端证书作为机器身份（供启动日志暴露真实姿态）。
func (c *Client) UsesMTLS() bool { return c.mtls }

// token 自签短时效 gateway 身份令牌（共享密钥；控制面据角色放行网关接口）。
func (c *Client) token() string {
	return auth.Sign(c.secret, auth.Claims{Sub: "gateway:" + c.gwID, Role: "gateway", Name: c.gwID}, 5*time.Minute)
}

func (c *Client) do(method, path string, body []byte) (*http.Response, error) {
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, c.control+path, rd)
	if err != nil {
		return nil, err
	}
	// mTLS 下身份由客户端证书承载，不再附带自签令牌——网关不应具备签发能力。
	if !c.mtls {
		req.Header.Set("Authorization", "Bearer "+c.token())
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpc.Do(req)
}

// Session 上报给控制面的一条活跃会话（真实在线用户来源）。
type Session struct {
	IP    string `json:"ip"`
	User  string `json:"user"`
	Role  string `json:"role"`
	Since int64  `json:"since"` // 首次敲门放行的 Unix 时刻
}

// Register 向控制面注册/心跳，同时上报真实活性指标与活跃会话：clients=放行窗口内已授权源数，
// tunnels=活跃隧道连接数，uptimeSec=网关运行秒数，sessions=当前活跃会话（供监控中心在线用户）。
func (c *Client) Register(clients, tunnels int, uptimeSec int64, sessions []Session) error {
	body, _ := json.Marshal(map[string]any{
		"id": c.gwID, "proxy": c.proxy, "spa": c.spa,
		"clients": clients, "tunnels": tunnels, "uptime": uptimeSec, "sessions": sessions,
	})
	resp, err := c.do(http.MethodPost, "/api/v1/gateways/register", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("control 注册返回 %d", resp.StatusCode)
	}
	return nil
}

// resourceDTO 对应控制面返回的资源 JSON（camelCase）。
type resourceDTO struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Backend    string   `json:"backend"`
	AllowRoles []string `json:"allowRoles"`
	AllowUsers []string `json:"allowUsers"`
}

// Revoked 控制面下发的一条强制下线封禁（封禁期内拒绝敲门，并撤窗/切断该账号隧道）。
// 数据面执行只需 user + until；处置原因（reason）为运营敏感文本，按最小披露原则不下发网关。
type Revoked struct {
	User  string `json:"user"`
	Until int64  `json:"until"` // 封禁截止 Unix 秒
}

// Policy 拉取当前资源授权策略 + 强制下线撤销名单（旧控制面无 revoked 字段则为空，向后兼容）。
func (c *Client) Policy() ([]resource.Resource, []Revoked, error) {
	resp, err := c.do(http.MethodGet, "/api/v1/gateways/policy", nil)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("control 拉策略返回 %d", resp.StatusCode)
	}
	var r struct {
		Resources []resourceDTO `json:"resources"`
		Revoked   []Revoked     `json:"revoked"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, nil, err
	}
	out := make([]resource.Resource, 0, len(r.Resources))
	for _, d := range r.Resources {
		out = append(out, resource.Resource{ID: d.ID, Backend: d.Backend, AllowRoles: d.AllowRoles, AllowUsers: d.AllowUsers})
	}
	return out, r.Revoked, nil
}
