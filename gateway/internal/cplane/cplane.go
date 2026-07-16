// Package cplane 是网关侧的控制面客户端：向 baidi-control 注册自身，并拉取资源授权策略。
// 网关用共享密钥自签 gateway 身份令牌认证（无需额外凭据下发）。
package cplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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
	httpc      *http.Client
}

// New 构造控制面客户端。
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
	req.Header.Set("Authorization", "Bearer "+c.token())
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
type Revoked struct {
	User   string `json:"user"`
	Until  int64  `json:"until"` // 封禁截止 Unix 秒
	Reason string `json:"reason"`
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
