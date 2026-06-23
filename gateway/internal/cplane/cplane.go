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

// Register 向控制面注册/心跳（上报 proxy/spa 地址）。
func (c *Client) Register() error {
	body, _ := json.Marshal(map[string]string{"id": c.gwID, "proxy": c.proxy, "spa": c.spa})
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

// Policy 拉取当前资源授权策略。
func (c *Client) Policy() ([]resource.Resource, error) {
	resp, err := c.do(http.MethodGet, "/api/v1/gateways/policy", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control 拉策略返回 %d", resp.StatusCode)
	}
	var r struct {
		Resources []resourceDTO `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	out := make([]resource.Resource, 0, len(r.Resources))
	for _, d := range r.Resources {
		out = append(out, resource.Resource{ID: d.ID, Backend: d.Backend, AllowRoles: d.AllowRoles, AllowUsers: d.AllowUsers})
	}
	return out, nil
}
