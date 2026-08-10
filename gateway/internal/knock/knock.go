// Package knock 定义 SPA 敲门包的封装/解析，提供**被动重放**防护。
//
// 敲门包从"裸 JWT"升级为 JSON 信封 {t:JWT, ts:时间戳, n:随机nonce}：
// 网关校验 ts 在允许时钟偏移内、且 nonce 在窗口内未用过——passively 嗅探到的整包再次重放会因
// nonce 重复 / ts 陈旧被拒。无需客户端持有共享密钥（nonce 只是随机数）。
//
// 主动重放（攻击者从捕获包里解出 JWT、自造新 ts+nonce 重敲）由 control 签发的
// **短时效一次性敲门令牌**根治：90s TTL + jti，网关按 jti 去重、并强制 use=knock
// （见 spa.checkKnock）——长效会话令牌自此无法用于敲门。
// 兼容：非 JSON 包按旧式裸 JWT 处理（无重放保护，strict 模式下直接拒绝）。
package knock

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrDenied 表示 control 定性拒绝签发敲门令牌（HTTP 403：强制下线 / 账号禁用锁定）。
// 与瞬时错误（网络抖动、5xx）区别对待：调用方遇 ErrDenied 应停止接入并向用户显示原因，
// 绝不回退会话令牌继续重试——回退只会让被封禁的客户端徒劳空转。
var ErrDenied = errors.New("接入被拒")

// fetchClient 取令牌用的 HTTP 客户端。必须带超时：strict 模式下这是数据面保活的热路径
// （每 reknock 一次），control 慢响应若无上界会把整轮保活拖过网关放行窗口而静默断连。
var fetchClient = &http.Client{Timeout: 5 * time.Second}

// FetchToken 用会话令牌向 baidi-control 换取短时效一次性敲门令牌（带 jti + use=knock）。
// 遇 403 返回包裹 ErrDenied 的错误并带出服务端原因；其余非 200 视为瞬时错误。
//
// device 是终端硬件指纹（与 posture 上报、登录 deviceId **同一个值**），供控制面的
// 授信终端准入闸判定（严格模式下非授信设备直接拒发）。空串 = 不上报指纹：
// 控制面在观察模式下照常签发并留痕，严格模式下拒——**不带指纹不是错误，是一种状态**，
// 因此这里不校验也不兜底猜一个值。猜一个（比如拿主机名 hash）会让管理员在设备台账里
// 看到一台与 posture 上报对不上的幽灵设备，而两处本该是同一台机器。
func FetchToken(control, sessionToken, device string) (string, error) {
	body, err := json.Marshal(map[string]string{"device": device})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(control, "/")+"/api/v1/knock-token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := fetchClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("%w：%s", ErrDenied, decodeErrMsg(resp.Body))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("control 返回 %d", resp.StatusCode)
	}
	var r struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	if r.Token == "" {
		return "", errors.New("control 返回空令牌")
	}
	return r.Token, nil
}

// decodeErrMsg 从 control 统一错误信封 {"error":{"message":...}} 取原因，取不到给兜底文案。
func decodeErrMsg(body io.Reader) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.NewDecoder(body).Decode(&e) == nil && e.Error.Message != "" {
		return e.Error.Message
	}
	return "已被管理员禁止接入"
}

type packet struct {
	T  string `json:"t"`  // JWT
	Ts int64  `json:"ts"` // unix 秒
	N  string `json:"n"`  // base64 nonce
}

// Seal 把 JWT 封装为带时间戳 + 随机 nonce 的敲门包。
func Seal(token string) ([]byte, error) {
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return nil, err
	}
	return json.Marshal(packet{T: token, Ts: time.Now().Unix(), N: base64.RawStdEncoding.EncodeToString(nb)})
}

// Cache 记录已用 nonce（带过期清理），防同一敲门包重放。并发安全。
type Cache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewCache() *Cache { return &Cache{seen: map[string]time.Time{}} }

// Seen 报告 key 是否已在窗口内出现过（出现过返回 true）；否则记下并在 ttl 后过期。
// 调用方用命名空间前缀区分用途（如 "n:"+nonce、"j:"+jti），避免跨用途碰撞。
func (c *Cache) Seen(key string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, exp := range c.seen { // 惰性清理过期项
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[key]; ok {
		return true
	}
	c.seen[key] = now.Add(ttl)
	return false
}

// Open 解析敲门包并做被动重放防护。返回待校验的 JWT 与是否启用了重放保护。
// JSON 信封：校 ts 新鲜度 + nonce 去重；非 JSON：当旧式裸 JWT（protected=false）。
func Open(data []byte, skew time.Duration, c *Cache) (token string, protected bool, err error) {
	var p packet
	if json.Unmarshal(data, &p) != nil || p.T == "" {
		return string(data), false, nil // 兼容旧式裸 JWT
	}
	now := time.Now().Unix()
	if d := now - p.Ts; d > int64(skew/time.Second) || d < -int64(skew/time.Second) {
		return "", false, errors.New("敲门包时间戳超出允许偏移（疑似重放）")
	}
	if p.N == "" || c.Seen("n:"+p.N, 2*skew) {
		return "", false, errors.New("敲门 nonce 缺失或重复（重放被拒）")
	}
	return p.T, true, nil
}
