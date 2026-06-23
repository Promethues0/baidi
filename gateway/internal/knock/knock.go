// Package knock 定义 SPA 敲门包的封装/解析，提供**被动重放**防护。
//
// 敲门包从"裸 JWT"升级为 JSON 信封 {t:JWT, ts:时间戳, n:随机nonce}：
// 网关校验 ts 在允许时钟偏移内、且 nonce 在窗口内未用过——passively 嗅探到的整包再次重放会因
// nonce 重复 / ts 陈旧被拒。无需客户端持有共享密钥（nonce 只是随机数）。
//
// 残留风险（需另案）：主动攻击者若从捕获包里**解出 JWT**，可自造新 ts+nonce 重新敲门——
// 这要靠 control 签发**短时效一次性敲门令牌**（分钟级 + jti，网关按 jti 去重）来根治，属后续工作。
// 兼容：非 JSON 包按旧式裸 JWT 处理（无重放保护，网关会告警）。
package knock

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

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

func (c *Cache) seenOrAdd(nonce string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, exp := range c.seen { // 惰性清理过期项
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return true
	}
	c.seen[nonce] = now.Add(ttl)
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
	if p.N == "" || c.seenOrAdd(p.N, 2*skew) {
		return "", false, errors.New("敲门 nonce 缺失或重复（重放被拒）")
	}
	return p.T, true, nil
}
