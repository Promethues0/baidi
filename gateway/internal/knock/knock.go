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

const (
	// sweepEvery 两次全表清理之间的最小间隔。
	//
	// ★这条常量是修一个算法复杂度攻击面（wave9）。此前 Seen **每次调用都遍历整个
	// map** 做惰性清理，而 map 无上界。SPA 是免认证的公网 UDP 口，且 knock.Open 里的
	// nonce 去重排在**验签之前**——攻击者不需要任何有效令牌，只要发合法 JSON 信封
	// （正确时间戳 + 随机 nonce）就能同时撑大 map 和触发全表扫描：
	// 发 N 包/秒 → 表里约 60N 条 → 每包扫两遍（nonce 一次、jti 一次）→ 成本 O(N²)。
	// 而 spa.Serve 是**单 goroutine**，CPU 一打满整个敲门面就失效——
	// 也就是「五道门」的第一道被一个不需要凭据的洪泛关掉。
	//
	// 同一个包里 secevent 的节流器早就写着「SPA 是 UDP，源地址可伪造，
	// 一次伪造源洪泛能造出无限多的键，表大小必须钉死」——那条纪律只覆盖了一半。
	sweepEvery = 5 * time.Second

	// maxEntries 表上界。nonce 窗口是 2×skew=60s、jti 不超过 knockMaxTTL+skew，
	// 正常部署的活跃条目数远达不到它；能填满的一定是洪泛。
	// 内存上界约十几 MB，与「无上界」相比是确定性的。
	maxEntries = 1 << 16
)

// Cache 记录已用 nonce/jti（带过期清理），防同一敲门包重放。并发安全。
type Cache struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	lastSweep time.Time
	// rejected 因表满而被拒的次数（可观测：这个数非零就说明正在被洪泛）。
	rejected uint64
}

func NewCache() *Cache { return &Cache{seen: map[string]time.Time{}} }

// Seen 报告 key 是否已在窗口内出现过（出现过返回 true）；否则记下并在 ttl 后过期。
// 调用方用命名空间前缀区分用途（如 "n:"+nonce、"j:"+jti），避免跨用途碰撞。
//
// 表满时返回 true（即"当作重放拒绝"）。这是刻意的 fail-closed：宁可在洪泛期间
// 拒掉新敲门，也不能因为记不下而放过一次真重放——放过重放等于一次性令牌失效。
func (c *Cache) Seen(key string, ttl time.Duration) bool {
	seen, _ := c.SeenOrFull(key, ttl)
	return seen
}

// SeenOrFull 同 Seen，另外报出「这次拒绝是因为表满」——调用方据此区分两种事实：
// 真重放（对方在重放）与表满（我方记不下了）。两者的归因方向相反，
// 而被表满挡下的那个包很可能来自**正常用户**（洪泛者把表填满，正常敲门跟着遭殃），
// 把他的源 IP 记进攻击源统计就是记反了。参照 proxy-capacity 的同款处置。
func (c *Cache) SeenOrFull(key string, ttl time.Duration) (seen, full bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()

	// 摊销清理：不再每次调用全扫。间隔到了、或表已到顶，才扫一次。
	if now.Sub(c.lastSweep) >= sweepEvery || len(c.seen) >= maxEntries {
		c.sweep(now)
	}

	if exp, ok := c.seen[key]; ok {
		// ★必须在这里判过期。改造前靠"每次先全扫"保证表里没有过期项，
		// 现在扫是摊销的，表里会残留已过期但还没被扫掉的条目——
		// 不判的话，一个早该失效的 key 会被当成重放，把正常敲门挡在门外。
		if now.After(exp) {
			c.seen[key] = now.Add(ttl)
			return false, false
		}
		return true, false
	}

	if len(c.seen) >= maxEntries {
		c.rejected++
		return true, true // 清理后仍满 = 正在被洪泛，fail-closed
	}
	c.seen[key] = now.Add(ttl)
	return false, false
}

// sweep 删除已过期项。调用方须持锁。
func (c *Cache) sweep(now time.Time) {
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	c.lastSweep = now
}

// Stats 当前条目数与因表满被拒的累计次数（供网关侧观测洪泛）。
func (c *Cache) Stats() (entries int, rejected uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen), c.rejected
}

// ErrCacheFull 去重表已满而拒绝。**不是对方在重放**，是我方记不下了——
// 表满只可能由洪泛造成，而被它挡下的包很可能来自正常用户。
// 调用方据此把归因说对，并且**不要**把这个源 IP 计进攻击源统计。
var ErrCacheFull = errors.New("敲门去重表已满（正被洪泛，本次敲门被拒）")

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
	if p.N == "" {
		return "", false, errors.New("敲门 nonce 缺失（重放被拒）")
	}
	if seen, full := c.SeenOrFull("n:"+p.N, 2*skew); seen {
		if full {
			return "", false, ErrCacheFull
		}
		return "", false, errors.New("敲门 nonce 重复（重放被拒）")
	}
	return p.T, true, nil
}
