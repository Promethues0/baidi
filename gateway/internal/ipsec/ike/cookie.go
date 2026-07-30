package ike

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net/netip"
	"time"
)

// IKE_SA_INIT 是网关上**唯一一个在任何认证之前就解析对端报文**的入口
// （白帝其余端口靠 SPA 敲门 + 内核态丢包实现隐身，IKE 做不到）。
// 本文件是这条攻击面上的三道闸，全部**不需要建立任何状态**就能生效：
//
//	① 每源 IP 限速     —— 挡住"一台机器每秒几万个 SA_INIT"；
//	② half-open 配额   —— 挡住"每个包都合法，但从不发 IKE_AUTH"的资源耗尽；
//	③ COOKIE 往返校验 —— 挡住伪造源 IP 的放大攻击（对端必须真能收到我们的回包）。
//
// ★三道闸失败时一律**静默丢包**，不回任何东西。回一个错误通知就等于：
// 攻击者用一个 60 字节的伪造包换我们发出一个 60 字节的包到受害者——完美的反射放大器。

const (
	// halfOpenLimitTotal 全局 half-open 上限。超限后新的 IKE_SA_INIT 一律先要 COOKIE。
	halfOpenLimitTotal = 64
	// halfOpenLimitPerIP 单源 IP 的 half-open 上限。
	// ★没有这一条，一个源就能把全局 64 个配额占满，让所有正常站点都被迫走 COOKIE 往返。
	halfOpenLimitPerIP = 8
	// halfOpenTTL half-open SA 的存活时长；到点静默清理（对端本来就没完成认证，无处可通知）。
	halfOpenTTL = 30 * time.Second

	// cookieSecretTTL cookie 密钥轮换周期。
	cookieSecretTTL = 60 * time.Second
	// cookieLen 版本字节 + 16 字节摘要。
	cookieLen = 1 + 16

	// initRatePerSec 每源 IP 每秒允许的 IKE_SA_INIT 请求数。
	initRatePerSec = 10
)

// cookieJar 生成与校验 COOKIE（RFC 7296 §2.6 推荐构造）：
//
//	Cookie = VersionOfSecret(1) ‖ SHA256( Ni ‖ IPi ‖ SPIi ‖ secret )[:16]
//
// ★保留上一代 secret 是必需的，不是优化：轮换那一瞬间，正在往返途中的
// cookie 会全部失效，表现为"每隔 60 秒有一批连接建不起来"——偶发、无规律、
// 两端日志都只说协商失败。保留一代就把这个窗口消掉了。
type cookieJar struct {
	now func() time.Time
	rnd io.Reader

	version  uint8
	secret   []byte
	prev     []byte
	rotateAt time.Time
}

func newCookieJar(now func() time.Time, rnd io.Reader) *cookieJar {
	j := &cookieJar{now: now, rnd: rnd, version: 1}
	j.secret = readRand(rnd, 32)
	j.rotateAt = now().Add(cookieSecretTTL)
	return j
}

// rotate 到点换一代 secret，旧的降级为 prev。
func (j *cookieJar) rotate() {
	n := j.now()
	if n.Before(j.rotateAt) {
		return
	}
	j.prev = j.secret
	j.secret = readRand(j.rnd, 32)
	j.version++
	if j.version == 0 { // 0 留给"无 prev"的哨兵语义，跳过
		j.version = 1
	}
	j.rotateAt = n.Add(cookieSecretTTL)
}

// compute 用给定 secret 与版本算一个 cookie。
func cookieCompute(version uint8, secret, ni []byte, ip netip.Addr, spii [8]byte) []byte {
	h := sha256.New()
	h.Write(ni)
	if ip.IsValid() {
		b := ip.AsSlice()
		h.Write(b)
	}
	h.Write(spii[:])
	h.Write(secret)
	sum := h.Sum(nil)
	out := make([]byte, 0, cookieLen)
	out = append(out, version)
	return append(out, sum[:16]...)
}

// issue 签发一个 cookie。
func (j *cookieJar) issue(ni []byte, ip netip.Addr, spii [8]byte) []byte {
	j.rotate()
	return cookieCompute(j.version, j.secret, ni, ip, spii)
}

// verify 校验对端带回来的 cookie。
//
// ★用 hmac.Equal 做常量时间比较：cookie 本身不是密钥，但逐字节短路比较会泄漏
// "前几个字节对了"，让攻击者能按字节爆破出一个有效 cookie，从而绕过整道闸。
// 常量时间比较的成本是零。
func (j *cookieJar) verify(cookie, ni []byte, ip netip.Addr, spii [8]byte) bool {
	j.rotate()
	if len(cookie) != cookieLen {
		return false
	}
	if hmac.Equal(cookie, cookieCompute(j.version, j.secret, ni, ip, spii)) {
		return true
	}
	if j.prev != nil && hmac.Equal(cookie, cookieCompute(j.version-1, j.prev, ni, ip, spii)) {
		return true
	}
	return false
}

// halfOpenTracker 统计 half-open 数量（全局 + 每源 IP）。
//
// ★"占配额"的是响应方在收到合法 IKE_SA_INIT 后建立的那点状态（SPI/nonce/DH 私钥/
// 派生出的密钥）。它不占任何数据面资源，但每条要算几毫秒的 DH——这正是被打的地方。
type halfOpenTracker struct {
	total int
	byIP  map[netip.Addr]int
}

func newHalfOpenTracker() *halfOpenTracker {
	return &halfOpenTracker{byIP: make(map[netip.Addr]int)}
}

// overLimit 报告"再收一条就超配额了"，此时应先要 COOKIE 而不是直接建状态。
func (t *halfOpenTracker) overLimit(ip netip.Addr) bool {
	return t.total >= halfOpenLimitTotal || t.byIP[ip] >= halfOpenLimitPerIP
}

func (t *halfOpenTracker) add(ip netip.Addr) {
	t.total++
	t.byIP[ip]++
}

func (t *halfOpenTracker) remove(ip netip.Addr) {
	if t.total > 0 {
		t.total--
	}
	if n := t.byIP[ip]; n > 1 {
		t.byIP[ip] = n - 1
	} else {
		delete(t.byIP, ip)
	}
}

// rateLimiter 每源 IP 的令牌桶（每秒 initRatePerSec 个）。
//
// 用"上次补充时刻 + 令牌数"而不是滑动窗口计数：滑动窗口要留一串时间戳，
// 而这里恰恰是被攻击时才生效的路径，内存开销必须与源 IP 数成正比、与包数无关。
type rateLimiter struct {
	now     func() time.Time
	buckets map[netip.Addr]*tokenBucket
	lastGC  time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(now func() time.Time) *rateLimiter {
	return &rateLimiter{now: now, buckets: make(map[netip.Addr]*tokenBucket), lastGC: now()}
}

// allow 消耗一个令牌；没有则拒绝（调用方静默丢包）。
func (r *rateLimiter) allow(ip netip.Addr) bool {
	n := r.now()
	b := r.buckets[ip]
	if b == nil {
		b = &tokenBucket{tokens: initRatePerSec, last: n}
		r.buckets[ip] = b
	}
	if d := n.Sub(b.last); d > 0 {
		b.tokens += d.Seconds() * initRatePerSec
		if b.tokens > initRatePerSec {
			b.tokens = initRatePerSec
		}
		b.last = n
	}
	// 定期清掉长期不活跃的桶。★没有这一步，桶表本身就成了新的内存耗尽面：
	// 攻击者只要每个包换一个伪造源 IP，就能让我们为它们各留一条记录。
	if n.Sub(r.lastGC) > time.Minute {
		for k, v := range r.buckets {
			if n.Sub(v.last) > time.Minute {
				delete(r.buckets, k)
			}
		}
		r.lastGC = n
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// readRand 读 n 字节随机数；失败即 panic。
//
// 取舍与 crypto.go 的 RandBytes 一致：熵源不可用时继续跑会产出可预测的
// cookie secret / SPI / nonce，静默降级比崩溃危险得多。
func readRand(rnd io.Reader, n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rnd, b); err != nil {
		panic("ike: 系统熵源不可用: " + err.Error())
	}
	return b
}
