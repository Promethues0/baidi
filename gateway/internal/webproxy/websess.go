package webproxy

// 七层 Web 会话台账（wave11 行动 14 ②③）。
//
// ── 为什么非有不可 ──
//
// 改造前网关对 L7 会话是**完全无状态**的：会话全在那张 HMAC Cookie 里，网关既数不出
// 「此刻有几个人在经浏览器访问」，也没有任何手段单独终止其中一条。两个后果：
//
//	① 控制台「在线用户」页只显示 SPA 放行表里的 C/S 会话（main 的 report() 取的是
//	   al.Sessions()）。一个整天用浏览器访问 OA 的人，在那一页上**从来不存在**——
//	   而那一页是「要不要处置这个人」的第一输入。
//	② 强制下线对 B/S 只有半边：KillUser 切得掉 WebSocket，切不掉普通请求会话。
//	   普通请求靠 spa.Allowlist 的封禁名单挡，而那个封禁窗只有 kickBanTTL（5 分钟），
//	   Cookie 却活 15 分钟——封禁期一过，被"强制下线"的人拿着同一张 Cookie 接着访问，
//	   管理台上写着「已下线」。
//
// ── 台账 = 判据，不是缓存 ──
//
// 登记在案的会话 id（sid）签在 Cookie 里，逐请求必须能在台账里查到。查不到即拒绝，
// 因为**唯二**的摘除来源就是「强制下线」与「超时注销」，两者都该拒。
// 网关重启时 SessionKey 重新生成、所有 Cookie 当场失效，所以"台账空了而 Cookie 还在"
// 这种形态不存在，这条硬判据不会误伤任何人。

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// SessionInfo 一条 L7 会话的台账快照（随心跳上报控制面，进「在线用户」页）。
type SessionInfo struct {
	ID   string `json:"id"`
	User string `json:"user"`
	Role string `json:"role"`
	Res  string `json:"res"`
	IP   string `json:"ip"`
	// Since 会话建立时刻（Unix 秒）。
	Since int64 `json:"since"`
	// LastActive 最近一次**通过逐请求鉴权**的业务请求时刻。
	//
	// ★与 spa.Allowlist.Touch 同一条纪律：在两道复核之后才刷新，否则往 L7 口打个
	// 无效请求就能替别人续命。这里天然满足——touch 排在 Authorize 之后。
	LastActive int64 `json:"lastActive"`
	// Exp 会话 Cookie 的到期时刻（Unix 秒）。会话绝不比签发它的 Cookie 活得久。
	Exp int64 `json:"exp"`
}

// liveSession 台账里的一行。
type liveSession struct {
	user, role, res, ip    string
	since, lastActive, exp int64
}

// sessionTracker 按 sid 索引的 L7 会话台账（并发安全）。
type sessionTracker struct {
	mu sync.Mutex
	m  map[string]*liveSession
}

func newSessionTracker() *sessionTracker {
	return &sessionTracker{m: map[string]*liveSession{}}
}

// newSessionID 生成一条会话的台账 id。
//
// ★由**网关**生成而不是取自票据的 jti：jti 是控制面签的、会出现在浏览器地址栏与
// 前置 nginx 的 access.log 里；拿它当台账键等于让一个已经泄露过的值决定"终止哪条会话"。
func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// start 登记一条新会话。
func (t *sessionTracker) start(sid, user, role, res, ip string, now, exp int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[sid] = &liveSession{user: user, role: role, res: res, ip: ip,
		since: now, lastActive: now, exp: exp}
	t.pruneLocked(now)
}

// get 取一条会话的**当前**快照（不更新 lastActive）。
//
// ★返回的是副本：超时判定要看的是"上一次业务请求在什么时候"，
// 而 touch 会把它改成现在——两步必须分开，合成一步的话超时规则对谁都不触发
// （与 api.accessSessionGate 里 self 必须是续期前快照是同一个坑）。
func (t *sessionTracker) get(sid string) (liveSession, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.m[sid]
	if !ok {
		return liveSession{}, false
	}
	return *s, true
}

// touch 刷新一条会话的业务活跃时刻（会话已不在台账时什么都不做）。
func (t *sessionTracker) touch(sid string, now int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.m[sid]; ok {
		s.lastActive = now
	}
}

// end 摘除一条会话（超时注销用；幂等）。
func (t *sessionTracker) end(sid string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.m[sid]; !ok {
		return false
	}
	delete(t.m, sid)
	return true
}

// endUser 摘除某账号的全部会话，返回条数（强制下线用）。
func (t *sessionTracker) endUser(user string) int {
	key := normUser(user)
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for sid, s := range t.m {
		if normUser(s.user) == key {
			delete(t.m, sid)
			n++
		}
	}
	return n
}

// snapshot 当前存活会话（顺带惰性清掉已过期的行）。
func (t *sessionTracker) snapshot(now int64) []SessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	out := make([]SessionInfo, 0, len(t.m))
	for sid, s := range t.m {
		out = append(out, SessionInfo{ID: sid, User: s.user, Role: s.role, Res: s.res,
			IP: s.ip, Since: s.since, LastActive: s.lastActive, Exp: s.exp})
	}
	return out
}

// count 当前台账条数（供日志/自检）。
func (t *sessionTracker) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// pruneLocked 清掉 Cookie 已到期的行。
//
// ★判据与 Open() 的过期判定**同一条**（Exp <= now）：两处分叉的话，
// 台账里会留下一批 Open 已经认定过期、而心跳仍在上报的"幽灵在线会话"。
func (t *sessionTracker) pruneLocked(now int64) {
	for sid, s := range t.m {
		if s.exp <= now {
			delete(t.m, sid)
		}
	}
}

// Sessions 当前 L7 会话快照（供网关心跳上报）。
func (s *Server) Sessions() []SessionInfo { return s.sessions.snapshot(time.Now().Unix()) }

// SessionCount 当前 L7 会话条数。
func (s *Server) SessionCount() int { return s.sessions.count() }

// SetIdleTimeout 设置「接入超时注销」阈值（FR-POLICY-30 在 B/S 这一侧的执行方）。
//
// 阈值由控制面随策略轮询下发（gateways/policy 的 webIdleSec），网关**不做任何推导**——
// 它不知道管理员配的是几分钟，也不该知道为什么。d<=0 = 规则不生效。
//
// ★缺省（控制面没下发这个字段，即旧控制面）就是 0 = 不生效，这里刻意**不做三态**：
// 「控制面还不认识这条规则」与「管理员把规则关了」的处置完全相同，都是不注销任何人，
// 做成三态只会多一个永远走同一分支的判定。真正需要区分的是**披露**——那由网关把
// 自己此刻在执行的值随心跳报回去（IdleTimeout），控制面据此在页面上分开显示
// 「已按 N 分钟执行」与「该网关未回报（旧版本，其上的浏览器接入不会被注销）」。
func (s *Server) SetIdleTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	s.idleTimeout.Store(int64(d))
}

// IdleTimeout 本网关此刻真正在执行的超时注销阈值（0 = 不生效）。回执用。
func (s *Server) IdleTimeout() time.Duration {
	return time.Duration(s.idleTimeout.Load())
}
