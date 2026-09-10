// Package spa 实现"单包授权"（Single Packet Authorization）：
// 网关默认对外不可达；收到携带有效 JWT 的 UDP 敲门包后，为该源 IP 开一个 TTL 放行窗口。
package spa

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"baidi.dev/gateway/internal/auth"
	"baidi.dev/gateway/internal/knock"
	"baidi.dev/gateway/internal/secevent"
)

// normUser 规范化账号（去首尾空格 + 小写），用作封禁/切断的匹配键——
// 企业身份（AD sAMAccountName、邮箱）通常大小写不敏感，规范化后杜绝
// "换大小写/加空格重登即绕过强制下线"。放行表仍存原始显示名，仅键规范化。
func normUser(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Allowlist 放行表：键是 **(源 IP, 账号)**，不是源 IP。
//
// ★为什么键必须带账号（wave11 行动 3）：原来 `map[源IP]entry` 且 entry 直接携带
// user/role，`Allow()` 是整条覆盖——同一出口（企业 NAT / CGNAT / 咖啡厅 / 云主机
// 同公网 IP）下两个账号交替敲门，会互相刷写对方的身份，于是
//
//	① proxy 按源 IP 取到的"身份"是**最后一个敲门的人**，与这条 TCP 连接毫无关系；
//	② RevokeUser(A) 按 e.user 匹配，末次敲门者是 B 时整条不匹配 → 强制下线漏撤窗；
//	③ Reap / -pf 回收 / Sessions() / ActiveCount() 全部把同出口两个人混成一条。
//
// 现在身份由隧道前导上的票据自证（见 proxy.handle），放行表退回它本来的职责：
// **端口闸**——"这个 (源IP, 账号) 此刻有没有敲开过窗"。两个维度都在，撤谁就只撤谁。
//
// 结构选嵌套 map（源IP → 规范化账号 → 条目）而不是复合键 map：proxy 每条连接都要问
// 一次「这个 IP 上有没有任何窗口」（隐身闸），扁平键得整表扫，而同一 IP 上的账号数很小。
type Allowlist struct {
	mu   sync.RWMutex
	m    map[string]map[string]entry
	deny map[string]time.Time // 账号 → 封禁截止（强制下线：封禁期内拒绝敲门）
	// OnAllow 在放行某 IP 时回调（如向防火墙 pf 表写入 pass 规则）。可空。
	//
	// ★内核放行是 **IP 粒度**的（pf/nft 的表里只有地址），账号维度到不了内核。
	// 于是同一 IP 上第二个账号敲门会重复写一次同样的 pass 规则（幂等，无害），
	// 而回收必须等该 IP 上**最后一条**窗口消失——回收前的 `Allowed(ip)` 复核就是那道闸。
	OnAllow func(ip, user string)
}

type entry struct {
	until time.Time
	since time.Time // 首次敲门放行时刻（供上报会话在线时长；重复敲门保活不重置）
	// lastActive 最近一次**业务连接**到达的时刻（由 proxy 在鉴权通过后 Touch）。
	//
	// ★零值有确定语义：**这条放行窗口从未承载过业务连接**，不是"刚刚活跃过"。
	// 它是 FR-POLICY-30「无业务流量超时注销」在控制面侧的唯一判据来源，
	// 而敲门保活（Allow 续窗）**刻意不刷新它**——客户端只要不退出就每 15s 敲一次门，
	// 拿保活当活跃的话那条规则永远不会触发，等于又造一条永不生效的假开关。
	lastActive time.Time
	user       string // 原始显示形态的账号（键是它的 normUser 规范化形式）
	role       string
}

// Session 一条活跃放行会话（供网关向控制面上报真实在线用户）。
type Session struct {
	IP    string
	User  string
	Role  string
	Since time.Time
	// LastActive 最近一次业务连接时刻；**零值 = 从未有过业务连接**（不可判定，不是"很久以前"）。
	LastActive time.Time
}

func NewAllowlist() *Allowlist {
	return &Allowlist{m: map[string]map[string]entry{}, deny: map[string]time.Time{}}
}

// DenyUser 封禁某账号至 until（强制下线：封禁期内拒绝后续敲门）。返回是否为新封禁/延长封禁。
// 注意：数据面处置（撤窗/断隧道）的幂等由调用方按 until 自管，不依赖本返回值——
// 避免网关本地时钟快于控制面时 until 被判过期、导致处置被整段跳过。
func (a *Allowlist) DenyUser(user string, until time.Time) bool {
	if !time.Now().Before(until) {
		return false
	}
	key := normUser(user)
	a.mu.Lock()
	defer a.mu.Unlock()
	if prev, ok := a.deny[key]; ok && !until.After(prev) {
		return false
	}
	a.deny[key] = until
	return true
}

// UserDenied 报告某账号是否在封禁期内（懒清理过期条目）。
func (a *Allowlist) UserDenied(user string) bool {
	key := normUser(user)
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.deny[key]
	if !ok {
		return false
	}
	if !time.Now().Before(until) {
		delete(a.deny, key)
		return false
	}
	return true
}

// RevokeUser 撤销某账号的全部放行窗口，返回受影响的源 IP（供 -pf 模式回收内核放行规则）。
//
// ★只删这个账号的条目。同出口另一个账号的窗口原样保留——这正是键带账号维度的意义：
// 从前 `RevokeUser(A)` 在末次敲门者是 B 时整条匹配不上（漏撤），而一旦匹配上又会把
// B 的窗口一起删掉（误伤）。两种错法此前都存在，方向相反、都不报错。
//
// 返回的是「该账号曾在这些 IP 上有窗口」，**不等于这些 IP 现在可以从内核放行集里摘掉**：
// 调用方（main.go 的 -pf 回收）必须再问一次 Allowed(ip)，因为同一 IP 上可能还有别人在用。
func (a *Allowlist) RevokeUser(user string) []string {
	key := normUser(user)
	a.mu.Lock()
	defer a.mu.Unlock()
	var ips []string
	for ip, byUser := range a.m {
		if _, ok := byUser[key]; !ok {
			continue
		}
		delete(byUser, key)
		if len(byUser) == 0 {
			delete(a.m, ip)
		}
		ips = append(ips, ip)
	}
	return ips
}

// Allow 放行 (源 IP, 账号) 一段时间（记录 role）。重复敲门刷新 until 但保留首次 since。
// 封禁期内的账号一律拒绝放行（返回 false）——封禁检查与写入放行表在同一把锁内完成，
// 杜绝"UserDenied 检查通过 → 并发封禁 → 仍写入放行窗口"的重开窗竞态。
func (a *Allowlist) Allow(ip, user, role string, ttl time.Duration) bool {
	key := normUser(user)
	a.mu.Lock()
	if until, ok := a.deny[key]; ok {
		if time.Now().Before(until) {
			a.mu.Unlock()
			return false
		}
		delete(a.deny, key) // 懒清理过期封禁
	}
	since := time.Now()
	var lastActive time.Time
	byUser := a.m[ip]
	if byUser == nil {
		byUser = map[string]entry{}
		a.m[ip] = byUser
	}
	// ★续窗只认**同一个账号**的上一条：从前按 IP 取，于是 B 首次敲门会继承 A 的 since，
	// 控制面看到的"在线时长"就是别人的。
	if prev, ok := byUser[key]; ok && time.Now().Before(prev.until) {
		since = prev.since           // 保活续窗：保留首次敲门时刻
		lastActive = prev.lastActive // ★同样保留：保活不是业务流量，见 entry.lastActive
	}
	byUser[key] = entry{until: time.Now().Add(ttl), since: since, lastActive: lastActive, user: user, role: role}
	cb := a.OnAllow
	a.mu.Unlock()
	if cb != nil {
		cb(ip, user)
	}
	return true
}

// Touch 记一次**业务连接**到达（proxy 鉴权通过后调用）。
//
// 窗口不存在或已过期时什么都不做——那种情况下这个连接本来也进不来，
// 凭空建一条 lastActive 会让「从未有过业务流量」与「刚活跃过」混成一谈。
//
// ★按 (IP, 账号) 打点。只按 IP 的话，同出口 A 在用而 B 空闲时，B 的会话会被 A 的流量
// 一路续命，「无业务流量超时注销」对 B 永不触发。
func (a *Allowlist) Touch(ip, user string) {
	key := normUser(user)
	a.mu.Lock()
	defer a.mu.Unlock()
	byUser := a.m[ip]
	if byUser == nil {
		return
	}
	e, ok := byUser[key]
	if !ok || time.Now().After(e.until) {
		return
	}
	e.lastActive = time.Now()
	byUser[key] = e
}

// Reap 删除已过期的条目，返回受影响的源 IP（供防火墙模式回收 pf 放行规则）。
// 同 RevokeUser：返回值只是"这些 IP 上刚清掉过东西"，能不能摘内核规则由调用方复核。
func (a *Allowlist) Reap() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	var expired []string
	for ip, byUser := range a.m {
		hit := false
		for key, e := range byUser {
			if now.After(e.until) {
				delete(byUser, key)
				hit = true
			}
		}
		if len(byUser) == 0 {
			delete(a.m, ip)
		}
		if hit {
			expired = append(expired, ip)
		}
	}
	return expired
}

// Allowed 报告该源 IP 上**是否还有任何**有效放行窗口——这是隐身端口闸，不是身份来源。
//
// ★签名从 (user, role, ok) 收窄成 ok 是 wave11 行动 3 的核心：拿它的返回值当身份，
// 就是把"共享源 IP"当成了"持有白帝账号"。隧道连接的身份现在只有一个来源——
// 前导上那张 use=tunnel 票据（proxy.handle）。
func (a *Allowlist) Allowed(ip string) bool {
	// ★读锁：本方法判过期但**不删**（回收统一由 Reap 做），是纯读。
	// proxy.handle 每条隧道连接要摸这把锁三次（Allowed + AllowedFor 两次 + Touch 一次）。
	//
	// 实测（BenchmarkAllowedParallel_*，8 核）：独占锁 204ns → 读锁 175ns，
	// **只快了 14%**，且都远高于单线程的 53ns。别把这条读成"锁竞争解决了"——
	// RWMutex 的读锁自身也要原子操作，多核仍在抢同一条 cache line。
	// 保留它的主要理由是语义：读操作就该用读锁，将来谁在这里加了写操作，
	// race 检测会当场指出来。真要消掉这层竞争得换数据结构（分片或无锁快照），
	// 那是另一件事，眼下的量级不值得。
	a.mu.RLock()
	defer a.mu.RUnlock()
	now := time.Now()
	for _, e := range a.m[ip] {
		if now.Before(e.until) {
			return true
		}
	}
	return false
}

// AllowedFor 报告 (源 IP, 账号) 是否在有效放行窗口内。
//
// ★这是隧道票据落地时的第二道复核：票据证明"控制面刚刚放行过这个账号"，
// 这道闸证明"这个账号真的从**这个源地址**敲开过窗"。少了它，强制下线只撤窗不断票，
// 被撤销的账号仍能凭手里那张没过期的票，借同出口任何人的窗口继续新建连接。
func (a *Allowlist) AllowedFor(ip, user string) bool {
	key := normUser(user)
	a.mu.RLock()
	defer a.mu.RUnlock()
	e, ok := a.m[ip][key]
	return ok && time.Now().Before(e.until)
}

// LiveOn 返回该源 IP 上当前有效的全部会话。
//
// ★唯一调用方是 proxy 的**逃生舱**回落路径（BAIDI_GW_TUNNEL_ID_STRICT=0，老客户端
// 不带票据时按源 IP 猜身份）。它刻意返回**全部**而不是"最近那条"：只有恰好一条时
// 身份才是确定的，两条及以上就是不可判定，回落路径必须据此拒绝而不是随手挑一个。
func (a *Allowlist) LiveOn(ip string) []Session {
	a.mu.RLock()
	defer a.mu.RUnlock()
	now := time.Now()
	var out []Session
	for _, e := range a.m[ip] {
		if now.Before(e.until) {
			out = append(out, Session{IP: ip, User: e.user, Role: e.role, Since: e.since, LastActive: e.lastActive})
		}
	}
	return out
}

// Sessions 返回当前仍在放行窗口内的活跃会话（供网关向控制面上报真实在线用户）。
func (a *Allowlist) Sessions() []Session {
	a.mu.RLock()
	defer a.mu.RUnlock()
	now := time.Now()
	out := make([]Session, 0, len(a.m))
	for ip, byUser := range a.m {
		for _, e := range byUser {
			if now.Before(e.until) {
				out = append(out, Session{IP: ip, User: e.user, Role: e.role, Since: e.since, LastActive: e.lastActive})
			}
		}
	}
	return out
}

// ActiveCount 返回当前有效的放行窗口数，即**已授权客户端数**（供网关向控制面上报）。
//
// ★此前它数的是**源 IP 数**，却被上报成"已授权客户端数"：同一出口下 20 个人在线，
// 控制台上显示 1。键带上账号维度之后这个数才名副其实。
func (a *Allowlist) ActiveCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	now := time.Now()
	n := 0
	for _, byUser := range a.m {
		for _, e := range byUser {
			if now.Before(e.until) {
				n++
			}
		}
	}
	return n
}

// checkKnock 校验一个已验签的令牌是否真是「control 签发的短时效一次性敲门令牌」。
//
// 这是根治旁路的判据：在此之前，任何持 8h 会话令牌的人都能直接敲门，完全绕过控制面的
// 强制下线封禁 / 账号禁用锁定 / 终端合规(posture) 三道闸——因为那三道闸只在 control 的
// /knock-token 签发处执行，而数据面从不要求令牌来自那里。
//
// 判据用 Use 字段而非 jti 有无：passkey 登录签发的 8h 会话令牌同样带 jti，
// 按 jti 区分等于给 passkey 用户留后门。maxTTL 作为纵深防御（令牌寿命上界），
// 由调用方以 flag 传入而非硬编码，避免与 control 的 knockTTL 常量隐式耦合。
func checkKnock(c auth.Claims, protected bool, maxTTL time.Duration) error {
	if c.Use != auth.UseKnock {
		return fmt.Errorf("非敲门令牌（use=%q，需 %q）", c.Use, auth.UseKnock)
	}
	if c.Jti == "" {
		return errors.New("敲门令牌缺 jti（无法做一次性去重）")
	}
	if c.Iat == 0 || time.Duration(c.Exp-c.Iat)*time.Second > maxTTL {
		return fmt.Errorf("敲门令牌寿命超上界（%ds > %s）", c.Exp-c.Iat, maxTTL)
	}
	// 角色白名单与 control 的 requireUser 一致：网关身份、MFA 半程票据都不得开数据面窗口。
	if c.Role != "admin" && c.Role != "user" {
		return fmt.Errorf("角色 %q 不得敲门", c.Role)
	}
	if !protected {
		return errors.New("旧式裸令牌无被动重放防护")
	}
	return nil
}

// skew 允许的时钟偏移 / 被动重放窗口。
//
// ★它同时是「敲门包时间戳能差多少」的判据（knock.Open）与 nonce 去重窗的一半，
// 是个**协议常量**而不是配置项：客户端不知道网关配了多少，配置化只会让
// 「为什么我这台敲不开」多一个查不到的变量。
const skew = 30 * time.Second

// Serve 启动 SPA UDP 监听；每个有效敲门包放行其源 IP。
// strict=true 时只接受 control /knock-token 签发的短时效一次性敲门令牌（见 checkKnock）；
// false 为过渡兼容姿态，仅告警不拒绝——生产务必开启。
// rep 为安全事件上报器（nil 安全）：每种拒绝除本机日志外，还经节流上报控制面留痕——
// SPA 隐身在挡谁，此前网关一重启就无从回答。
func Serve(addr string, v *auth.Verifier, ttl time.Duration, al *Allowlist, strict bool, knockMaxTTL time.Duration, rep *secevent.Reporter) error {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	slog.Info("SPA 敲门监听", "addr", addr, "ttl", ttl.String(), "strict", strict,
		"knockMaxTTL", knockMaxTTL.String(), "pubkey", v.HasPublicKey(), "acceptHS256", v.AcceptsLegacy())
	h := &handler{v: v, ttl: ttl, al: al, strict: strict, knockMaxTTL: knockMaxTTL, rep: rep, cache: knock.NewCache()}
	buf := make([]byte, 8192)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		h.handle(buf[:n], hostOf(src.String()))
	}
}

// handler 是 Serve 的循环体状态，抽出来只为一件事：**让「哪一类拒绝上报了哪个类别」可测**。
//
// ★Serve 本身是「真 UDP 监听 + 无限循环 + 不返回端口」，用例够不着它的分支；
// 而本波（行动 11-①）要改的正是分类，改错的症状是安全概览把正常员工列成攻击源——
// 那是页面上的一行文字，编译、集成、e2e 全绿。抽成方法后每一类拒绝都能直接驱动。
type handler struct {
	v           *auth.Verifier
	ttl         time.Duration
	al          *Allowlist
	strict      bool
	knockMaxTTL time.Duration
	rep         *secevent.Reporter
	cache       *knock.Cache
}

// handle 处理一个敲门包（ip 为源地址）。
func (h *handler) handle(pkt []byte, ip string) {
	token, protected, err := knock.Open(pkt, skew, h.cache)
	switch {
	case errors.Is(err, knock.ErrCacheFull):
		// ★表满不是「对方在重放」，是我方记不下了：只可能由洪泛造成，而被它挡下的
		// 这个包很可能来自**正常用户**。类别单列，并归在攻击源统计之外
		// （store.AttackExemptCats）——把正常用户的 IP 列进「攻击源 TOP」，
		// 管理员会去封他，而真正该做的是查洪泛来源。同 proxy-capacity 的处置。
		entries, rejected := h.cache.Stats()
		slog.Error("SPA 敲门拒绝（去重表已满，正被洪泛）", "src", ip,
			"表内条目", entries, "累计被拒", rejected)
		h.rep.Report("knock-cache-full", ip, "SPA 敲门拒绝（去重表已满，正被洪泛；本次被拒的来源未必是洪泛者）")
		return
	case errors.Is(err, knock.ErrClockSkew):
		// ★时钟超窗与「重放」分开报（wave11 行动 11-①）。合在一起的后果不是措辞不精确，
		// 而是**归因反了**：客户端保活每 15s 敲一次、每轮敲全部落点，一台时钟偏了 31 秒的
		// 正常员工机一天稳定产出几千次这种拒绝，必然把安全概览的「攻击源 TOP」顶到第一名，
		// 而类别中文名写着「敲门信封无效/重放」——管理员照着去封的是自己的员工，
		// 且真正该做的（给那台机器校时）在页面上一个字都没有。
		// 同批归入 store.AttackExemptCats：它不是攻击信号，判据见那里。
		// ★判读法：单一来源超窗 = 那台终端的钟；多个来源同时超窗且方向一致 = 怀疑
		// **网关自己**的钟（那半由控制面告警规则 clock_skew 覆盖：网关自报时钟 vs 控制面）。
		slog.Warn("SPA 敲门拒绝（时间戳超窗，多半是终端时钟偏差）", "src", ip, "err", err.Error())
		h.rep.Report("knock-clockskew", ip, "SPA 敲门拒绝："+err.Error())
		return
	case err != nil:
		// 剩下的两种都是真异常形态：nonce 缺失（信封不合规）与 nonce 重复（**被动重放**，
		// 整包重发）。两者与时钟无关，照旧计入攻击源统计。
		slog.Warn("SPA 敲门拒绝（信封无效/被动重放）", "src", ip, "err", err.Error())
		h.rep.Report("knock-envelope", ip, "SPA 敲门拒绝（信封无效/被动重放）")
		return
	}
	claims, err := h.v.Verify(token)
	if err != nil {
		slog.Warn("SPA 敲门拒绝（令牌无效）", "src", ip, "err", err.Error())
		h.rep.Report("knock-token", ip, "SPA 敲门拒绝（令牌无效）")
		return
	}
	// 用途闸：只认 control 签发的短时效一次性敲门令牌。
	if err := checkKnock(claims, protected, h.knockMaxTTL); err != nil {
		if h.strict {
			slog.Warn("SPA 敲门拒绝（令牌用途不符）", "src", ip, "user", claims.Name,
				"role", claims.Role, "use", claims.Use, "err", err.Error())
			h.rep.Report("knock-use", ip, "SPA 敲门拒绝（令牌用途不符，账号 "+claims.Name+"）")
			return
		}
		slog.Warn("SPA 敲门放行了非规范令牌（strict 已关闭，长效会话令牌可绕过控制面三道闸——仅限过渡）",
			"src", ip, "user", claims.Name, "err", err.Error())
	}
	// 一次性敲门令牌（带 jti）：同一 jti 只放行一次——杜绝令牌被解出后用新信封主动重放。
	// 去重窗按令牌实际剩余寿命 + 偏移，不再固定 10min 上界（敲门令牌只有 90s，
	// 固定上界会让每张用过的令牌在缓存里多躺 8 分半，放大 UDP 洪泛的内存占用）。
	if claims.Jti != "" {
		dedupTTL := time.Until(time.Unix(claims.Exp, 0)) + skew
		if max := h.knockMaxTTL + skew; dedupTTL > max {
			dedupTTL = max
		}
		if dedupTTL > 0 && h.cache.Seen("j:"+claims.Jti, dedupTTL) {
			slog.Warn("SPA 敲门拒绝（一次性令牌已用，主动重放被拒）", "src", ip, "jti", claims.Jti)
			h.rep.Report("knock-replay", ip, "SPA 敲门拒绝（一次性令牌已用，主动重放被拒，账号 "+claims.Name+"）")
			return
		}
	}
	// Allow 内在同一把锁下复核封禁：即便与并发强制下线相撞，也不会重开放行窗口。
	if !h.al.Allow(ip, claims.Name, claims.Role, h.ttl) {
		slog.Warn("SPA 敲门拒绝（用户已被强制下线，封禁期内）", "src", ip, "user", claims.Name)
		h.rep.Report("knock-banned", ip, "SPA 敲门拒绝（账号 "+claims.Name+" 已被强制下线，封禁期内）")
		return
	}
	slog.Info("SPA 敲门放行", "src", ip, "user", claims.Name, "role", claims.Role, "ttl", h.ttl.String())
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
