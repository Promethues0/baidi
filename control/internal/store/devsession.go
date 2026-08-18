package store

import (
	"context"
	"sort"
	"strconv"
	"strings"
)

// ── 终端接入会话（FR-POLICY-29/30 的判定材料）──
//
// 与 `trusted_devices` 分表，理由与 `ipsec_sites.status` / `ipsec_sa_state` 那次拆分完全相同：
// 一张表不能同时表达「管理员登记了这台设备」（台账、长期意图）与「它此刻正接入着」
// （运行态、秒级变化）。混在一起的直接后果是台账页上的「已授信」会随接入状态闪烁。

// 接入会话状态。
const (
	DevSessionActive  = "active"  // 正在接入（或最近还在续敲门令牌）
	DevSessionTimeout = "timeout" // 因无业务流量被注销，须重新登录
)

// DevSessionStaleDays 多久没再敲门就清掉这一行（防无界增长）。
// 只是垃圾回收，不是判据——判据是 LastKnock/LastActive 的时间差。
const DevSessionStaleDays = 30

// DeviceSession 一台终端的接入会话。
type DeviceSession struct {
	Account     string `json:"account"`
	Fingerprint string `json:"fingerprint"`
	// Platform 终端平台（Windows|macOS|Linux|iOS|Android|""）。
	// 空串 = 客户端没报过 posture，平台不可判定——分平台计数时按 PC 处理（见 IsMobilePlatform）。
	Platform string `json:"platform"`
	// IP 最近一次取敲门令牌时控制面看到的源地址。
	// ★它是「网关报来的会话」与「这一行」之间唯一的连接键：网关的会话按源 IP 记，
	// 而它不知道设备指纹（SPA 单包里没有）。同一 NAT 出口下的两台终端会共用一个 IP，
	// 此时两台的活跃时刻互相顶替——方向是 fail-open（不该踢的不踢），已在页面上写明。
	IP        string `json:"ip"`
	FirstSeen int64  `json:"firstSeen"`
	LastKnock int64  `json:"lastKnock"`
	// LastActive 最近一次业务连接（网关回执）。**三态**：
	// ActivityKnown=false → 没有任何网关报过这条会话的活跃时刻（旧网关 / 从没连上过网关）。
	LastActive    int64  `json:"lastActive"`
	ActivityKnown bool   `json:"activityKnown"`
	State         string `json:"state"`
	// EndedReason 被注销时的原因（页面与审计用）。
	EndedReason string `json:"endedReason,omitempty"`
}

// IsMobilePlatform 报告平台是否算移动端（分平台计数用）。
//
// ★不可判定（空串）按 **PC** 计：把它算成移动端的话，一个从没报过 posture 的
// Windows 终端会去挤移动端的名额，而管理员在页面上看到的是「PC 1/3」。
// 两种错法都不完美，选这一种是因为它与「桌面客户端是主接入形态」一致。
func IsMobilePlatform(p string) bool {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "ios", "android", "harmonyos":
		return true
	}
	return false
}

// DevSessionStore 接入会话的读写（SQLite 后端实现；纯 Memory 后端没有它，
// 此时接入策略整块**不生效**并在页面上如实说明——不是静默跳过）。
type DevSessionStore interface {
	// TouchDeviceSession 记一次敲门（新建或续期）。返回续期**前**的那一行（不存在则 ok=false）。
	TouchDeviceSession(ctx context.Context, account, fingerprint, platform, ip string, now int64) (DeviceSession, bool, error)
	// DeviceSessions 该账号名下全部接入会话。
	DeviceSessions(ctx context.Context, account string) ([]DeviceSession, error)
	// EndDeviceSession 把一条会话标记为已注销（原因入库，页面与审计都要说得出为什么）。
	EndDeviceSession(ctx context.Context, account, fingerprint, reason string, now int64) error
	// ReviveDeviceSessions 登录时把该账号（指定指纹，空则全部）的已注销会话恢复成可接入。
	ReviveDeviceSessions(ctx context.Context, account, fingerprint string) error
	// MarkDeviceActivity 网关回执：该账号在某源 IP 上的最近业务连接时刻。
	// lastActive=0 表示"网关报了、但这条会话从未有业务连接"，同样要落库（ActivityKnown=true）。
	MarkDeviceActivity(ctx context.Context, account, ip string, lastActive int64) error
	// AllDeviceSessions 全量（管理页/诊断用）。
	AllDeviceSessions(ctx context.Context) ([]DeviceSession, error)
	// DeleteDeviceSession 删掉一条会话行。**被并发上限拒之门外的新终端必须删**——
	// 记账发生在判定之前（并发下必须如此），没进来的那台若把行留着，
	// 它会在下一次排名里参与竞争，把一台真正在线的终端挤掉。
	DeleteDeviceSession(ctx context.Context, account, fingerprint string) error
}

// AccessDecision 接入闸的判定结果。
type AccessDecision struct {
	Allowed bool
	// Reason 拒绝原因（要点名是哪条规则、当前数值），直接给用户看。
	Reason string
	// Rule 命中的规则（concurrency | idle），审计用。
	Rule string
}

// EvaluateAccess 纯判定：这台终端此刻能否再取一张敲门令牌。
//
// 入参：
//   - sessions：该账号名下**全部**接入会话（含本机那条——调用方是先记账后判定的）；
//   - self：本机会话的**续期前**快照；existed=false 表示这是它第一次出现；
//   - now：服务端当前 Unix 秒；onlineWindowSec：多久没敲门就算离线。
//
// ★纯函数、不碰 IO：条件写反在集成环境里与"一切正常"无法区分（没人被拒 =
// 看起来很正常），只有纯函数测得住（与 alerting.Evaluate 同一条理由）。
// 取数在 api.accessSessionGate。
func EvaluateAccess(p AccessPolicy, sessions []DeviceSession, self DeviceSession, existed bool,
	now int64, onlineWindowSec int64) AccessDecision {
	// ── FR-POLICY-30 接入超时注销 ──
	// 判据是**业务流量**，不是敲门保活：客户端只要不退出就每 15s 敲一次门，
	// 拿保活当活跃的话这条规则永远不会触发。
	if p.IdleEnabled && existed {
		if d, ok := idleSeconds(self, now); ok && d > int64(p.IdleMinutes)*60 {
			return AccessDecision{Rule: "idle", Reason: idleReason(p, d)}
		}
	}
	// 已被判过超时的会话，必须重新登录才能恢复（登录会删掉这一行，下次敲门重建）。
	// ★这一条独立于 IdleEnabled：管理员事后关掉规则，不该让已经注销的会话
	// 在下一个 15s 保活里自己活过来——那等于"注销"从未发生。
	if existed && self.State == DevSessionTimeout {
		return AccessDecision{Rule: "idle", Reason: "接入已超时注销（" + self.EndedReason + "），请重新登录"}
	}

	// ── FR-POLICY-29 同时在线设备上限 ──
	if !p.DeviceLimitEnabled {
		return AccessDecision{Allowed: true}
	}
	limit, scope := p.MaxDevices, "终端"
	if p.SplitPlatform && IsMobilePlatform(self.Platform) {
		limit, scope = p.MaxDevicesMobile, "移动端"
	} else if p.SplitPlatform {
		scope = "PC 端"
	}
	// PRD 原文：0 = 禁止登录。
	if limit == 0 {
		return AccessDecision{Rule: "concurrency",
			Reason: "接入策略已把「同时在线" + scope + "上限」设为 0（= 禁止接入），请联系管理员"}
	}
	// 名额按**先到先得**分配：把同类的在线终端（含本机）按首次接入时间排序，
	// 本机排在第 limit 名之后就没有名额。
	//
	// ★为什么不是简单的「本机已经在线就放行」：那样写的话，管理员把上限从 5 调到 2
	// 之后，已经在线的 5 台会各自靠保活无限续期，新上限**永远不会生效**——
	// 一条改了却不起作用的安全配置，页面上还显示着"已启用 · 2 台"。
	// 按 first_seen 排序则会让超出的那几台在下一个保活周期被挤掉，几分钟内收敛。
	//
	// ★同时也解决了另一个反向错误：判据若是"当前列表里有没有我"，由于调用方是
	// **先记账后判定**的（并发下必须如此），列表里必然有自己，这条上限对谁都不会触发。
	online := onlineDevices(sessions, self, existed, p, now, onlineWindowSec)
	deny := AccessDecision{Rule: "concurrency",
		Reason: "已达同时在线" + scope + "上限（" + strconv.Itoa(limit) + " 台），请先在其它终端退出后再接入"}
	if !existed {
		// 新来的那台：占不占得上名额只看**别人**占了几个。
		// ★不能用排名判：first_seen 是秒级的，同一秒接入的两台会由指纹决定先后，
		// 于是一台新终端可能凭字典序把一台已经在线的挤下去（它下一个保活周期才发现自己被踢，
		// 而"是谁把我挤掉的"在任何日志里都看不出来）。新来的永远排在已在线的后面。
		if len(online)-1 >= limit {
			return deny
		}
		return AccessDecision{Allowed: true}
	}
	rank := -1
	for i, fp := range online {
		if fp == self.Fingerprint {
			rank = i
			break
		}
	}
	if rank < 0 || rank >= limit {
		return deny
	}
	return AccessDecision{Allowed: true}
}

// onlineDevices 当前算作"在线"的同类终端指纹，**含本机**，按「首次接入时间 → 指纹」排序。
//
// 排序键必须带指纹这一维：first_seen 是秒级的，两台同一秒接入的终端会让顺序在
// 每次判定时抖动（sort.Slice 不稳定），表现为两台机器轮流被踢。
func onlineDevices(sessions []DeviceSession, self DeviceSession, existed bool, p AccessPolicy,
	now, onlineWindowSec int64) []string {
	type cand struct {
		fp    string
		first int64
	}
	list := []cand{}
	seenSelf := false
	for _, s := range sessions {
		if s.State == DevSessionTimeout {
			continue
		}
		if s.Fingerprint != self.Fingerprint && now-s.LastKnock > onlineWindowSec {
			continue // 早就不再续敲门令牌 = 已经离线（本机此刻正在敲，不适用）
		}
		// 分平台计数时，只和同类的比名额。
		if p.SplitPlatform && IsMobilePlatform(s.Platform) != IsMobilePlatform(self.Platform) {
			continue
		}
		if s.Fingerprint == self.Fingerprint {
			seenSelf = true
		}
		list = append(list, cand{s.Fingerprint, s.FirstSeen})
	}
	if !seenSelf {
		// 调用方还没来得及记账（或用的是纯判定），本机按"此刻首次接入"参与排序。
		list = append(list, cand{self.Fingerprint, self.FirstSeen})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].first != list[j].first {
			return list[i].first < list[j].first
		}
		return list[i].fp < list[j].fp
	})
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, c.fp)
	}
	return out
}

// idleSeconds 这条会话已经多久没有业务流量；ok=false 表示**不可判定**。
//
// ★不可判定的两种来源都必须走 false：① 网关根本不报活跃时刻（旧版本）；
// ② 这条会话还没被任何网关报过。此时绝不能拿"没有消息"当"没有流量"——
// 判据缺席就把人踢下线，是本项目反复在杀的那种「探不到当确定结论」。
func idleSeconds(s DeviceSession, now int64) (int64, bool) {
	if !s.ActivityKnown {
		return 0, false
	}
	base := s.LastActive
	if base == 0 {
		base = s.FirstSeen // 网关报了"从未有业务连接"：从接入那一刻起算
	}
	if base == 0 || now < base {
		return 0, false
	}
	return now - base, true
}

func idleReason(p AccessPolicy, idle int64) string {
	return "已超过 " + strconv.Itoa(p.IdleMinutes) + " 分钟无业务流量，接入已自动注销（实际空闲 " +
		strconv.Itoa(int(idle/60)) + " 分钟），请重新登录"
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
