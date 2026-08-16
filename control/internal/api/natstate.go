package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"baidi.dev/control/internal/store"
)

// ── 地址转换运行态回执（wave8 行动 3，FR-NAT-02/11/17）──
//
// 此前 `nat_policies.enabled` 那一个开关同时表达两件事：「管理员想让它开」与
// 「它现在真的开着」。于是两种失效在控制台上与正常完全同形，且**都不打日志**：
//
//	① 网关没带 -nat 启动（deploy/install-remote.sh 生成的 baidi-gateway.env
//	   根本不含这一项）→ applyNAT() 首行 `if natApp == nil { return }` 静默返回；
//	② 有内核后端但 nft 语法/权限出错 → 规则从未进内核，只有网关本机 slog。
//
// 症状分别是「发布的业务公网打不开」和「内网网段上不了网」，而管理员在页面上
// 看到的是绿的。IPSec 早就识别并修掉了同一形态（拆出 ipsec_sa_state + 四态 +
// ConfigWarning），NAT 这边原样重犯了一遍——本文件是照那条路补上的回执侧。

// gwNATHit 一条规则的命中计数（与 natfw.Hit / cplane.NATHit 同构）。
type gwNATHit struct {
	PolicyID string `json:"policyId"`
	Packets  int64  `json:"packets"`
	Bytes    int64  `json:"bytes"`
}

// gwNATState 网关随心跳上报的地址转换运行态。字段语义见 cplane.NATState。
type gwNATState struct {
	Enabled    bool        `json:"enabled"`
	DryRun     bool        `json:"dryrun"`
	Backend    string      `json:"backend"`
	Applied    int         `json:"applied"`
	LastError  string      `json:"lastError"`
	LastAt     int64       `json:"lastAt"`
	Forwarding *bool       `json:"forwarding"` // nil = 读不到（不是「关着」）
	Hits       *[]gwNATHit `json:"hits"`       // nil = 读不到（pf 拆不到规则粒度 / nft -j 失败）
}

// gwNATInfo 某台网关最近一次上报的 NAT 运行态 + 收到时刻。
type gwNATInfo struct {
	State gwNATState
	At    int64
}

// NATReceipt 一台网关的地址转换回执（页面「网关回执」栏与 /diag 消费）。
type NATReceipt struct {
	GatewayID string `json:"gatewayId"`
	// Status 五态，逐个都是**真实可区分**的形态，不是好看话：
	//   unreported  该网关从未上报过 nat 字段（旧版本网关）——控制面对它一无所知
	//   disabled    网关明确说「我没带 -nat 启动」，规则一条都不会进内核
	//   failed      上一次灌入内核失败（lastError 是原文）
	//   dryrun      只生成规则集不灌内核（自检模式）
	//   applied     已灌入内核
	Status string `json:"status"`
	// Say 一句话结论，直接渲染给管理员看（必须给得出下一步动作）。
	Say string `json:"say"`
	// Online 该网关此刻是否在心跳新鲜期内。离线时上面那些是**陈值**，
	// 页面必须一并说清楚，否则管理员会照着一份三天前的回执排障。
	Online  bool   `json:"online"`
	Backend string `json:"backend,omitempty"`
	Applied int    `json:"applied"`
	// Forwarding 内核 IP 转发。★三态：nil = 不可判定。转发关着时规则全部正确
	// 但一个包都过不去，且没有任何报错——这一格是那种失效唯一的前置信号。
	Forwarding *bool  `json:"forwarding,omitempty"`
	LastError  string `json:"lastError,omitempty"`
	LastAt     int64  `json:"lastAt,omitempty"`
	At         int64  `json:"at,omitempty"` // 控制面收到这份回执的时刻
}

// NAT 回执状态常量。
const (
	NATRcptUnreported = "unreported"
	NATRcptDisabled   = "disabled"
	NATRcptFailed     = "failed"
	NATRcptDryRun     = "dryrun"
	NATRcptApplied    = "applied"
)

// natReceipts 为一批 NAT 策略涉及的每台网关算出回执。
//
// 只为**策略真的落在其上**的网关算：没有任何策略的网关，它开没开 NAT 与管理员无关，
// 报出来只会在页面上堆一排与本页无关的告警。
func (s *Server) natReceipts(policies []store.NATPolicy) map[string]NATReceipt {
	ids := map[string]bool{}
	for _, p := range policies {
		if id := strings.TrimSpace(p.GatewayID); id != "" {
			ids[id] = true
		}
	}
	out := make(map[string]NATReceipt, len(ids))
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range ids {
		out[id] = s.natReceiptLocked(id)
	}
	return out
}

// natReceiptLocked 单台网关的回执。调用方须持 s.mu。
func (s *Server) natReceiptLocked(id string) NATReceipt {
	r := NATReceipt{GatewayID: id, Status: NATRcptUnreported}
	if g, ok := s.gateways[id]; ok {
		r.Online = gatewayFresh(g.LastSeen, time.Now())
	}
	info, ok := s.gwNAT[id]
	if !ok {
		// 两种成因合并成一句话，因为管理员的下一步动作是同一个：去看那台网关。
		r.Say = "该网关从未上报地址转换运行态——多半是网关版本较旧（v0.4 之前不上报），" +
			"也可能是它从未成功心跳过。控制面无从确认规则是否真的进了内核。"
		return r
	}
	st := info.State
	r.At, r.Backend, r.Applied = info.At, st.Backend, st.Applied
	r.Forwarding, r.LastError, r.LastAt = st.Forwarding, st.LastError, st.LastAt
	switch {
	case !st.Enabled:
		r.Status = NATRcptDisabled
		r.Say = "网关未带 -nat 启动：这里配的规则一条都不会进内核。" +
			"请在该网关的启动参数或 BAIDI_GW_NAT 里开启地址转换后重启网关。"
	case st.LastError != "":
		r.Status = NATRcptFailed
		r.Say = "规则灌入内核失败，网关保留上一版规则并在下一轮重试：" + st.LastError
	case st.DryRun:
		r.Status = NATRcptDryRun
		r.Say = "网关处于 -nat-dryrun：只生成规则集、不灌内核，转换不会真的发生。"
	default:
		r.Status = NATRcptApplied
		r.Say = fmt.Sprintf("已灌入内核（后端 %s，%d 条策略生效）", st.Backend, st.Applied)
	}
	// 转发是独立的一道闸：规则灌进去了、转发关着，包一样过不去且无报错。
	// 故这句追加在结论之后，而不是覆盖它——两件事都要说。
	if r.Status == NATRcptApplied && st.Forwarding != nil && !*st.Forwarding {
		r.Say += "。★但内核 IP 转发处于关闭状态：规则全部正确，一个包也不会被转发"
	}
	if !r.Online {
		r.Say += "（注意：该网关当前离线，以上是最后一次心跳的陈值）"
	}
	return r
}

// natHits 逐策略命中计数。
//
// 返回 (计数表, 有没有任何一台网关报得出计数)。第二个返回值不可省：
// 读不到计数（pf 拆不到规则粒度 / nft -j 失败）与「规则一次都没被命中」
// 在页面上必须分得开——前者去查网关，后者去查流量为什么没走过来。
func (s *Server) natHits(policies []store.NATPolicy) (map[string]gwNATHit, bool) {
	ids := map[string]bool{}
	for _, p := range policies {
		if id := strings.TrimSpace(p.GatewayID); id != "" {
			ids[id] = true
		}
	}
	out := map[string]gwNATHit{}
	known := false
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range ids {
		info, ok := s.gwNAT[id]
		if !ok || info.State.Hits == nil {
			continue
		}
		known = true
		for _, h := range *info.State.Hits {
			out[h.PolicyID] = gwNATHit{PolicyID: h.PolicyID, Packets: h.Packets, Bytes: h.Bytes}
		}
	}
	return out, known
}

// natReceiptWarnings 把回执里「配了却不会生效」的那些翻成页面顶部的告警。
//
// 只报**启用中的策略**所在的网关：管理员把策略关掉本来就不指望它生效，
// 为一条 disabled 的策略报「网关没开 NAT」是噪声。
func natReceiptWarnings(policies []store.NATPolicy, rcpts map[string]NATReceipt) []string {
	live := map[string]bool{}
	for _, p := range policies {
		if p.Enabled {
			if id := strings.TrimSpace(p.GatewayID); id != "" {
				live[id] = true
			}
		}
	}
	ids := make([]string, 0, len(live))
	for id := range live {
		ids = append(ids, id)
	}
	sort.Strings(ids) // 稳定顺序：告警条目每次刷新乱跳会让人以为状态在变
	var out []string
	for _, id := range ids {
		r, ok := rcpts[id]
		if !ok || r.Status == NATRcptApplied {
			// applied 且转发正常时不报。转发关着的情况由下面那条单独兜住。
			if ok && r.Forwarding != nil && !*r.Forwarding {
				out = append(out, fmt.Sprintf("网关「%s」的内核 IP 转发处于关闭状态：地址转换规则全部正确，但一个包都不会被转发。", id))
			}
			continue
		}
		out = append(out, fmt.Sprintf("网关「%s」：%s", id, r.Say))
	}
	return out
}

// checkNAT /diag 的「地址转换生效性」检查项（wave8 行动 3）。
//
// 它回答的是页面上那个开关回答不了的问题：**规则到底进内核了没有**。
// 没有任何启用中的策略时 skip——为一个没人用的功能常年挂一条 warn 是噪声。
func (s *Server) checkNAT(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "nat", Category: "dataplane", Name: "地址转换规则生效性"}
	if s.nat == nil {
		c.Status = "skip"
		c.Summary = "当前后端不支持地址转换（纯内存演示栈）"
		return c
	}
	ps, err := s.nat.NATPolicies(ctx)
	if err != nil {
		c.Status = "warn"
		c.Summary = "读地址转换策略失败：" + err.Error()
		return c
	}
	var live []store.NATPolicy
	for _, p := range ps {
		if p.Enabled {
			live = append(live, p)
		}
	}
	if len(live) == 0 {
		c.Status = "skip"
		c.Summary = "没有启用中的地址转换策略"
		c.Metric = fmt.Sprintf("已配 %d 条（全部停用）", len(ps))
		return c
	}
	rcpts := s.natReceipts(live)
	ids := make([]string, 0, len(rcpts))
	for id := range rcpts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	bad, unknown := 0, 0
	for _, id := range ids {
		r := rcpts[id]
		st := "pass"
		switch r.Status {
		case NATRcptApplied:
			if r.Forwarding != nil && !*r.Forwarding {
				st, bad = "fail", bad+1 // 规则对、转发关着 = 一个包都不通，且无报错
			}
		case NATRcptUnreported:
			st, unknown = "warn", unknown+1
		default: // disabled / failed / dryrun
			st, bad = "fail", bad+1
		}
		c.Items = append(c.Items, DiagItem{Label: id, Value: r.Say, Status: st})
	}
	c.Metric = fmt.Sprintf("启用 %d 条策略 · 涉及 %d 台网关", len(live), len(ids))
	switch {
	case bad > 0:
		c.Status = "fail"
		c.Summary = fmt.Sprintf("%d 台网关上的地址转换规则没有真正生效（配置是绿的，内核里不是）", bad)
		c.Hint = "逐条见下方明细：多半是网关没带 -nat 启动，或规则灌入内核失败"
	case unknown > 0:
		c.Status = "warn"
		c.Summary = fmt.Sprintf("%d 台网关未上报地址转换运行态，无从确认规则是否进了内核", unknown)
		c.Hint = "低于 v0.5 的网关不上报该字段；升级后每次心跳自动回报。未上报 ≠ 已生效"
	default:
		c.Status = "pass"
		c.Summary = "涉及的网关都已回报规则已灌入内核"
	}
	return c
}
