package store

import "context"

// ── 攻击源统计（wave7 行动 5：FR-MON-05 + FR-AUDIT-02 的机读半边）──
//
// 数据面拒绝事件随网关心跳落审计（人读）的同时，按 (网关, 源IP, 类别, 小时桶)
// 计入 attack_sources（机读）。安全概览的「隐身防线」与 24h 攻击源统计从这里取数——
// 此前那格用 trusted_devices 台账顶包，而「谁在敲门」才是 SPA 隐身在挡攻击的唯一可见证据。
//
// ★计数值累加的是网关侧节流器（gateway/internal/secevent）报来的聚合数，
// 不是行数：一行「5 分钟内 4093 次」在这里就是 +4093，量级不失真。

// AttackCatZh 拒绝类别的中文名（展示唯一真相；类别枚举见 gateway cplane.Event.Cat 注释）。
// 网关报来未知类别时原样显示 key——新网关先于控制面升级的过渡期不丢数据。
var AttackCatZh = map[string]string{
	"knock-envelope":    "敲门信封无效/重放",
	"knock-token":       "敲门令牌无效",
	"knock-use":         "敲门令牌用途不符",
	"knock-replay":      "敲门令牌重放",
	"knock-banned":      "敲门封禁期拒绝",
	"proxy-unauth":      "未敲门直连隧道口",
	"proxy-revoked":     "隧道放行已撤销",
	"proxy-preamble":    "隧道前导不完整",
	"proxy-nopreamble":  "隧道未声明目标资源（无 CONNECT 前导）",
	"proxy-ssrf":        "隧道资源未注册/疑似 SSRF",
	"proxy-authz":       "隧道无资源授权",
	"web-ticket":        "Web 票据无效",
	"web-ticket-replay": "Web 票据重放",
	"web-entry-banned":  "Web 入口封禁期拒绝",
	"web-res-missing":   "Web 资源未下发",
	"web-entry-authz":   "Web 入口无授权",
	"web-cookie":        "Web 会话 Cookie 无效",
	"web-cookie-cross":  "Web Cookie 跨应用复用",
	"web-cross-origin":  "Web 跨应用请求",
	"web-banned":        "Web 会话封禁期拒绝",
	"web-authz":         "Web 逐请求鉴权拒绝",
}

// attackCatLabel 类别中文名（未知类别原样回 key，不编造）。
func attackCatLabel(cat string) string {
	if zh, ok := AttackCatZh[cat]; ok {
		return zh
	}
	return cat
}

// AttackTop 一个攻击源的聚合行（安全概览 TOP 列表用）。
type AttackTop struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
	// Cat 该来源计数最多的类别（中文名）。一个 IP 常同时打多个面，取主要形态展示。
	Cat string `json:"cat"`
}

// AttackStat 近 24h 攻击源统计（安全概览「隐身防线」卡片与攻击源面板的数据源）。
type AttackStat struct {
	// Sources 24h 内出现过的独立来源数（「（多源聚合）」这类聚合行算一个来源）。
	Sources int `json:"sources"`
	// Denies 24h 内的拒绝总次数（聚合计数累加，非行数）。
	Denies int `json:"denies"`
	// Top 按次数排序的 TOP5 来源。
	Top []AttackTop `json:"top"`
	// Trend 24 个小时桶的拒绝次数（从 23 小时前到当前小时，空桶为 0——
	// 这里 0 是真实的「这一小时没有拒绝」，与设备指标的 NULL 语义不同）。
	Trend []KV `json:"trend"`
}

// AttackStore 攻击源统计的读写能力（SQLiteStore 实现；api 层类型断言取用，
// Memory 种子模式没有——攻击源是真实数据域，绝不造种子攻击）。
type AttackStore interface {
	// RecordAttack 累加一条拒绝事件（ts 为控制面收到的时刻，Unix 秒）。
	RecordAttack(ctx context.Context, gatewayID, ip, cat string, count int, ts int64) error
	// AttackStats 近 sinceHours 小时的聚合统计。
	AttackStats(ctx context.Context, sinceHours int) (AttackStat, error)
	// PurgeAttackSources 删掉 before（Unix 秒）之前的小时桶，返回删除行数。
	PurgeAttackSources(ctx context.Context, before int64) (int64, error)
}
