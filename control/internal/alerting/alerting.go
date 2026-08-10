// Package alerting 是业务告警的**纯判定层**：吃一份信号快照 + 规则清单，
// 吐出候选告警。它不碰数据库、不发通知、不看时钟（now 由调用方传入）。
//
// 之所以把判定单拎出来：告警最容易出的错不是"存不下来"，而是"条件写反了"——
// 而条件写反在集成环境里几乎测不出来（页面上就是"没有告警"，与一切正常无法区分）。
// 纯函数让每一条规则都能用一个构造出来的快照精确断言。
//
// ★每条规则读的都是真实存在的信号，出处逐条写在 store.alertKindSpecs 的 Signal 字段里。
// 取数（谁去问网关注册表、谁去查 jit_grants）在 api 层，见 api/alerts.go 的 alertSnapshot。
package alerting

import (
	"fmt"
	"sort"
	"strings"

	"baidi.dev/control/internal/store"
)

// GatewayStat 一台**已注册过**的网关的活性。
//
// ★只有注册过的网关才在这里出现：控制面重启后注册表是空的，一台从此再没上线的网关
// 不会产生离线告警。这是内存注册表的固有边界，不是 bug——但必须写下来，
// 否则"重启后告警消失"会被当成告警系统坏了。
type GatewayStat struct {
	ID       string
	LastSeen int64 // Unix 秒
}

// Snapshot 一次评估所需的全部信号。字段为空 = 该信号本轮无数据，
// 对应规则**不产生**候选（不是产生"一切正常"，也不是报错）。
type Snapshot struct {
	Now int64
	// OfflineAfterSec 网关离线判据的默认值（与 api.gatewayOnlineWindow 同源）；
	// 规则阈值 offlineSec 可覆盖它。
	OfflineAfterSec int64
	Gateways        []GatewayStat
	// Metrics 网关资源指标数据源的运行时探测结论。Ready=false 时资源水位规则
	// 一条候选都不产生，理由由调用方直接呈现给管理员（"等待数据面上报"）。
	Metrics store.MetricsProbe
	// MetricsFreshSec 指标样本的新鲜度上限：超过这个岁数的样本不参与判定
	// （拿一小时前的 CPU 报"现在超载"是谎报）。<=0 视为不限。
	MetricsFreshSec int64
	ActiveGrants    []store.JitGrant
	StaleGrants     []store.JitGrant
	UnlinkedApps    []AppRef
	Lockouts        []store.Lockout
	PostureBlocked  []string
	// AuditChain 审计链自检结论；nil = 本轮没查（存储不支持，或还没到自检周期）。
	// ★nil 与「查了、没问题」必须区分：把没查当成没问题，正是"防篡改链没人查等于没有"。
	AuditChain *ChainStatus
}

// AppRef 一个未关联受控资源的应用。
type AppRef struct{ ID, Name string }

// ChainStatus 审计防篡改链一次自检的结论。
type ChainStatus struct {
	OK       bool
	Checked  int
	BrokenAt int64
	// Err 自检本身没能完成（读库失败等）。★与 OK=false 是两回事：
	// 一个是"查出链断了"，一个是"没查成"，运维的下一步动作完全不同。
	Err string
}

// Candidate 一条候选告警（还没落库、还没去重）。
type Candidate struct {
	RuleID    string
	Kind      string
	Category  string
	Severity  string
	Title     string
	Detail    string
	ObjectKey string
	// CooldownSec 取自规则，由落库侧执行去重。
	CooldownSec int
}

// Evaluate 按规则清单评估快照，返回候选告警（顺序稳定：规则序 × 对象键序）。
// 禁用的规则、未知 kind 一律跳过。
func Evaluate(rules []store.AlertRule, snap Snapshot) []Candidate {
	var out []Candidate
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		spec, ok := store.AlertKindSpecOf(rule.Kind)
		if !ok {
			continue // 库里存着一个已被删掉的 kind：不猜语义，直接跳过
		}
		cs := evalRule(rule, spec, snap)
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].ObjectKey < cs[j].ObjectKey })
		out = append(out, cs...)
	}
	return out
}

// thresh 取规则阈值；规则里没有该键时回落到 kind 的默认值。
func thresh(rule store.AlertRule, spec store.AlertKindSpec, key string) float64 {
	if v, ok := rule.Threshold[key]; ok {
		return v
	}
	return spec.Thresholds[key]
}

func evalRule(rule store.AlertRule, spec store.AlertKindSpec, snap Snapshot) []Candidate {
	mk := func(objectKey, title, detail string) Candidate {
		return Candidate{
			RuleID: rule.ID, Kind: rule.Kind, Category: spec.Category, Severity: spec.Severity,
			Title: title, Detail: detail, ObjectKey: objectKey, CooldownSec: rule.CooldownSec,
		}
	}
	var out []Candidate
	switch rule.Kind {

	case store.AlertKindGatewayOffline:
		limit := int64(thresh(rule, spec, store.ThreshOfflineSec))
		if limit <= 0 {
			limit = snap.OfflineAfterSec
		}
		for _, gw := range snap.Gateways {
			gap := snap.Now - gw.LastSeen
			if gap <= limit {
				continue
			}
			out = append(out, mk("gw:"+gw.ID,
				"网关「"+gw.ID+"」心跳超时",
				fmt.Sprintf("已 %s 未收到该网关的注册心跳（判定阈值 %ds）。该网关此刻不参与在线会话统计，其后的敲门与隧道很可能已不可用。",
					humanGap(gap), limit)))
		}

	case store.AlertKindGatewayLoad:
		if !snap.Metrics.Ready {
			break // 数据源没就绪：不产生候选，理由由 api 层如实呈现（等待数据面上报）
		}
		cpu := thresh(rule, spec, store.ThreshCPUPercent)
		mem := thresh(rule, spec, store.ThreshMemPercent)
		disk := thresh(rule, spec, store.ThreshDiskPercent)
		for _, m := range snap.Metrics.Samples {
			if snap.MetricsFreshSec > 0 && snap.Now-m.TS > snap.MetricsFreshSec {
				continue // 陈旧样本不参与判定：拿一小时前的读数报"现在超载"是谎报
			}
			// ★只比较**采到了**的项：nil 表示网关如实报告"这一项采不到"，
			// 当成 0 会让一台采集失明的网关永远不告警，当成 100 会天天误报。
			var over []string
			if v, ok := overThresh(m.CPU, cpu); ok {
				over = append(over, fmt.Sprintf("CPU %.0f%%（阈值 %.0f%%）", v, cpu))
			}
			if v, ok := overThresh(m.Mem, mem); ok {
				over = append(over, fmt.Sprintf("内存 %.0f%%（阈值 %.0f%%）", v, mem))
			}
			if v, ok := overThresh(m.Disk, disk); ok {
				over = append(over, fmt.Sprintf("磁盘 %.0f%%（阈值 %.0f%%）", v, disk))
			}
			if len(over) == 0 {
				continue
			}
			out = append(out, mk("gwload:"+m.GatewayID,
				"网关「"+m.GatewayID+"」资源水位超阈值",
				"最近一次上报："+strings.Join(over, "，")))
		}

	case store.AlertKindGrantExpiring:
		before := int64(thresh(rule, spec, store.ThreshBeforeMin)) * 60
		for _, g := range snap.ActiveGrants {
			left := g.ExpiresAt - snap.Now
			if left <= 0 || left > before {
				continue
			}
			out = append(out, mk("grant:"+g.ID,
				"JIT 授予即将到期："+g.User+" → "+grantResName(g),
				fmt.Sprintf("该临时授权将在 %s 后到期（到期后网关下一轮轮询即失去放行）。如仍需访问请重新走申请审批。", humanGap(left))))
		}

	case store.AlertKindGrantStale:
		grace := int64(thresh(rule, spec, store.ThreshGraceMinutes)) * 60
		for _, g := range snap.StaleGrants {
			overdue := snap.Now - g.ExpiresAt
			if overdue < grace {
				continue
			}
			out = append(out, mk("grant:"+g.ID,
				"JIT 授予已过期未回收："+g.User+" → "+grantResName(g),
				fmt.Sprintf("该授予已过期 %s，但 jit_grants 里的状态仍是 active。数据面早已不再放行（按 expires_at 过滤），"+
					"但授权清单显示的是失真状态。", humanGap(overdue))))
		}

	case store.AlertKindAppUnlinked:
		for _, a := range snap.UnlinkedApps {
			out = append(out, mk("app:"+a.ID,
				"应用「"+a.Name+"」未关联受控资源",
				"该应用的 resourceId 为空：JIT 自助申请解析不出目标资源，客户端接入剖面也排不出到它的路由——"+
					"两处都不会报错，表现为「点开应用不走隧道」。请在资源策略页补齐关联。"))
		}

	case store.AlertKindAccountLockout:
		for _, l := range snap.Lockouts {
			if l.Until <= snap.Now {
				continue // 已到期的锁定不报（Guard 的懒清理可能还没扫到它）
			}
			what := "账号「" + l.Key + "」"
			if l.Kind == store.LockKindIP {
				what = "源 IP " + l.Key
			}
			out = append(out, mk("lockout:"+l.Kind+":"+l.Key,
				what+"因连续登录失败被锁定",
				l.Reason+"；锁定将在 "+humanGap(l.Until-snap.Now)+"后自动解除，可在安全中心提前解锁。"))
		}

	case store.AlertKindPostureBlock:
		for _, acc := range snap.PostureBlocked {
			out = append(out, mk("posture:"+acc,
				"终端环境不合规已阻断："+acc,
				"该账号任一设备的最新合规判定为 block：控制面已拒发敲门令牌，并经网关策略下发撤窗断隧道。"+
					"修复终端环境并重新上报后自动恢复。"))
		}

	case store.AlertKindAuditChain:
		st := snap.AuditChain
		if st == nil {
			break // 本轮没查——不产生"一切正常"的假结论
		}
		switch {
		case st.Err != "":
			out = append(out, mk("audit-chain",
				"审计防篡改链自检未能完成",
				"周期性自检执行失败："+st.Err+"。这不等于链已损坏，但在排除故障前，防篡改保证处于未验证状态。"))
		case !st.OK:
			out = append(out, mk("audit-chain",
				"审计防篡改链校验失败",
				fmt.Sprintf("重算 %d 条审计记录，链在第 %d 条（seq）处断裂：该行之后的记录与其前序不再匹配，"+
					"意味着 audit_log 被就地修改过或行被删除。请立即取证。", st.Checked, st.BrokenAt)))
		}
	}
	return out
}

// overThresh 报告一个**可空**指标是否超过阈值。nil（采不到）一律返回 false：
// 不可判定 ≠ 不合规，与终端 posture 的 unknown 同口径。
func overThresh(v *float64, limit float64) (float64, bool) {
	if v == nil {
		return 0, false
	}
	return *v, *v > limit
}

// grantResName 授予的资源展示名（冗余名为空时回落资源 id）。
func grantResName(g store.JitGrant) string {
	if strings.TrimSpace(g.ResourceName) != "" {
		return g.ResourceName
	}
	return g.ResourceID
}

// humanGap 把秒数说成人话（告警正文要给人看，"7325 秒"没人算得动）。
func humanGap(sec int64) string {
	if sec < 0 {
		sec = -sec
	}
	switch {
	case sec < 60:
		return fmt.Sprintf("%d 秒", sec)
	case sec < 3600:
		return fmt.Sprintf("%d 分钟", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%d 小时 %d 分钟", sec/3600, (sec%3600)/60)
	default:
		return fmt.Sprintf("%d 天 %d 小时", sec/86400, (sec%86400)/3600)
	}
}
