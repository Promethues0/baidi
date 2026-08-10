// Package risk 终端环境风险引擎：按安全中心基线评估终端上报的检查结果。
// 纯函数、无 IO；判定权在控制面（客户端只做采集与机械布尔化）。
package risk

import "baidi.dev/control/internal/store"

// Verdict 一次评估的可解释结论。
type Verdict struct {
	Score int    // 0-100，失败检查按严重度加权累计
	Level string // low | medium | high（违反 block 基线强制 high）
	// Disposal 处置档：allow | gray | degrade | block（violated 基线取最严）。
	//
	// ★四档**都有执行方**，语义定义在 store 包（见 store.DisposalAllow 一组常量的注释）：
	//   gray    → 访问权不变，控制面每轮策略下发记一条 observing 审计；
	//   degrade → 降权不断连：高敏资源（Resource.Sensitivity=high）从网关允许集合与
	//             客户端剖面里同时摘除，普通资源照常可访问；
	//   block   → 全断：拒发敲门令牌 + 撤放行窗 + 断隧道。
	// 加新档位前先想清楚谁执行它——只落库不执行的档位就是 config-only。
	Disposal string
	Reasons  []string // 失败检查的 label（缺失上报的附「（未上报）」）
	Unknowns []string // 不可判定检查的 label（observe 下不计分不抬处置，但必须让人看见）
}

// Options 评估口径开关。
type Options struct {
	// StrictUnknown 把「不可判定」的检查当成不合规（计分 + 抬处置）。
	// 由 BAIDI_POSTURE_ENFORCE=strict 驱动，与「缺报/过期即拒」是同一条 fail-closed 口径：
	// strict 的语义就是「说不清楚就不放行」。默认 observe——不可判定既不计分也不抬处置，
	// 只进 Unknowns 供页面与上报响应展示（对齐既有的「缺报默认放行」）。
	StrictUnknown bool
}

var severityWeight = map[string]int{"high": 25, "medium": 10, "low": 5}

// DisposalRank 处置严厉度排序值（block 最严）；未知处置视为 allow。
//
// 排序表只在 store 里定义一份（store.DisposalRank）——它同时被"跨设备取最差"
// （store.PostureVerdict）与用户状态页用到，三份抄写各改各的迟早分叉。
func DisposalRank(d string) int { return store.DisposalRank(d) }

// Evaluate 用启用且平台适用的基线评估上报的检查结果。
// 缺失某基线要求的 key 视为该检查失败（缺失即不合规，防选择性上报）；
// 上报了但标记 Unknown（探不到）的按 opts.StrictUnknown 处理，见 Options。
func Evaluate(platform string, checks []store.PostureCheckResult, baselines []store.BaselinePolicy, opts Options) Verdict {
	reported := make(map[string]store.PostureCheckResult, len(checks))
	for _, c := range checks {
		reported[c.Key] = c
	}
	v := Verdict{Level: "low", Disposal: store.DisposalAllow, Reasons: []string{}, Unknowns: []string{}}
	for _, b := range baselines {
		if b.Status != "enabled" || !platformApplies(platform, b.Platforms) {
			continue
		}
		violated := false
		for _, c := range b.Checks {
			if c.Platform != "All" && c.Platform != platform {
				continue
			}
			rep, present := reported[c.Key]
			// ★Unknown 先于 OK 判：客户端探不到时会把 OK 置 false，若先看 OK 就退化成
			// "不可判定 = 不合规"，恰是本分支要避免的误拒。恶意端把两者都置真也走这条，
			// 与直接报 OK=true 等价——posture 本就不是对抗被控终端的边界。
			if present && rep.Unknown {
				if !opts.StrictUnknown {
					v.Unknowns = append(v.Unknowns, c.Label+"（无法判定）")
					continue
				}
			} else if present && rep.OK {
				continue
			}
			violated = true
			w := severityWeight[c.Severity]
			if w == 0 {
				w = severityWeight["medium"]
			}
			v.Score += w
			// reason 是失败陈述而非检查项名（"磁盘已加密"单独出现会读反）
			reason := c.Label + " 未通过"
			switch {
			case !present:
				reason = c.Label + "（未上报）"
			case rep.Unknown:
				reason = c.Label + "（无法判定，strict 视为不合规）"
			}
			v.Reasons = append(v.Reasons, reason)
		}
		if violated && DisposalRank(b.Disposal) > DisposalRank(v.Disposal) {
			v.Disposal = b.Disposal
		}
	}
	if v.Score > 100 {
		v.Score = 100
	}
	switch {
	case v.Disposal == store.DisposalBlock || v.Score >= 60:
		v.Level = "high"
	case v.Score >= 30:
		v.Level = "medium"
	}
	return v
}

func platformApplies(platform string, platforms []string) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, p := range platforms {
		if p == platform {
			return true
		}
	}
	return false
}
