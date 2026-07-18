// Package risk 终端环境风险引擎：按安全中心基线评估终端上报的检查结果。
// 纯函数、无 IO；判定权在控制面（客户端只做采集与机械布尔化）。
package risk

import "baidi.dev/control/internal/store"

// Verdict 一次评估的可解释结论。
type Verdict struct {
	Score    int      // 0-100，失败检查按严重度加权累计
	Level    string   // low | medium | high（违反 block 基线强制 high）
	Disposal string   // allow | degrade | gray | block（violated 基线取最严）
	Reasons  []string // 失败检查的 label（缺失上报的附「（未上报）」）
}

var severityWeight = map[string]int{"high": 25, "medium": 10, "low": 5}
var disposalRank = map[string]int{"allow": 0, "degrade": 1, "gray": 2, "block": 3}

// DisposalRank 处置严厉度排序值（block 最严）；未知处置视为 allow。
func DisposalRank(d string) int { return disposalRank[d] }

// Evaluate 用启用且平台适用的基线评估上报的检查结果。
// 缺失某基线要求的 key 视为该检查失败（缺失即不合规，防选择性上报）。
func Evaluate(platform string, checks []store.PostureCheckResult, baselines []store.BaselinePolicy) Verdict {
	reported := make(map[string]store.PostureCheckResult, len(checks))
	for _, c := range checks {
		reported[c.Key] = c
	}
	v := Verdict{Level: "low", Disposal: "allow", Reasons: []string{}}
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
			if present && rep.OK {
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
			if !present {
				reason = c.Label + "（未上报）"
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
	case v.Disposal == "block" || v.Score >= 60:
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
