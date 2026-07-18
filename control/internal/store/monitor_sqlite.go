package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// UserStates 覆盖：真实 users 表 × posture 判定（脱种子）。
// state 优先级 disabled > locked > risk-high > risk-low；状态正常且无 posture 异常的用户不进清单；
// idle（空闲挂起）无真实来源，诚实为 0。
func (s *SQLiteStore) UserStates(ctx context.Context) (UserStateBundle, error) {
	ub, err := s.Users(ctx)
	if err != nil {
		return UserStateBundle{}, err
	}
	reports, err := s.PostureReports(ctx)
	if err != nil {
		return UserStateBundle{}, err
	}
	rank := map[string]int{"allow": 0, "degrade": 1, "gray": 2, "block": 3}
	worst := map[string]PostureReport{}
	for _, r := range reports {
		w, ok := worst[r.User]
		if !ok || rank[r.Verdict] > rank[w.Verdict] || (rank[r.Verdict] == rank[w.Verdict] && r.TS > w.TS) {
			worst[r.User] = r
		}
	}
	now := time.Now().Unix()
	items := []UserStateItem{}
	for _, u := range ub.Users {
		key := strings.ToLower(strings.TrimSpace(u.Account))
		rep, hasRep := worst[key]
		var state, riskLv string
		reasons := []string{}
		lastEvent, lastSeen := "—", "—"
		switch {
		case u.Status == "disabled":
			state, riskLv = "disabled", "none"
			reasons = append(reasons, "账号已被管理员禁用")
			lastEvent = "管理员禁用账号"
		case u.Status == "locked":
			state, riskLv = "locked", "high"
			reasons = append(reasons, "账号已锁定")
			lastEvent = "账号锁定"
		case hasRep && (rep.Verdict == "block" || rep.Level == "high"):
			state, riskLv = "risk-high", "high"
		case hasRep && (rep.Level == "medium" || rep.Score > 0):
			state, riskLv = "risk-low", "low"
		default:
			continue // 状态正常且终端合规（或无报告）：不是"受关注用户"
		}
		if hasRep {
			reasons = append(reasons, rep.Reasons...)
			lastEvent = fmt.Sprintf("终端环境上报（评分 %d · %s）", rep.Score, rep.Device)
			lastSeen = humanAgo(now - rep.TS)
		}
		items = append(items, UserStateItem{
			ID: u.ID, User: u.Name, Account: u.Account, Org: u.Org, State: state, Risk: riskLv,
			Online: hasRep && now-rep.TS <= 600, Reasons: reasons, LastEvent: lastEvent, LastSeen: lastSeen,
		})
	}
	count := func(states ...string) int {
		n := 0
		for _, it := range items {
			for _, st := range states {
				if it.State == st {
					n++
				}
			}
		}
		return n
	}
	buckets := []UserStateBucket{
		{Key: "risk-high", Label: "高风险用户", Count: count("risk-high"), Tone: "danger"},
		{Key: "risk-low", Label: "关注用户", Count: count("risk-low"), Tone: "warning"},
		{Key: "locked", Label: "锁定账号", Count: count("locked"), Tone: "danger"},
		{Key: "disabled", Label: "禁用账号", Count: count("disabled"), Tone: "info"},
		{Key: "idle", Label: "空闲挂起", Count: 0, Tone: "normal"},
	}
	return UserStateBundle{Buckets: buckets, Items: items}, nil
}

// humanAgo 粗粒度"多久之前"。
func humanAgo(sec int64) string {
	switch {
	case sec < 60:
		return "刚刚"
	case sec < 3600:
		return fmt.Sprintf("%d 分钟前", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%d 小时前", sec/3600)
	default:
		return fmt.Sprintf("%d 天前", sec/86400)
	}
}
