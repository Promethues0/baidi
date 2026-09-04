package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// UserStates 覆盖：真实 users 表 × posture 判定（脱种子）。
//
// state 优先级 disabled > locked > 风险处置档（block > degrade > gray）。
// ★档位口径与风险引擎的处置四档统一：这一页显示的 block/degrade/gray 就是
// `risk.Verdict.Disposal` 的原值，也正是网关策略与客户端剖面**当前正在执行**的那一档
// （degrade 已摘掉高敏资源、gray 每轮下发都在记 observing 审计）。此前这里是另一套
// 名字（risk-high/risk-low），和真正被执行的处置没有映射关系——管理员看得到"高风险"，
// 却看不出这个人此刻到底被怎么处置了。
//
// 处置为 allow 的账号**不进清单**（哪怕评分非零）：既然没有任何收缩在执行，它就不是
// "受关注用户"。评分与失败项仍可在安全中心「终端合规」页逐设备查看，信息没有丢。
func (s *SQLiteStore) UserStates(ctx context.Context) (UserStateBundle, error) {
	ub, err := s.Users(ctx)
	if err != nil {
		return UserStateBundle{}, err
	}
	reports, err := s.PostureReports(ctx)
	if err != nil {
		return UserStateBundle{}, err
	}
	worst := map[string]PostureReport{}
	for _, r := range reports {
		w, ok := worst[r.User]
		rr, rw := DisposalRank(r.Verdict), DisposalRank(w.Verdict)
		if !ok || rr > rw || (rr == rw && r.TS > w.TS) {
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
		case hasRep && rep.Verdict == DisposalBlock:
			state, riskLv = DisposalBlock, "high"
		case hasRep && rep.Verdict == DisposalDegrade:
			state, riskLv = DisposalDegrade, "high"
		case hasRep && rep.Verdict == DisposalGray:
			state, riskLv = DisposalGray, "low"
		default:
			continue // 状态正常且处置为 allow（或无报告）：没有任何收缩在执行，不是"受关注用户"
		}
		if hasRep {
			reasons = append(reasons, rep.Reasons...)
			lastEvent = fmt.Sprintf("终端环境上报（评分 %d · %s）", rep.Score, rep.Device)
			lastSeen = humanAgo(now - rep.TS)
		}
		items = append(items, UserStateItem{
			ID: u.ID, User: u.Name, Account: u.Account, Org: u.Org, State: state, Risk: riskLv,
			// ★Online 这里**不填**（留 nil = 不可判定），由 api.handleUserState 按
			// 网关上报的真实会话现算。原先填的是 `hasRep && now-rep.TS <= 600`——
			// 那是"采集器十分钟内还活着"，不是"此刻连着隧道"，两个意思在这一页上
			// 并排出现过（挂着客户端上报 posture 的人在这页是绿点，在线用户页里查无此人）。
			Reasons: reasons, LastEvent: lastEvent, LastSeen: lastSeen,
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
	return UserStateBundle{Buckets: userStateBuckets(count), Items: items}, nil
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
