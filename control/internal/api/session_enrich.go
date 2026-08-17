package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"baidi.dev/control/internal/store"
)

// ── 在线会话的组织 / 授信态 / 风险档（wave8 行动 5）──
//
// 网关按会话上报的只有 `{IP, User, Role, Since}`。这三格是控制面**按账号**从库里
// 现取的真值，取不到一律 unknown——绝不回落成好值。
//
// ★为什么这条比「补 0」更要紧：补 0 是把不知道说成零；这里此前是把不知道说成
// **「授信 / 无风险」**，即一个正向的安全断言。observe 模式下被放行的未授信终端、
// 被 degrade 降权的账号，在监控中心这一页上全部显示为绿色——而管理员打开这一页
// 的目的恰恰是找出它们。与项目在网关指标（采不到就报不可判定）与 posture
// （unknown 先于 ok 判）上立的纪律方向相反。
//
// ★三格都是**账号级**的：网关的会话上报里没有设备指纹，控制面无从知道是哪台机器
// 建的这条隧道。所以结论旁边必须带依据（TrustNote/RiskNote），让管理员看得出
// 这是"这个账号名下有台机器被吊销了"，而不是"这条会话来自一台被吊销的机器"。

// enrichSessions 就地补齐每条会话的 Org / Trust / Risk（含依据文案）。
//
// 三处取数各自失败互不影响：读不到就是 unknown，不让一次库抖动把整页打空。
func (s *Server) enrichSessions(ctx context.Context, sessions []store.OnlineSession) {
	if len(sessions) == 0 {
		return
	}
	orgOf := s.orgNameByAccount(ctx)
	trustOf := s.deviceTrustByAccount(ctx)
	// 风险档按账号查一次就够：同一个人开三条隧道是常态，逐会话查等于把
	// PostureVerdict 打三遍，而它是个跨设备取最差的聚合查询。
	riskOf := map[string][2]string{}
	for i := range sessions {
		acc := normUser(sessions[i].Account)
		if v := orgOf[acc]; v != "" {
			sessions[i].Org = v
		} else {
			sessions[i].Org = "—" // 真的没归属（外部账号建号时会落 org，本地账号可能没配）
		}
		// ★map 取不到时是零值空串，而空串在前端既不是 trusted 也不是 unknown——
		// 它会让那一格什么都不显示，看起来像"这一列还没做完"。一台设备都没登记过
		// 恰恰是 observe 模式下最常见、也最该被看见的形态，必须显式说成 unknown。
		if t, ok := trustOf[acc]; ok {
			sessions[i].Trust, sessions[i].TrustNote = t.state, t.note
		} else {
			sessions[i].Trust = store.SessionTrustUnknown
			sessions[i].TrustNote = "该账号名下没有任何已登记终端——控制面不知道这条会话来自什么设备" +
				"（observe 准入模式下未登记终端照样能敲门接入）"
		}
		if v, ok := riskOf[acc]; ok {
			sessions[i].Risk, sessions[i].RiskNote = v[0], v[1]
			continue
		}
		risk, note := s.riskOfAccount(ctx, acc)
		riskOf[acc] = [2]string{risk, note}
		sessions[i].Risk, sessions[i].RiskNote = risk, note
	}
}

// orgNameByAccount 账号 → 组织名。读失败回空表（每条会话显示「—」）。
//
// 取的是 DirUser.Org——SQLiteStore.Users 已按 org_units 表把它回填成组织名
// （org/orgKey 是组织表出现前的展示遗物，OrgID 有值时以组织表为准）。
// 这里不再自己遍历一遍组织树：那会造出第二处「怎么把 org_id 翻成名字」的实现。
func (s *Server) orgNameByAccount(ctx context.Context) map[string]string {
	out := map[string]string{}
	b, err := s.store.Users(ctx)
	if err != nil {
		slog.Warn("在线会话补组织失败，本次显示「—」", "err", err.Error())
		return out
	}
	for _, u := range b.Users {
		if n := strings.TrimSpace(u.Org); n != "" {
			out[normUser(u.Account)] = n
		}
	}
	return out
}

// accountTrust 一个账号名下终端的授信结论 + 依据。
type accountTrust struct {
	state string
	note  string
}

// deviceTrustByAccount 账号 → 授信态。
//
// 判据（严厉度从高到低，命中即定）：
//   - 名下有 revoked 设备 → untrusted（吊销是明确的"不许它进"）
//   - 名下有 pending 设备 → untrusted（还没批，approval 模式下本就不该放行）
//   - 名下设备全部 trusted → trusted
//   - **一台都没登记 → unknown**（不是 trusted！这恰恰是 observe 模式下最常见的形态：
//     终端没装客户端 / 没上报过 posture，照样能敲门进来）
func (s *Server) deviceTrustByAccount(ctx context.Context) map[string]accountTrust {
	out := map[string]accountTrust{}
	b, err := s.store.Devices(ctx)
	if err != nil {
		slog.Warn("在线会话补授信态失败，本次一律「不可判定」", "err", err.Error())
		return out
	}
	type tally struct{ trusted, pending, revoked int }
	agg := map[string]*tally{}
	for _, d := range b.Devices {
		acc := normUser(d.Account)
		if agg[acc] == nil {
			agg[acc] = &tally{}
		}
		switch d.Status {
		case store.DeviceStatusTrusted:
			agg[acc].trusted++
		case store.DeviceStatusRevoked:
			agg[acc].revoked++
		default:
			agg[acc].pending++
		}
	}
	for acc, t := range agg {
		total := t.trusted + t.pending + t.revoked
		parts := []string{}
		if t.trusted > 0 {
			parts = append(parts, fmt.Sprintf("%d 台已授信", t.trusted))
		}
		if t.pending > 0 {
			parts = append(parts, fmt.Sprintf("%d 台待审批", t.pending))
		}
		if t.revoked > 0 {
			parts = append(parts, fmt.Sprintf("%d 台已吊销", t.revoked))
		}
		note := fmt.Sprintf("该账号名下 %d 台终端：%s（会话上报里没有设备指纹，无法定位到具体是哪一台）",
			total, strings.Join(parts, " / "))
		state := store.SessionTrustTrusted
		if t.revoked > 0 || t.pending > 0 {
			state = store.SessionTrustUntrusted
		}
		out[acc] = accountTrust{state: state, note: note}
	}
	return out
}

// riskOfAccount 账号的终端合规风险档 + 理由。
//
// 判据用**跨设备最差判定**（store.PostureVerdict），与降权名单、撤销名单、
// 剖面降权提示取的是同一份——这一页要是自己算一套，就会出现「页面说无风险、
// 而这个人的高敏资源已经被摘掉了」。
func (s *Server) riskOfAccount(ctx context.Context, account string) (string, string) {
	rep, ok, err := s.store.PostureVerdict(ctx, account)
	if err != nil {
		return store.SessionRiskUnknown, "终端合规判定读取失败，本次不可判定"
	}
	if !ok {
		// ★这是最常见、也最该被看见的一种：这个账号从来没上报过终端环境，
		// 而 observe 模式下他照样能接入。说成 none 就是替一台完全未知的机器背书。
		return store.SessionRiskUnknown, "该账号从未上报过终端环境（observe 模式下仍可接入）"
	}
	why := strings.Join(rep.Reasons, "、")
	if why == "" {
		why = "无失败项"
	}
	switch rep.Verdict {
	case store.DisposalBlock:
		return store.SessionRiskHigh, "终端合规判定 block（已拒发敲门令牌 / 撤窗断隧道）：" + why
	case store.DisposalDegrade:
		return store.SessionRiskHigh, "终端合规判定 degrade（高敏资源已暂停）：" + why
	case store.DisposalGray:
		return store.SessionRiskLow, "终端合规判定 gray（观察中，访问权未变更）：" + why
	case store.DisposalAllow:
		return store.SessionRiskNone, "终端合规判定 allow：" + why
	}
	return store.SessionRiskUnknown, "终端合规判定取值未知：" + rep.Verdict
}
