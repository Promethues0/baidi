package store

import "context"

// Overview 覆盖：在 Memory 种子（设备拓扑/三道防线骨架等暂无真实来源的字段）之上，
// 用真实数据重算可计算的部分——用户统计（users 表）、审计分类/判定/威胁（audit_log），
// 以及账号防线的真实高危 TOP。设备数/在线会话数没有真实库存来源，会话数由 api 层用
// 网关上报的真实会话再行注入（见 handleOverview）。
func (s *SQLiteStore) Overview(ctx context.Context) (Overview, error) {
	ov, err := s.Memory.Overview(ctx)
	if err != nil {
		return Overview{}, err
	}

	// 1) 用户统计：真实 users 表
	if b, err := s.Users(ctx); err == nil {
		var total, disabled, locked int
		var highRisk []string
		for _, u := range b.Users {
			total++
			switch u.Status {
			case "disabled":
				disabled++
			case "locked":
				locked++
			}
			if u.Risk == "high" && len(highRisk) < 3 {
				highRisk = append(highRisk, u.Account)
			}
		}
		ov.Users = UserStat{Total: total, Disabled: disabled, Locked: locked}
		// 账号防线 TOP 用真实高危账号（有则替换种子）
		if len(highRisk) > 0 {
			for i := range ov.Defense {
				if ov.Defense[i].Key == "account" {
					ov.Defense[i].Top = highRisk
					ov.Defense[i].Risk = riskScore(locked+disabled, len(highRisk))
				}
			}
		}
	}

	// 2) 审计分类 / 判定 / 威胁：真实 audit_log 聚合
	byCat, byVerdict, err := s.auditAggregates(ctx)
	if err != nil {
		return ov, err
	}
	ov.AuditByKind = []KV{
		{Name: "访问决策", Value: byCat["access"]},
		{Name: "登录认证", Value: byCat["auth"]},
		{Name: "策略变更", Value: byCat["policy"] + byCat["admin"]},
		{Name: "安全事件", Value: byCat["security"]},
	}
	ov.Verdicts = []KV{
		{Name: "允许", Value: byVerdict["allow"] + byVerdict["ok"]},
		{Name: "二次鉴权", Value: byVerdict["mfa"]},
		{Name: "拒绝", Value: byVerdict["deny"]},
		{Name: "失败", Value: byVerdict["fail"]},
	}
	ov.Threats = ThreatStat{
		Rejected:  byVerdict["deny"],
		Failed:    byVerdict["fail"],
		Secondary: byVerdict["mfa"],
	}

	// 3) posture 高危并入账号防线 TOP（风险引擎判定 block/high 的账号），终端防线由最差报告真实化。
	if reports, err := s.PostureReports(ctx); err == nil && len(reports) > 0 {
		rank := map[string]int{"allow": 0, "degrade": 1, "gray": 2, "block": 3}
		worstUser := map[string]PostureReport{}
		for _, r := range reports {
			w, ok := worstUser[r.User]
			if !ok || rank[r.Verdict] > rank[w.Verdict] {
				worstUser[r.User] = r
			}
		}
		var epTop []string
		epRisk := 0
		for _, r := range worstUser {
			if (r.Verdict == "block" || r.Level == "high") && len(epTop) < 3 {
				epTop = append(epTop, r.User)
			}
			if r.Score > epRisk {
				epRisk = r.Score
			}
		}
		for i := range ov.Defense {
			if ov.Defense[i].Key == "endpoint" {
				ov.Defense[i].Risk = epRisk
				if len(epTop) > 0 {
					ov.Defense[i].Top = epTop
				}
			}
			if ov.Defense[i].Key == "account" && len(epTop) > 0 {
				// posture 高危账号补入账号防线 TOP（去重，cap 3）
				seen := map[string]bool{}
				for _, a := range ov.Defense[i].Top {
					seen[a] = true
				}
				for _, a := range epTop {
					if !seen[a] && len(ov.Defense[i].Top) < 3 {
						ov.Defense[i].Top = append(ov.Defense[i].Top, a)
						seen[a] = true
					}
				}
			}
		}
	}
	return ov, nil
}

// auditAggregates 返回 audit_log 按 category 与 verdict 的全表计数。
func (s *SQLiteStore) auditAggregates(ctx context.Context) (byCat, byVerdict map[string]int, err error) {
	byCat, byVerdict = map[string]int{}, map[string]int{}
	if err = scanCounts(ctx, s, `SELECT category, COUNT(*) FROM audit_log GROUP BY category`, byCat); err != nil {
		return
	}
	err = scanCounts(ctx, s, `SELECT verdict, COUNT(*) FROM audit_log GROUP BY verdict`, byVerdict)
	return
}

func scanCounts(ctx context.Context, s *SQLiteStore, q string, into map[string]int) error {
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		into[k] = n
	}
	return rows.Err()
}

// riskScore 由锁定/禁用账号数与高危账号数粗算账号防线风险分（0-100，单调、可解释）。
func riskScore(blocked, high int) int {
	score := blocked*6 + high*12
	if score > 100 {
		score = 100
	}
	return score
}
