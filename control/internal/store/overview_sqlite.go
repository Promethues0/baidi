package store

import (
	"context"
	"fmt"
	"time"
)

// Overview 态势总览：**逐字段由真实数据构造，不以 Memory 种子打底**。
//
// ★这是本轮"种子字段残留"清理的第四例，也是数字最多的一处。原实现开头是
// `ov, err := s.Memory.Overview(ctx)`，然后覆盖用户统计与审计聚合——剩下的
// Devices（186/240）、Sessions（186）、三道防线的风险分与 TOP 实体（"203.0.113.7"、
// "svc-bot-04"、"WIN-诊室-12"）全部原样继承种子，与被覆盖的真实字段并排显示在
// 同一屏 KPI 上，页面上看不出哪个是真的。
//
// 现在每一项的出处：
//   - Devices  → trusted_devices 台账计数（在线不可得，改台账口径，见 DeviceStat）
//   - Users    → users 表
//   - Threats / AuditByKind / Verdicts → audit_log 聚合
//   - Sessions → 恒 0，由 api 层按网关上报注入（库里没有会话这回事）
//   - Defense  → 设备线取台账、账号线取 users + posture、终端线取 posture
//
// 数据源为空时给出的是 0 与空列表——那是"确实没有"，不是"暂时先显示个数"。
func (s *SQLiteStore) Overview(ctx context.Context) (Overview, error) {
	ov := Overview{
		GeneratedAt: time.Now().Format(time.RFC3339),
		AuditByKind: []KV{},
		Verdicts:    []KV{},
		Defense:     []DefenseLine{},
	}

	// 1) 设备台账：真实 trusted_devices
	dev, devTop, err := s.deviceStat(ctx)
	if err != nil {
		return Overview{}, err
	}
	ov.Devices = dev

	// 2) 用户统计：真实 users 表
	b, err := s.Users(ctx)
	if err != nil {
		return Overview{}, err
	}
	var highRisk []string
	for _, u := range b.Users {
		ov.Users.Total++
		switch u.Status {
		case "disabled":
			ov.Users.Disabled++
		case "locked":
			ov.Users.Locked++
		}
		if u.Risk == "high" && len(highRisk) < 3 {
			highRisk = append(highRisk, u.Account)
		}
	}

	// 3) 审计分类 / 判定 / 威胁：真实 audit_log 聚合
	byCat, byVerdict, err := s.auditAggregates(ctx)
	if err != nil {
		return Overview{}, err
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

	// 4) posture：终端防线由最差报告真实化，高危账号并入账号防线 TOP
	epTop, epRisk, err := s.postureDefense(ctx)
	if err != nil {
		return Overview{}, err
	}
	acctTop := append([]string{}, highRisk...)
	seen := map[string]bool{}
	for _, a := range acctTop {
		seen[a] = true
	}
	for _, a := range epTop {
		if !seen[a] && len(acctTop) < 3 {
			acctTop = append(acctTop, a)
			seen[a] = true
		}
	}

	// 5) 攻击源统计（wave7 行动 5）：数据面拒绝事件的 24h 聚合。
	// 第一格防线从「设备台账顶包」换成它——SPA 隐身在挡谁，这里是唯一能回答的地方。
	atk, err := s.AttackStats(ctx, 24)
	if err != nil {
		return Overview{}, err
	}
	ov.Attack = &atk
	atkTop := []string{}
	for _, t := range atk.Top {
		if len(atkTop) >= 3 {
			break
		}
		atkTop = append(atkTop, fmt.Sprintf("%s · %s ×%d", t.IP, t.Cat, t.Count))
	}
	_ = devTop // 设备台账 TOP 不再上第一格防线（台账数字仍在 ov.Devices）

	ov.Defense = []DefenseLine{
		// 隐身防线：24h 内被网关拒之门外的来源（敲门/隧道/L7 三个面）。
		// 风险分口径：来源数是主信号（多来源=面上有扫描），总量是次信号。
		{Key: "attack", Name: "隐身防线", Risk: riskScore(atk.Sources, atk.Denies/50), Top: atkTop},
		{Key: "account", Name: "账号防线", Risk: riskScore(ov.Users.Locked+ov.Users.Disabled, len(highRisk)), Top: acctTop},
		// 终端防线的分值直接用最差 posture 报告的真实分（不再二次加工）。
		{Key: "endpoint", Name: "终端防线", Risk: epRisk, Top: epTop},
	}
	return ov, nil
}

// deviceStat 授信终端台账统计 + 设备防线 TOP。
//
// TOP 取"最近登记/上报过、且状态不是 trusted"的设备，展示成「账号 · 设备名」：
// 这两类（pending 待批、revoked 已吊销）是台账上唯一称得上风险实体的东西，
// 而且点得到、查得着——种子里那三个 203.0.113.x 在库里根本不存在。
func (s *SQLiteStore) deviceStat(ctx context.Context) (DeviceStat, []string, error) {
	var st DeviceStat
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM trusted_devices GROUP BY status`)
	if err != nil {
		return DeviceStat{}, nil, err
	}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return DeviceStat{}, nil, err
		}
		switch status {
		case DeviceStatusTrusted:
			st.Trusted = n
		case DeviceStatusPending:
			st.Pending = n
		case DeviceStatusRevoked:
			st.Revoked = n
		}
		st.Total += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return DeviceStat{}, nil, err
	}
	if st.Total > 0 {
		st.Rate = float64(st.Trusted) / float64(st.Total)
	}

	top := []string{}
	trows, err := s.db.QueryContext(ctx,
		`SELECT account, COALESCE(NULLIF(name,''),fingerprint) FROM trusted_devices
		 WHERE status<>? ORDER BY last_seen DESC, id LIMIT 3`, DeviceStatusTrusted)
	if err != nil {
		return DeviceStat{}, nil, err
	}
	defer trows.Close()
	for trows.Next() {
		var account, name string
		if err := trows.Scan(&account, &name); err != nil {
			return DeviceStat{}, nil, err
		}
		top = append(top, account+" · "+name)
	}
	return st, top, trows.Err()
}

// postureDefense 终端防线：跨设备取每个账号最差的一份 posture 判定。
// 返回 (被判 block/high 的账号 TOP3, 最高风险分)。没有任何报告即空 + 0。
func (s *SQLiteStore) postureDefense(ctx context.Context) ([]string, int, error) {
	reports, err := s.PostureReports(ctx)
	if err != nil {
		return nil, 0, err
	}
	worstUser := map[string]PostureReport{}
	for _, r := range reports {
		w, ok := worstUser[r.User]
		// 排序只认 DisposalRank 那一份表（原先这里抄了第四份，改一处漏三处时
		// "跨设备取最差"在不同页面会给出不同答案）。
		if !ok || DisposalRank(r.Verdict) > DisposalRank(w.Verdict) {
			worstUser[r.User] = r
		}
	}
	top := []string{}
	risk := 0
	for _, r := range worstUser {
		if (r.Verdict == DisposalBlock || r.Level == "high") && len(top) < 3 {
			top = append(top, r.User)
		}
		if r.Score > risk {
			risk = r.Score
		}
	}
	return top, risk, nil
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

// riskScore 由两类真实计数粗算防线风险分（0-100，单调、可解释）。
//
// 账号防线：blocked=锁定+禁用账号数，high=高危账号数。
// 设备防线：blocked=待审批设备数，high=已吊销设备数（吊销权重更高——那是管理员
// 显式说过"不许进"的终端，它还留在台账里就说明还没退役）。
func riskScore(blocked, high int) int {
	score := blocked*6 + high*12
	if score > 100 {
		score = 100
	}
	return score
}
