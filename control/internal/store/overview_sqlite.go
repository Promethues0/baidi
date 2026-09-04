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
func (s *SQLiteStore) Overview(ctx context.Context, windowHours int) (Overview, error) {
	windowHours = ClampOverviewWindow(windowHours)
	ov := Overview{
		GeneratedAt: time.Now().Format(time.RFC3339),
		WindowHours: windowHours,
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
		if u.Risk == "high" && len(highRisk) < OverviewTopN {
			highRisk = append(highRisk, u.Account)
		}
	}

	// 3) 审计分类 / 判定 / 威胁：真实 audit_log 聚合
	byCat, byVerdict, err := s.auditAggregates(ctx, windowHours)
	if err != nil {
		return Overview{}, err
	}
	// ★与审计中心同一份字典（AuditCategories）。
	//   此前这里把 policy+admin 并成一格「策略变更」，并且完全不含 dataplane/system：
	//   于是同一个词在两个页面上指的不是同一批记录（总览的「策略变更」含管理操作，
	//   审计中心的「管理操作」又是另一格），而数据面回执在总览上根本不存在。
	//   两处同源之后，两个页面的类别分布可以逐格对得上。
	ov.AuditByKind = make([]KV, 0, len(AuditCategories))
	for _, c := range AuditCategories {
		ov.AuditByKind = append(ov.AuditByKind, KV{Name: c.Label, Value: byCat[c.Key]})
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
		if !seen[a] && len(acctTop) < OverviewTopN {
			acctTop = append(acctTop, a)
			seen[a] = true
		}
	}

	// 5) 攻击源统计（wave7 行动 5）：数据面拒绝事件的聚合，**与审计派生统计同一个窗口**。
	//    此前这里写死 24——于是同一屏上两个数字口径不同且都不标（wave8 行动 9 修）。
	// 第一格防线从「设备台账顶包」换成它——SPA 隐身在挡谁，这里是唯一能回答的地方。
	atk, err := s.AttackStats(ctx, windowHours)
	if err != nil {
		return Overview{}, err
	}
	ov.Attack = &atk
	atkTop := []string{}
	for _, t := range atk.Top {
		if len(atkTop) >= OverviewTopN {
			break
		}
		atkTop = append(atkTop, fmt.Sprintf("%s · %s ×%d", t.IP, t.Cat, t.Count))
	}
	_ = devTop // 设备台账 TOP 不再上第一格防线（台账数字仍在 ov.Devices）

	// ★三条防线的口径**不一样**，必须逐条标出来（Scope）：
	// 只有隐身防线真按时间窗算；账号防线读 users 表的当前状态（"锁定/禁用"是此刻的
	// 属性，不是"这段时间内发生过几次"）；终端防线读 posture_reports 的最新一份
	// （每个 (账号,设备) 只存一行，压根没有历史）。时间选择器对后两条不生效——
	// 不标的话，切到「近 7 天」看到的是当前状态，却以为那是七天内的情况。
	ov.Defense = []DefenseLine{
		// 隐身防线：窗口内被网关拒之门外的来源（敲门/隧道/L7 三个面）。
		// 风险分口径：来源数是主信号（多来源=面上有扫描），总量是次信号。
		{Key: "attack", Name: "隐身防线", Risk: riskScore(atk.Sources, atk.Denies/50), Top: atkTop,
			Scope: ScopeWindow, Note: "按所选时间窗聚合数据面拒绝事件（attack_sources 小时桶）"},
		{Key: "account", Name: "账号防线", Risk: riskScore(ov.Users.Locked+ov.Users.Disabled, len(highRisk)), Top: acctTop,
			Scope: ScopeCurrent, Note: "当前状态：此刻处于锁定/禁用的账号数，与所选时间窗无关"},
		// 终端防线的分值直接用最差 posture 报告的真实分（不再二次加工）。
		{Key: "endpoint", Name: "终端防线", Risk: epRisk, Top: epTop,
			Scope: ScopeCurrent, Note: "当前状态：posture_reports 每个 (账号,设备) 只存最新一份，" +
				"没有历史可回溯，与所选时间窗无关"},
	}
	ov.WindowNote, ov.Truncated = s.overviewWindowNote(windowHours)
	return ov, nil
}

// overviewWindowNote 口径说明 + 是否被审计留存期截断。
//
// ★留存期短于所选窗口时，审计派生的数只能回溯到留存期为止。不说的话，
// 选「近 30 天」而留存 7 天，看到的是 7 天的数却以为是 30 天的——
// 与「设备状态时间窗按 metricsRetentionHours 截断」同一条纪律。
func (s *SQLiteStore) overviewWindowNote(windowHours int) (string, bool) {
	base := fmt.Sprintf("审计派生统计（访问决策/判定分布/威胁事件/攻击源）按最近 %s聚合；"+
		"设备与用户台账、账号与终端两条防线是当前状态，与时间窗无关", humanWindow(windowHours))
	retainH := s.auditRetainDays * 24
	if s.auditRetainDays > 0 && retainH < windowHours {
		return base + fmt.Sprintf("。★审计留存期只有 %d 天，本窗口内早于留存期的记录已被轮转清理，"+
			"实际只覆盖最近 %d 天", s.auditRetainDays, s.auditRetainDays), true
	}
	return base, false
}

// humanWindow 时间窗的人话形式。
//
// ★措辞必须与页面上的时间选择器逐字一致（「24 小时 / 7 天 / 30 天」）：
// 口径说明里冒出「1 周」或「1 天」，会让人以为那是**另一个**窗口。
// 同一件事只能有一个名字——不满 48 小时说小时，其余整天说天。
func humanWindow(h int) string {
	if h >= 48 && h%24 == 0 {
		return fmt.Sprintf("%d 天", h/24)
	}
	return fmt.Sprintf("%d 小时", h)
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
		 WHERE status<>? ORDER BY last_seen DESC, id LIMIT 5`, DeviceStatusTrusted)
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
		if (r.Verdict == DisposalBlock || r.Level == "high") && len(top) < OverviewTopN {
			top = append(top, r.User)
		}
		if r.Score > risk {
			risk = r.Score
		}
	}
	return top, risk, nil
}

// auditAggregates 返回 audit_log 在 windowHours 窗口内按 category 与 verdict 的计数。
//
// ★此前这两条 SQL **一个 WHERE 都没有**，是建库以来的累计，却与严格 24h 的攻击源
// 并排显示在标着「实时判定态势」的同一屏上。而且 BAIDI_AUDIT_RETENTION_DAYS
// 轮转一到期，那个"累计"还会无缘由地往下掉——看的人无从知道是威胁少了还是日志被清了。
func (s *SQLiteStore) auditAggregates(ctx context.Context, windowHours int) (byCat, byVerdict map[string]int, err error) {
	byCat, byVerdict = map[string]int{}, map[string]int{}
	cutoff := time.Now().Add(-time.Duration(windowHours) * time.Hour).Format("2006-01-02 15:04:05")
	if err = scanCounts(ctx, s, auditWindowGroupSQL("category"), byCat, cutoff); err != nil {
		return
	}
	err = scanCounts(ctx, s, auditWindowGroupSQL("verdict"), byVerdict, cutoff)
	return
}

// auditWindowGroupSQL 「时间窗内按某一列分组计数」的语句（col 只由代码常量传入，
// 不接受外部输入）。抽出来是为了让 EQP 守卫（audit_index_test.go）测的就是
// **生产在跑的这一条**——这两条查询正是 idx_audit_log_ts 最主要的受益方，
// 也是「谁再给 category 建一条索引就会整条退化到 1.5s」的那两条。
func auditWindowGroupSQL(col string) string {
	return `SELECT ` + col + `, COUNT(*) FROM audit_log WHERE ts >= ? GROUP BY ` + col
}

func scanCounts(ctx context.Context, s *SQLiteStore, q string, into map[string]int, args ...any) error {
	rows, err := s.db.QueryContext(ctx, q, args...)
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
