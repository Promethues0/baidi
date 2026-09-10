package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
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
//   - Defense  → 隐身线取 attack_sources、账号线取 users + posture（**按账号**）、
//     终端线取 posture（**按 (账号,设备指纹)**）
//
// 数据源为空时给出的是 0 与空列表——那是"确实没有"，不是"暂时先显示个数"。
// **唯一的例外是 DefenseLine.Risk**：它三态，nil 表示"这条防线一份判定材料都没有"。
// 空列表能自解释（"没有风险实体"），而一个 0 分不能——它会被渲染成绿色的「良好」。
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
	dev, err := s.deviceStat(ctx)
	if err != nil {
		return Overview{}, err
	}
	ov.Devices = dev

	// 2) 用户统计：真实 users 表
	b, err := s.Users(ctx)
	if err != nil {
		return Overview{}, err
	}
	for _, u := range b.Users {
		ov.Users.Total++
		switch u.Status {
		case "disabled":
			ov.Users.Disabled++
		case "locked":
			ov.Users.Locked++
		}
		// ★这里曾经还有一句 `if u.Risk == "high" { highRisk = append(...) }`。
		// users.risk 那一列全仓**只有 INSERT、没有一处 UPDATE**（建号那一刻写下的死值，
		// 种子里 li.fang / ext.zhou 恒为 high），wave9 已因此把用户目录页的这一列改成现算，
		// 安全概览这一半没跟上——同一个账号在两页上给出相反的结论，而概览这页
		// 正是管理员用来决定"今天该盯谁"的入口。现在两页同源，见 accountDefense。
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

	// 4) posture：账号防线与终端防线的判定材料。一次扫描出两条线要的东西——
	//    **两条线的聚合单位刻意不同**（账号 vs (账号,设备指纹)），这正是改造前
	//    两张卡显示同一批账号名的根因。
	dg, err := s.postureDigest(ctx)
	if err != nil {
		return Overview{}, err
	}
	acct := accountDefense(b.Users, dg, ov.Users.Locked+ov.Users.Disabled)
	orphanDevices, err := s.devicesWithoutVerdict(ctx)
	if err != nil {
		return Overview{}, err
	}
	ep := endpointDefense(dg, orphanDevices)

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

	// ★三条防线的口径**不一样**，必须逐条标出来（Scope）：
	// 只有隐身防线真按时间窗算；账号防线读 users 表的当前状态（"锁定/禁用"是此刻的
	// 属性，不是"这段时间内发生过几次"）；终端防线读 posture_reports 的最新一份
	// （每个 (账号,设备) 只存一行，压根没有历史）。时间选择器对后两条不生效——
	// 不标的话，切到「近 7 天」看到的是当前状态，却以为那是七天内的情况。
	ov.Defense = []DefenseLine{
		// 隐身防线：窗口内被网关拒之门外的来源（敲门/隧道/L7 三个面）。
		// 风险分口径：来源数是主信号（多来源=面上有扫描），总量是次信号。
		// Unknown 恒 0：攻击源是"发生过什么"的记账，没有"不可判定"这一档。
		{Key: "attack", Name: "隐身防线", Risk: intp(riskScore(atk.Sources, atk.Denies/50)), Top: atkTop,
			Scope: ScopeWindow, Note: "按所选时间窗聚合数据面拒绝事件（attack_sources 小时桶）"},
		// 账号防线：**账号**维度。锁定/禁用取自 users 当前状态，风险账号由
		// store.RiskOfDisposal 现算（与「用户与角色」页同源），从未上报过终端环境的
		// 单列成 Unknown 而不计进分子——不列出来的话，"高危 0"会被读成"全体健康"。
		{Key: "account", Name: "账号防线", Risk: acct.risk, Top: acct.top,
			Unknown: acct.unknown, Scope: ScopeCurrent, Note: acct.note},
		// 终端防线：**(账号,设备指纹)** 维度，一行一台机器。分值直接用最差
		// posture 报告的真实分（不再二次加工）；一份上报都没有时 Risk 缺席。
		{Key: "endpoint", Name: "终端防线", Risk: ep.risk, Top: ep.top, Unknown: ep.unknown,
			Scope: ScopeCurrent, Note: ep.note},
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

// deviceStat 授信终端台账统计（trusted_devices 真实计数）。
//
// ★曾经还回一份「设备防线 TOP」，在第一格防线换成攻击源之后就没有消费方了
// （调用处一行 `_ = devTop` 兜着）。留着的话下一个人会以为它还在页面上，
// 而它只是每次总览多跑一条 LIMIT 5 的查询。设备维度的风险实体现在由
// 终端防线按 (账号,指纹) 给出，见 endpointDefense。
func (s *SQLiteStore) deviceStat(ctx context.Context) (DeviceStat, error) {
	var st DeviceStat
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM trusted_devices GROUP BY status`)
	if err != nil {
		return DeviceStat{}, err
	}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			rows.Close()
			return DeviceStat{}, err
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
		return DeviceStat{}, err
	}
	if st.Total > 0 {
		st.Rate = float64(st.Trusted) / float64(st.Total)
	}
	return st, nil
}

// ── 账号防线 / 终端防线的判定材料（wave11 行动 12）──
//
// ★两条防线的**聚合单位不同**，这是它们该不该并成一张卡的分界：
// 账号防线按账号（一个人多台机器取最差，与降权/撤销名单同口径），
// 终端防线按 (账号, 设备指纹) 一行一台机器。改造前后者返回的也是账号名，
// 于是「风险终端 TOP5」与「风险账号 TOP5」是同一批条目、各起一个名字——
// 看的人以为交叉印证了两次，其实只有一份数据。

// postureDigest 一次扫描出的 posture 判定材料。
//
// ★刻意不走 PostureReports()：那条查询带 ListLimit(500) 上限且**不告诉调用方被截断了**
// （终端合规页显式渲染 truncated，聚合这条路径没有那个出口）。20 台/账号的上限意味着
// 26 个账号就能撑满 500 行，之后总览的两条防线会静默地只统计"最近的那 500 台"。
// 这里只取聚合真正要的七列（不解 checks/reasons 两个 JSON），无上限。
type postureDigest struct {
	// devices 全部设备行（终端防线按它逐台聚合）。
	devices []PostureReport
	// worstByAccount 规范化账号 → 跨设备最差判定。判据与 PostureVerdict 逐字同款
	// （DisposalRank 高者优先，同级取最新），不另抄一份排序表。
	worstByAccount map[string]PostureReport
}

func (s *SQLiteStore) postureDigest(ctx context.Context) (postureDigest, error) {
	dg := postureDigest{worstByAccount: map[string]PostureReport{}}
	rows, err := s.db.QueryContext(ctx,
		`SELECT user,device,platform,os,verdict,score,level,ts FROM posture_reports`)
	if err != nil {
		return postureDigest{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var r PostureReport
		if err := rows.Scan(&r.User, &r.Device, &r.Platform, &r.OS, &r.Verdict, &r.Score, &r.Level, &r.TS); err != nil {
			return postureDigest{}, err
		}
		dg.devices = append(dg.devices, r)
		w, ok := dg.worstByAccount[r.User]
		rr, rw := DisposalRank(r.Verdict), DisposalRank(w.Verdict)
		if !ok || rr > rw || (rr == rw && r.TS > w.TS) {
			dg.worstByAccount[r.User] = r
		}
	}
	return dg, rows.Err()
}

// devicesWithoutVerdict 已登记进台账、却没有任何合规判定的终端数（终端防线的"不可判定"）。
//
// 正常链路上两表按 (账号,指纹) 一一对应（首次 posture 上报即登记、删除时两表同删），
// 所以这个数通常是 0——但它**不能不算**：一旦不是 0，那批机器在终端防线上既不在
// TOP 里、也不进风险分，与"确实合规"完全同形。
func (s *SQLiteStore) devicesWithoutVerdict(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM trusted_devices d
WHERE NOT EXISTS (SELECT 1 FROM posture_reports p WHERE p.user=d.account AND p.device=d.fingerprint)`).Scan(&n)
	return n, err
}

// defenseFacts 一条防线算出来的展示材料。
type defenseFacts struct {
	top     []string
	risk    *int // nil = 不可判定
	unknown int
	note    string
}

// accountDefense 账号防线：**账号**维度的风险实体 + 不可判定计数。
//
// 风险档由 RiskOfDisposal 现算（与「用户与角色」页、在线用户页同一处折算表）——
// 改造前这里读的是 users.risk，那一列全仓只有 INSERT 没有 UPDATE。
//
// ★「从未上报过终端环境」的账号计进 unknown 而**不是**当成无风险：管理台账号本来
// 就不跑客户端，一套刚装好的系统里这个数等于全体账号数。TOP 空着而 unknown 不为零，
// 说的是"没有判定材料"，不是"没有风险"——两句话对应的下一步动作完全相反。
func accountDefense(users []DirUser, dg postureDigest, blocked int) defenseFacts {
	type cand struct {
		account string
		rank    int
		score   int
	}
	var high []cand
	unknown := 0
	for _, u := range users {
		acc := normAccount(u.Account)
		rep, ok := dg.worstByAccount[acc]
		if !ok {
			unknown++
			continue
		}
		switch RiskOfDisposal(rep.Verdict) {
		case SessionRiskHigh:
			high = append(high, cand{account: u.Account, rank: DisposalRank(rep.Verdict), score: rep.Score})
		case SessionRiskUnknown:
			// 认不出的处置值同样是"判不出来"，不能当成 allow（RiskOfDisposal 已定调）。
			unknown++
		}
	}
	// 排序确定性：严厉度 → 分值 → 账号名。少了最后一把钥匙，同分的两个账号会
	// 随 map/查询顺序在两次刷新之间换位，看的人会以为态势变了。
	sort.Slice(high, func(i, j int) bool {
		if high[i].rank != high[j].rank {
			return high[i].rank > high[j].rank
		}
		if high[i].score != high[j].score {
			return high[i].score > high[j].score
		}
		return high[i].account < high[j].account
	})
	top := []string{}
	for _, c := range high {
		if len(top) >= OverviewTopN {
			break
		}
		top = append(top, c.account)
	}
	note := fmt.Sprintf("当前状态：锁定/禁用取自 users 表此刻的状态（%d 个）；风险账号由终端合规"+
		"最新判定现算（block/degrade 计高危，共 %d 个，与「用户与角色」页同源，"+
		"不读建号那天写下的 users.risk）。", blocked, len(high))
	if unknown > 0 {
		note += fmt.Sprintf("另有 %d 个账号从未上报过终端环境（浏览器接入与管理台账号本就不上报），"+
			"其风险不可判定、未计入分值。", unknown)
	}
	// ★分子用 len(high) 而不是 len(top)：TOP 只展示前 OverviewTopN 条，拿被截断的
	// 那个数去算分，20 个高危账号与 5 个会得到同一个分值。
	return defenseFacts{top: top, risk: intp(riskScore(blocked, len(high))), unknown: unknown,
		note: note + "与所选时间窗无关"}
}

// endpointDefense 终端防线：**(账号, 设备指纹)** 维度，一行一台机器。
//
// TOP 条目形如「macOS 15.1 · 指纹 3f2a91b0c4d5… · 已阻断 · li.fang」：平台 + 指纹短码
// 让人一眼看出这是**终端**而不是账号，账号缀在末尾是为了知道该找谁。
// 风险分取所有上报里最高的那一份评分（不二次加工）；**一份上报都没有时 risk 缺席**。
func endpointDefense(dg postureDigest, orphans int) defenseFacts {
	f := defenseFacts{top: []string{}, unknown: orphans}
	if len(dg.devices) > 0 {
		worst := 0
		for _, r := range dg.devices {
			if r.Score > worst {
				worst = r.Score
			}
		}
		f.risk = intp(worst)
	}
	risky := make([]PostureReport, 0, len(dg.devices))
	for _, r := range dg.devices {
		// 判据与账号防线同源（RiskOfDisposal=high 即 block/degrade），另收 level=high：
		// 那是风险引擎给出的分档，与处置档不是同一维（observe 下高分也可能只判 gray）。
		if RiskOfDisposal(r.Verdict) == SessionRiskHigh || r.Level == "high" {
			risky = append(risky, r)
		}
	}
	sort.Slice(risky, func(i, j int) bool {
		ri, rj := DisposalRank(risky[i].Verdict), DisposalRank(risky[j].Verdict)
		if ri != rj {
			return ri > rj
		}
		if risky[i].Score != risky[j].Score {
			return risky[i].Score > risky[j].Score
		}
		if risky[i].User != risky[j].User {
			return risky[i].User < risky[j].User
		}
		return risky[i].Device < risky[j].Device
	})
	for _, r := range risky {
		if len(f.top) >= OverviewTopN {
			break
		}
		f.top = append(f.top, endpointLabel(r))
	}
	if len(dg.devices) == 0 {
		f.note = "不可判定：一台终端都没有上报过环境，风险分显示「—」而不是 0" +
			"（0 分会被读成「没有任何不合规终端」）。"
	} else {
		f.note = fmt.Sprintf("当前状态：按 (账号,设备指纹) 逐台聚合，已上报 %d 台、其中 %d 台判为"+
			"降权或阻断，风险分取全部上报里最高的一份评分。", len(dg.devices), len(risky))
	}
	if orphans > 0 {
		f.note += fmt.Sprintf("另有 %d 台终端登记在授信台账里却没有任何合规判定，不可判定、未计入。", orphans)
	}
	f.note += "posture_reports 每台只存最新一份，没有历史可回溯，与所选时间窗无关"
	return f
}

// endpointLabel 一台终端在 TOP 里的展示形态。
func endpointLabel(r PostureReport) string {
	plat := strings.TrimSpace(r.Platform + " " + r.OS)
	if plat == "" {
		plat = "未知平台"
	}
	return fmt.Sprintf("%s · 指纹 %s · %s · %s", plat, fingerprintBadge(r.Device), DisposalLabel(r.Verdict), r.User)
}

// fingerprintBadge 指纹短码（TOP 行里的展示形态）。
//
// ★截断必须带省略号：不带的话一个 12 位短码看起来就是完整指纹，管理员拿它去
// 授信终端页搜索会一无所获，而页面上没有任何迹象表明这是个前缀
// （同一条纪律见 RADIUS 组值那处——截断会造出一个谁也不认识的名字）。
// 长度沿用 shortFingerprint 一处定义，两边各写一个 12 会在改动时分家。
func fingerprintBadge(fp string) string {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return "未上报"
	}
	if short := shortFingerprint(fp); short != fp {
		return short + "…"
	}
	return fp
}

// intp 取址助手：Risk 是三态指针，只有"算得出来"时才有值。
func intp(v int) *int { return &v }

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
// 账号防线：blocked=锁定+禁用账号数，high=**现算**的高危账号数（见 accountDefense；
//
//	此前这一项是 users.risk 那列死值的计数）。
//
// 隐身防线：blocked=攻击来源数（主信号：多来源=面上有扫描），high=拒绝总量/50（次信号）。
//
// ★注释里原来还有一条「设备防线」的口径——那格防线在第一格换成攻击源时就没了，
// 留着会让人以为还有第三个调用方。终端防线**不走这个函数**：它的分值直接取
// posture 上报里最高的那一份评分，没有二次加工。
func riskScore(blocked, high int) int {
	score := blocked*6 + high*12
	if score > 100 {
		score = 100
	}
	return score
}
