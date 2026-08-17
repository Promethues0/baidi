package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ── wave8 行动 9：态势总览的统计时间窗 ──
//
// 被修的坏形态：同一屏上「威胁事件 N」是**建库以来累计**（auditAggregates 那两条
// SQL 一个 WHERE 都没有），而「攻击源」是**严格 24 小时**，标题却写着「实时判定态势」。
// 两个口径并排显示且一处不标；BAIDI_AUDIT_RETENTION_DAYS 轮转一到期，
// 那个"累计"还会无缘由地往下掉——看的人无从知道是威胁少了还是日志被清了。

// recordAt 在指定时刻落一条审计。
func recordAt(t *testing.T, st *SQLiteStore, at time.Time, verdict string) {
	t.Helper()
	err := st.RecordAudit(context.Background(), AuditEntry{
		Time: at.Format("2006-01-02 15:04:05"), Category: "access",
		User: "u", SrcIP: "1.1.1.1", Event: "e", Verdict: verdict,
	})
	if err != nil {
		t.Fatalf("落审计失败：%v", err)
	}
}

// TestOverviewWindowExcludesOldRows 窗口外的审计不该计进来。
func TestOverviewWindowExcludesOldRows(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now()
	recordAt(t, st, now.Add(-2*time.Hour), "deny")      // 24h 内
	recordAt(t, st, now.Add(-30*24*time.Hour), "deny")  // 30 天前
	recordAt(t, st, now.Add(-100*24*time.Hour), "deny") // 100 天前

	day, err := st.Overview(ctx, 24)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	month, err := st.Overview(ctx, 24*31)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if day.Threats.Rejected >= month.Threats.Rejected {
		t.Fatalf("24h 的拒绝数应严格少于 31 天（窗口没生效？）：24h=%d 31d=%d",
			day.Threats.Rejected, month.Threats.Rejected)
	}
	// 100 天前那条在 31 天窗口里也不该出现。
	all, _ := st.Overview(ctx, MaxOverviewWindowHours)
	if all.Threats.Rejected <= month.Threats.Rejected {
		t.Fatalf("90 天窗口应比 31 天多（100 天前那条本就不该被任何窗口捞到，"+
			"但种子数据也在更早的位置）：31d=%d 90d=%d", month.Threats.Rejected, all.Threats.Rejected)
	}
}

// TestOverviewWindowIsReported 窗口必须随结果下发，否则页面无从标注口径。
func TestOverviewWindowIsReported(t *testing.T) {
	st := openTestStore(t)
	ov, err := st.Overview(context.Background(), 168)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if ov.WindowHours != 168 {
		t.Fatalf("WindowHours 应回 168，得到 %d", ov.WindowHours)
	}
	if !strings.Contains(ov.WindowNote, "7 天") {
		t.Fatalf("口径说明应含人话的窗口长度，得到 %q", ov.WindowNote)
	}
	// ★必须点明"哪些不按窗口算"——否则时间选择器就是个悄悄不生效的筛选。
	if !strings.Contains(ov.WindowNote, "当前状态") {
		t.Fatalf("口径说明必须点明有些数是当前状态，得到 %q", ov.WindowNote)
	}
}

// TestOverviewDefenseScopeLabeled 三条防线各自标出口径。
//
// ★只有隐身防线真按时间窗算；账号防线读 users 表的当前状态，终端防线读
// posture_reports 的最新一份（压根没有历史）。**一个悄悄不生效的筛选比没有筛选更坏**。
func TestOverviewDefenseScopeLabeled(t *testing.T) {
	st := openTestStore(t)
	ov, err := st.Overview(context.Background(), 24)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	want := map[string]string{
		"attack":   ScopeWindow,
		"account":  ScopeCurrent,
		"endpoint": ScopeCurrent,
	}
	if len(ov.Defense) != len(want) {
		t.Fatalf("应有 %d 条防线，得到 %d", len(want), len(ov.Defense))
	}
	for _, d := range ov.Defense {
		w, ok := want[d.Key]
		if !ok {
			t.Errorf("多出一条防线 %q", d.Key)
			continue
		}
		if d.Scope != w {
			t.Errorf("防线 %q 的口径应为 %q，得到 %q", d.Key, w, d.Scope)
		}
		if d.Note == "" {
			t.Errorf("防线 %q 缺口径说明——只标 window/current 而不说为什么，看的人还是不知道该不该信", d.Key)
		}
	}
}

// TestOverviewWindowTruncatedByRetention 窗口超过审计留存期时必须说出来。
//
// ★选「近 30 天」而留存只有 7 天，看到的是 7 天的数却以为是 30 天的——
// 与「设备状态时间窗按 metricsRetentionHours 截断」同一条纪律。
func TestOverviewWindowTruncatedByRetention(t *testing.T) {
	st := openTestStore(t)
	st.SetAuditRetentionDays(7)
	ov, err := st.Overview(context.Background(), 24*30)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if !ov.Truncated {
		t.Fatal("30 天窗口 + 7 天留存必须标为已截断")
	}
	if !strings.Contains(ov.WindowNote, "留存期") {
		t.Fatalf("说明里要点出留存期，得到 %q", ov.WindowNote)
	}
	// 留存期足够长时不该误报。
	st.SetAuditRetentionDays(180)
	ov2, _ := st.Overview(context.Background(), 24*30)
	if ov2.Truncated {
		t.Fatalf("180 天留存 + 30 天窗口不该报截断：%q", ov2.WindowNote)
	}
}

// TestClampOverviewWindow 边界钳制。
func TestClampOverviewWindow(t *testing.T) {
	cases := map[int]int{
		0:      DefaultOverviewWindowHours,
		-5:     DefaultOverviewWindowHours,
		1:      1,
		24:     24,
		100000: MaxOverviewWindowHours,
	}
	for in, want := range cases {
		if got := ClampOverviewWindow(in); got != want {
			t.Errorf("ClampOverviewWindow(%d) = %d，期望 %d", in, got, want)
		}
	}
}

// TestRecordAuditFillsEmptyTime 空时刻要补上服务端当前时间。
//
// ★空 ts 是一种很坏的行：它对**所有按时间窗的查询**不可见（ts >= cutoff 恒假），
// 却会被留存轮转删掉（ts < cutoff 恒真）——查不到但会消失。
// 态势总览按窗口聚合之后，这条路径必须堵上。
func TestRecordAuditFillsEmptyTime(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if err := st.RecordAudit(ctx, AuditEntry{Category: "access", User: "u", Event: "无时刻", Verdict: "deny"}); err != nil {
		t.Fatalf("落审计失败：%v", err)
	}
	var ts string
	if err := st.db.QueryRow(`SELECT ts FROM audit_log WHERE event='无时刻'`).Scan(&ts); err != nil {
		t.Fatalf("查回失败：%v", err)
	}
	if strings.TrimSpace(ts) == "" {
		t.Fatal("空时刻没被补上——这条审计对任何时间窗查询都不可见，却会被留存轮转删掉")
	}
	// 并且要能被 24h 窗口捞到。
	ov, _ := st.Overview(ctx, 24)
	if ov.Threats.Rejected == 0 {
		t.Fatal("补了时刻却还是进不了 24h 窗口")
	}
}

// TestOverviewTopN TOP 放到 5 条。
func TestOverviewTopN(t *testing.T) {
	if OverviewTopN != 5 {
		t.Fatalf("OverviewTopN 应为 5，得到 %d", OverviewTopN)
	}
}

// TestOverviewAttackSharesSameWindow 攻击源与审计派生统计**必须共用同一个窗口**。
//
// ★这正是本行动要消灭的那个缺陷本身：改造前攻击源写死 24h，而审计聚合是全表累计，
// 两个口径并排显示在同一屏上、页面一处不标。只测「审计聚合按窗口」的话，
// 把 AttackStats(ctx, windowHours) 改回 AttackStats(ctx, 24) 用例照样全绿——
// 口径又分家了，而症状与改造前一模一样。
func TestOverviewAttackSharesSameWindow(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now()
	// 一个源在 2 小时前，另一个在 10 天前。
	if err := st.RecordAttack(ctx, "gw-1", "203.0.113.7", "knock-replay", 5,
		now.Add(-2*time.Hour).Unix()); err != nil {
		t.Fatalf("落攻击记录失败：%v", err)
	}
	if err := st.RecordAttack(ctx, "gw-1", "198.51.100.4", "proxy-unauth", 3,
		now.Add(-10*24*time.Hour).Unix()); err != nil {
		t.Fatalf("落攻击记录失败：%v", err)
	}

	day, err := st.Overview(ctx, 24)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	month, err := st.Overview(ctx, 24*30)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if day.Attack == nil || month.Attack == nil {
		t.Fatal("攻击统计缺席")
	}
	if day.Attack.Sources != 1 {
		t.Fatalf("24h 窗口应只看到 1 个攻击源，得到 %d（攻击源没跟着窗口走？）", day.Attack.Sources)
	}
	if month.Attack.Sources != 2 {
		t.Fatalf("30 天窗口应看到 2 个攻击源，得到 %d", month.Attack.Sources)
	}
	// 隐身防线的 TOP 也应随窗口变化（它就是从 Attack.Top 来的）。
	topOf := func(ov Overview) int {
		for _, d := range ov.Defense {
			if d.Key == "attack" {
				return len(d.Top)
			}
		}
		return -1
	}
	if topOf(day) >= topOf(month) {
		t.Fatalf("隐身防线 TOP 应随窗口变化：24h=%d 30d=%d", topOf(day), topOf(month))
	}
}
