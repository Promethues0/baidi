package store

// 运营报表：每个数字都必须能指回 audit_log/alerts 里具体的行。
// 种子会灌 8 条审计（时间为当下），所以断言一律落在**回填的历史日期**上，
// 或对今天的数字只做增量/下界断言——与 audit_sqlite_test 同一条约定。

import (
	"context"
	"testing"
	"time"
)

func day(offset int) string { return time.Now().AddDate(0, 0, offset).Format("2006-01-02") }

func TestOpsReportAggregatesRealRows(t *testing.T) {
	st := openAuditStore(t)
	ctx := context.Background()

	d2 := day(-2) // 前天：可控的一天，种子污染不到
	mustRecord(t, st, d2+" 09:00:00", "auth", "zhang.wei", "10.0.0.1", "登录成功", "ok")
	mustRecord(t, st, d2+" 09:05:00", "auth", "zhang.wei", "10.0.0.1", "登录成功", "ok")
	mustRecord(t, st, d2+" 09:10:00", "auth", "li.fang", "10.0.0.2", "登录成功", "ok")
	mustRecord(t, st, d2+" 09:15:00", "auth", "wang.wu", "10.0.0.3", "口令错误", "fail")
	mustRecord(t, st, d2+" 10:00:00", "access", "zhang.wei", "10.0.0.1", "访问 OA", "allow")
	mustRecord(t, st, d2+" 10:05:00", "access", "wang.wu", "10.0.0.3", "越权访问财务", "deny")
	mustRecord(t, st, d2+" 11:00:00", "admin", "admin", "10.0.0.9", "修改策略", "ok")
	mustRecord(t, st, d2+" 11:30:00", "system", "admin", "10.0.0.9", "修改升级规则", "ok")
	mustRecord(t, st, d2+" 12:00:00", "security", "system", "—", "爆破锁定", "fail")
	// mfa 判定：不进 ok/fail 两栏，但必须进当日 Total——少了它,"合计=各栏之和"的
	// 假实现也能过上面的断言。
	mustRecord(t, st, d2+" 12:30:00", "auth", "zhao.liu", "10.0.0.4", "触发二次认证", "mfa")

	rep, err := st.OpsReport(ctx, 7)
	if err != nil {
		t.Fatalf("OpsReport: %v", err)
	}
	if rep.Days != 7 || len(rep.Daily) != 7 {
		t.Fatalf("7 天窗口应回 7 行（零日补全），实得 days=%d rows=%d", rep.Days, len(rep.Daily))
	}
	var got *OpsDay
	for i := range rep.Daily {
		if rep.Daily[i].Date == d2 {
			got = &rep.Daily[i]
		}
	}
	if got == nil {
		t.Fatalf("日桶里找不到 %s：%v", d2, rep.Daily)
	}
	if got.AuthOK != 3 || got.AuthFail != 1 {
		t.Errorf("认证成/败应为 3/1，实得 %d/%d", got.AuthOK, got.AuthFail)
	}
	if got.AccessAllow != 1 || got.AccessDeny != 1 {
		t.Errorf("访问放行/拒绝应为 1/1，实得 %d/%d", got.AccessAllow, got.AccessDeny)
	}
	if got.AdminOps != 2 {
		t.Errorf("管理操作应含 admin+system 两类共 2 条，实得 %d", got.AdminOps)
	}
	if got.Security != 1 {
		t.Errorf("安全事件应为 1，实得 %d", got.Security)
	}
	if got.Total != 10 {
		t.Errorf("当日全量应为 10（含 mfa 那条），实得 %d", got.Total)
	}

	// 活跃账号：zhang.wei / li.fang（成功登录）；wang.wu 只有失败、zhao.liu 只有 mfa，都不算。
	if rep.Totals.ActiveAccounts < 2 {
		t.Errorf("活跃账号应 ≥2，实得 %d", rep.Totals.ActiveAccounts)
	}
	// 榜单：zhang.wei 2 次成功登录应在 TopLogin 里且计数正确。
	found := false
	for _, kv := range rep.TopLogin {
		if kv.Name == "zhang.wei" && kv.Value == 2 {
			found = true
		}
	}
	if !found {
		t.Errorf("TopLogin 应含 zhang.wei=2，实得 %v", rep.TopLogin)
	}
	// 合计与日桶必须自洽（合计就是从日桶累加的，这条钉住将来有人改成独立 SQL）。
	sum := 0
	for _, d := range rep.Daily {
		sum += d.Total
	}
	if sum != rep.Totals.Entries {
		t.Errorf("合计 %d ≠ 各日之和 %d", rep.Totals.Entries, sum)
	}
	// 告警段：没有告警时三档全 0 而不是缺项（前端按固定三档渲染）。
	if len(rep.Alerts.BySeverity) != 3 {
		t.Errorf("severity 应固定三档，实得 %v", rep.Alerts.BySeverity)
	}
}

// 窗口外的行绝不能混进来——这条防的是 since 过滤写成 substr 比较错位之类的静默错。
func TestOpsReportWindowExcludesOldRows(t *testing.T) {
	st := openAuditStore(t)
	old := day(-40)
	mustRecord(t, st, old+" 09:00:00", "auth", "ancient.user", "10.0.0.1", "登录成功", "ok")

	rep, err := st.OpsReport(context.Background(), 7)
	if err != nil {
		t.Fatalf("OpsReport: %v", err)
	}
	for _, kv := range rep.TopLogin {
		if kv.Name == "ancient.user" {
			t.Fatalf("40 天前的行进了 7 天窗口：%v", rep.TopLogin)
		}
	}
	for _, d := range rep.Daily {
		if d.Date == old {
			t.Fatalf("日桶里出现窗口外日期 %s", old)
		}
	}
}

// 留存截断：窗口比留存长时必须缩窗并标记，绝不为已清理的日子补 0。
func TestOpsReportTruncatesToRetention(t *testing.T) {
	st := openAuditStore(t)
	st.SetAuditRetentionDays(10)

	rep, err := st.OpsReport(context.Background(), 30)
	if err != nil {
		t.Fatalf("OpsReport: %v", err)
	}
	if !rep.Truncated || rep.Days != 10 || len(rep.Daily) != 10 {
		t.Fatalf("留存 10 天时 30 天请求应截成 10 并标 truncated，实得 days=%d truncated=%v rows=%d",
			rep.Days, rep.Truncated, len(rep.Daily))
	}
}
