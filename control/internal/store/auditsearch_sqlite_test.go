package store

import (
	"context"
	"testing"
)

// 检索的每个维度都要两向断言：命中该来的 + 不带进不该来的。
func TestSearchAudit(t *testing.T) {
	st := openAuditStore(t)
	ctx := context.Background()
	mustRecord(t, st, "2026-08-01 09:00:00", "auth", "srch.zhang", "172.30.1.31", "登录成功", "ok")
	mustRecord(t, st, "2026-08-02 09:00:00", "auth", "srch.lifang", "172.30.1.12", "登录失败", "fail")
	mustRecord(t, st, "2026-08-03 09:00:00", "admin", "srch.zhang", "10.0.0.9", "修改策略「东区%特批」", "ok")
	mustRecord(t, st, "2026-08-04 09:00:00", "access", "srch.wangwu", "192.168.1.5", "访问 财务系统", "deny")

	// 按账号精确（规范化）：ZHANG.WEI 也要命中，li 不能把 li.fang 带出来。
	logs, total, err := st.SearchAudit(ctx, AuditQuery{Actor: " SRCH.ZHANG "})
	if err != nil || total != 2 || len(logs) != 2 {
		t.Fatalf("按账号应恰 2 条，实得 total=%d err=%v", total, err)
	}
	if _, total, _ := st.SearchAudit(ctx, AuditQuery{Actor: "srch"}); total != 0 {
		t.Errorf("账号是精确匹配，'srch' 不该命中 srch.lifang（模糊会把证据链查串），实得 %d", total)
	}

	// 源 IP 前缀：10.8. 命中两条，192.168.1.5 精确一条。
	if _, total, _ := st.SearchAudit(ctx, AuditQuery{SrcIP: "172.30.1."}); total != 2 {
		t.Errorf("IP 前缀 172.30.1. 应 2 条，实得 %d", total)
	}

	// 关键词含 LIKE 通配符：字面 % 必须被转义，否则「东区%特批」查不准。
	if _, total, _ := st.SearchAudit(ctx, AuditQuery{Keyword: "东区%特批"}); total != 1 {
		t.Errorf("含字面 %% 的关键词应恰 1 条（通配符要转义），实得 %d", total)
	}

	// 时间窗含当日两端。
	if _, total, _ := st.SearchAudit(ctx, AuditQuery{From: "2026-08-02", To: "2026-08-03"}); total != 2 {
		t.Errorf("时间窗 [08-02,08-03] 应 2 条（含两端当日），实得 %d", total)
	}

	// 分页：total 不随页移动（total 与行同一组 WHERE）。
	p1, total1, _ := st.SearchAudit(ctx, AuditQuery{Actor: "srch.zhang", Limit: 1, Offset: 0})
	p2, total2, _ := st.SearchAudit(ctx, AuditQuery{Actor: "srch.zhang", Limit: 1, Offset: 1})
	if total1 != 2 || total2 != 2 || len(p1) != 1 || len(p2) != 1 || p1[0].Time == p2[0].Time {
		t.Errorf("分页失真：t1=%d t2=%d p1=%v p2=%v", total1, total2, p1, p2)
	}
}
