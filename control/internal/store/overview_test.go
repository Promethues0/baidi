package store

import (
	"context"
	"testing"
)

// overview 的用户统计应来自真实 users 表（种子 8 人：含 admin，ext.zhou 禁用、zhao.min 锁定），
// 而非硬编码 312/7/4。
func TestOverviewUsersFromRealTable(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	ov, err := st.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if ov.Users.Total != 8 {
		t.Errorf("Users.Total=%d, want 8（真实种子用户数）", ov.Users.Total)
	}
	if ov.Users.Disabled != 1 {
		t.Errorf("Users.Disabled=%d, want 1（ext.zhou）", ov.Users.Disabled)
	}
	if ov.Users.Locked != 1 {
		t.Errorf("Users.Locked=%d, want 1（zhao.min）", ov.Users.Locked)
	}
}

// 审计分类/判定/威胁应来自真实 audit_log 聚合（与 Audit() 同源），非硬编码常量。
func TestOverviewAuditAggregatesReal(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// 制造已知审计事件：2 拒绝 + 1 失败 + 1 二次鉴权
	for i := 0; i < 2; i++ {
		_ = st.RecordAudit(ctx, AuditEntry{Category: "access", User: "u", Event: "e", Verdict: "deny"})
	}
	_ = st.RecordAudit(ctx, AuditEntry{Category: "auth", User: "u", Event: "e", Verdict: "fail"})
	_ = st.RecordAudit(ctx, AuditEntry{Category: "security", User: "u", Event: "e", Verdict: "mfa"})

	ov, err := st.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if ov.Threats.Rejected < 2 {
		t.Errorf("Threats.Rejected=%d, want >=2（真实 deny 计数）", ov.Threats.Rejected)
	}
	if ov.Threats.Failed < 1 {
		t.Errorf("Threats.Failed=%d, want >=1（真实 fail 计数）", ov.Threats.Failed)
	}
	if ov.Threats.Secondary < 1 {
		t.Errorf("Threats.Secondary=%d, want >=1（真实 mfa 计数）", ov.Threats.Secondary)
	}
	// 判定分布总和应 > 0（真实聚合）
	var verdictSum int
	for _, v := range ov.Verdicts {
		verdictSum += v.Value
	}
	if verdictSum == 0 {
		t.Error("Verdicts 聚合为空，应来自真实 audit_log")
	}
	// 账号防线 TOP 应含真实高危用户（种子 li.fang / ext.zhou 为 high）
	var acct *DefenseLine
	for i := range ov.Defense {
		if ov.Defense[i].Key == "account" {
			acct = &ov.Defense[i]
		}
	}
	if acct == nil || len(acct.Top) == 0 {
		t.Fatal("账号防线应存在且 TOP 非空")
	}
}
