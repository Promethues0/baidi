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

	ov, err := st.Overview(ctx, 0)
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

	ov, err := st.Overview(ctx, 0)
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
	// ★这里原本断言「账号防线 TOP 非空」，理由写的是"种子 li.fang / ext.zhou 为 high"——
	// 而那个 high 是 users.risk 那一列建号时 INSERT 下去的死值（全仓无 UPDATE）。
	// 那条断言把「拿建号那天写的标签当此刻的风险」钉成了预期行为，与 wave10 里
	// zhang.wei 被四条用例钉住是同一族的错。现在正面钉住相反的事实：
	// 一份 posture 上报都没有时，账号防线不许列出任何风险实体。
	acct := defenseOf(t, ov, "account")
	if len(acct.Top) != 0 {
		t.Fatalf("没有任何 posture 上报时账号防线不该有风险实体（种子 users.risk 是死列），实得 %v", acct.Top)
	}
	if acct.Unknown != ov.Users.Total {
		t.Fatalf("全体账号都没上报过终端环境，Unknown 应等于账号总数 %d，实得 %d",
			ov.Users.Total, acct.Unknown)
	}
}

// defenseOf 取某一条防线（找不到直接 Fatal——防线缺席是回归，不是空值）。
func defenseOf(t *testing.T, ov Overview, key string) DefenseLine {
	t.Helper()
	for _, d := range ov.Defense {
		if d.Key == key {
			return d
		}
	}
	t.Fatalf("防线 %q 缺席：%+v", key, ov.Defense)
	return DefenseLine{}
}
