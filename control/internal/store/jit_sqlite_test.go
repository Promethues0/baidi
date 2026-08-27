package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newReq(user string) AccessRequest {
	return AccessRequest{User: user, ResourceID: "finance", ResourceName: "财务核算系统", Reason: "季度对账", TTLMinutes: 60}
}

// 申请落库 + 规范化：User 小写去空格；同 (账号,资源) 已有 pending → 去重拒；不同资源可并存。
func TestCreateAccessRequestDedup(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r1, err := s.CreateAccessRequest(ctx, newReq("  Bob "))
	if err != nil {
		t.Fatalf("首次申请应成功: %v", err)
	}
	if r1.User != "bob" || r1.Status != "pending" || r1.ID == "" {
		t.Fatalf("落库字段异常: %+v", r1)
	}
	// 规范化匹配读回
	mine, _ := s.AccessRequestsFor(ctx, "BOB")
	if len(mine) != 1 {
		t.Fatalf("我的申请应 1 条: %d", len(mine))
	}
	// 同账号同资源重复申请 → 去重
	if _, err := s.CreateAccessRequest(ctx, newReq("bob")); !errors.Is(err, ErrDuplicateRequest) {
		t.Fatalf("重复申请应 ErrDuplicateRequest: %v", err)
	}
	// 不同资源可并存
	other := newReq("bob")
	other.ResourceID = "git"
	if _, err := s.CreateAccessRequest(ctx, other); err != nil {
		t.Fatalf("不同资源应可申请: %v", err)
	}
}

// 审批通过：同事务建 active 授予 + 回填 grant_id + expires_at=now+ttl；ActiveGrantsFor 可见。
func TestDecideApproveCreatesGrant(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, _ := s.CreateAccessRequest(ctx, newReq("bob"))

	before := time.Now().Unix()
	req, grant, err := s.DecideAccessRequest(ctx, r.ID, "approved", "核准", "admin", 0)
	if err != nil {
		t.Fatalf("审批应成功: %v", err)
	}
	if req.Status != "approved" || req.GrantID != grant.ID || grant.ID == "" {
		t.Fatalf("回填 grant_id 失败: req=%+v grant=%+v", req, grant)
	}
	// ttlOverride=0 → 用申请单原值 60 分钟
	if grant.ExpiresAt < before+60*60 || grant.ExpiresAt > time.Now().Unix()+60*60+5 {
		t.Fatalf("expires_at 应≈now+60min: %d", grant.ExpiresAt)
	}
	act, _ := s.ActiveGrantsFor(ctx, "bob")
	if len(act) != 1 || act[0].ResourceID != "finance" || act[0].Status != "active" {
		t.Fatalf("有效授予应可见: %+v", act)
	}
	// 有 active 授予后，同资源再申请也应被去重拒
	if _, err := s.CreateAccessRequest(ctx, newReq("bob")); !errors.Is(err, ErrDuplicateRequest) {
		t.Fatalf("有有效授予时重复申请应拒: %v", err)
	}
}

// 状态守卫：已处置的申请再次审批 → ErrRequestDecided，不产生第二个授予。
func TestDecideStatusGuard(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, _ := s.CreateAccessRequest(ctx, newReq("bob"))
	if _, _, err := s.DecideAccessRequest(ctx, r.ID, "approved", "ok", "admin", 30); err != nil {
		t.Fatalf("首次审批应成功: %v", err)
	}
	if _, _, err := s.DecideAccessRequest(ctx, r.ID, "approved", "again", "admin", 30); !errors.Is(err, ErrRequestDecided) {
		t.Fatalf("重复审批应 ErrRequestDecided: %v", err)
	}
	all, _ := s.JitGrants(ctx)
	if len(all) != 1 {
		t.Fatalf("不应重复建授予，应仅 1 条: %d", len(all))
	}
}

// 职责分离：审批人==申请人 → ErrSelfApprove（防自申请自批准）。
func TestDecideSelfApproveRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, _ := s.CreateAccessRequest(ctx, newReq("alice"))
	if _, _, err := s.DecideAccessRequest(ctx, r.ID, "approved", "自批", "  Alice ", 0); !errors.Is(err, ErrSelfApprove) {
		t.Fatalf("自审批应 ErrSelfApprove: %v", err)
	}
	// 申请单仍为 pending（未被消费）
	mine, _ := s.AccessRequestsFor(ctx, "alice")
	if len(mine) != 1 || mine[0].Status != "pending" {
		t.Fatalf("自审批失败后申请应仍 pending: %+v", mine)
	}
}

// 惰性到期：过了 expires_at 的 active 授予不进 ActiveGrants；JitGrants 展示层纠正为 expired。
func TestActiveGrantsLazyExpiry(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	// 白盒直插一条已过期的 active 授予
	if _, err := s.db.Exec(`INSERT INTO jit_grants(`+grantCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,0,'')`,
		"grant-old", "bob", "finance", "财务核算系统", "areq-x", "r", "admin", now-3600, now-60, "active"); err != nil {
		t.Fatal(err)
	}
	if act, _ := s.ActiveGrants(ctx); len(act) != 0 {
		t.Fatalf("已过期授予不应进 ActiveGrants: %+v", act)
	}
	if act, _ := s.ActiveGrantsFor(ctx, "bob"); len(act) != 0 {
		t.Fatalf("已过期授予不应进 ActiveGrantsFor: %+v", act)
	}
	all, _ := s.JitGrants(ctx)
	if len(all) != 1 || all[0].Status != "expired" {
		t.Fatalf("JitGrants 应把到期 active 展示为 expired: %+v", all)
	}
}

// 撤销：active → revoked；ActiveGrantsFor 不再返回；重复撤销 → ErrGrantInactive。
func TestRevokeGrant(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, _ := s.CreateAccessRequest(ctx, newReq("bob"))
	_, grant, _ := s.DecideAccessRequest(ctx, r.ID, "approved", "ok", "admin", 0)

	g, err := s.RevokeGrant(ctx, grant.ID, "违规")
	if err != nil || g.Status != "revoked" || g.RevokedAt == 0 {
		t.Fatalf("撤销应成功: %+v %v", g, err)
	}
	if act, _ := s.ActiveGrantsFor(ctx, "bob"); len(act) != 0 {
		t.Fatalf("撤销后不应再有有效授予: %+v", act)
	}
	if _, err := s.RevokeGrant(ctx, grant.ID, "再撤"); !errors.Is(err, ErrGrantInactive) {
		t.Fatalf("重复撤销应 ErrGrantInactive: %v", err)
	}
	if _, err := s.RevokeGrant(ctx, "grant-ghost", ""); !errors.Is(err, ErrGrantInactive) {
		t.Fatalf("撤销不存在授予应 ErrGrantInactive: %v", err)
	}
}

// JIT 续期（PRD FR-AUTH-03/04，ApprovalFlow.requestType「申请/续期」，
// 验收标准：「通过后用户授权延续」）。
//
// ★此前续期**结构上不可能**：CreateAccessRequest 对「已有 active 授予」一律回
// ErrDuplicateRequest —— 未到期提交被 409，等到期了访问已经断了，用户得在中断状态下
// 重新申请并等审批。而门户此时连入口都没有：已授予资源的磁贴渲染的是「访问」不是
// 「申请」，「剩余 X」红了也没有任何可点的动作。
func TestJitRenew(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r, err := s.CreateAccessRequest(ctx, newReq("bob"))
	if err != nil {
		t.Fatalf("首次申请: %v", err)
	}
	if r.Kind != AccessKindRequest {
		t.Errorf("首次申请的 kind 应是 request，实得 %q", r.Kind)
	}
	_, g, err := s.DecideAccessRequest(ctx, r.ID, "approved", "同意", "admin", 0)
	if err != nil {
		t.Fatalf("审批: %v", err)
	}

	// ① 刚获批、离到期还早 → 仍是重复提交（否则「续期」会变成刷时长的工具）
	if _, err := s.CreateAccessRequest(ctx, newReq("bob")); !errors.Is(err, ErrDuplicateRequest) {
		t.Errorf("离到期还早时应拒（防止把审批当刷时长工具），实得 %v", err)
	}

	// ② 把授予改成"快到期"：进入续期窗口
	near := time.Now().Unix() + int64(RenewWindowMinutes)*60 - 60
	if _, err := s.db.ExecContext(ctx, `UPDATE jit_grants SET expires_at=? WHERE id=?`, near, g.ID); err != nil {
		t.Fatal(err)
	}
	rn, err := s.CreateAccessRequest(ctx, newReq("bob"))
	if err != nil {
		t.Fatalf("临近到期应允许提交续期，实得 %v", err)
	}
	if rn.Kind != AccessKindRenew {
		t.Errorf("该单应被标记为续期，实得 %q", rn.Kind)
	}

	// ③ 审批通过 → **延长现有授予**，不新建
	_, g2, err := s.DecideAccessRequest(ctx, rn.ID, "approved", "续期同意", "admin", 0)
	if err != nil {
		t.Fatalf("审批续期: %v", err)
	}
	if g2.ID != g.ID {
		t.Errorf("续期应延长原授予（id 不变），实得新 id %s（原 %s）——"+
			"新建的话同一资源上会同时躺着两条 active 授予：网关两条都放行、都到期，"+
			"而撤销时管理员只会看到并撤掉其中一条", g2.ID, g.ID)
	}
	if g2.ExpiresAt <= near {
		t.Errorf("续期后到期时间应被延长：%d → %d", near, g2.ExpiresAt)
	}
	act, err := s.ActiveGrantsFor(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(act) != 1 {
		t.Errorf("续期后该资源上应仍只有 1 条 active 授予，实得 %d 条", len(act))
	}
}
