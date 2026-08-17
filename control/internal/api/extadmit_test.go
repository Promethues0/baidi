package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

// ── wave8 行动 10：外部身份准入闸 ──
//
// 被修的坏形态：外部认证源认证通过 = 立刻建一个 role=user, status=active 的本地账号，
// **没有任何开关、白名单或审批**，建号本身也不落审计。而自动建号的外部账号落进
// 「外部目录」单元，其父是第一个顶层组织（种子里就是根）——组织授权含全部后代，
// 于是「把 OA 授权给根组织」这个最自然的操作，即刻覆盖全部自动建号的外部账号。

func admitSrc(policy string, domains, groups []string) store.AuthSourceRec {
	cfg, _ := json.Marshal(map[string]any{
		"host": "ldap.example.com", "admitPolicy": policy,
		"allowedDomains": domains, "allowedGroups": groups,
	})
	return store.AuthSourceRec{ID: "src-ad", Name: "总部 AD", Kind: "ad", Enabled: true, Config: string(cfg)}
}

func ident(user, email string, groups ...string) authsrc.Identity {
	return authsrc.Identity{
		Subject:  "CN=" + user + ",OU=People,DC=example,DC=com",
		Username: user, DisplayName: user, Email: email, Groups: groups,
	}
}

// TestAdmitAutoIsDefault 存量配置（没有 admitPolicy）行为不变——升级不该把人挡在门外。
func TestAdmitAutoIsDefault(t *testing.T) {
	s, _, _ := newFailServer(t)
	rec := store.AuthSourceRec{ID: "src", Name: "旧源", Kind: "ldap", Config: `{"host":"x"}`}
	if v := s.admitExternal(context.Background(), rec, ident("li", "li@ex.com"), false); !v.Allowed {
		t.Fatalf("没有 admitPolicy 的存量配置应保持自动建号，得到：%s", v.Reason)
	}
}

// TestAdmitApprovalBlocksFirstLogin approval 模式下首登不建号，只登记待批单。
func TestAdmitApprovalBlocksFirstLogin(t *testing.T) {
	s, _, _ := newFailServer(t)
	ctx := context.Background()
	rec := admitSrc(store.AdmitApproval, nil, nil)
	id := ident("wang", "wang@ex.com")

	v := s.admitExternal(ctx, rec, id, false)
	if v.Allowed {
		t.Fatal("approval 模式下首登必须被挡住——这正是被修的那个洞")
	}
	if !v.Pending || v.ApprovalID == "" {
		t.Fatalf("应登记一条待批单并带回单号：%+v", v)
	}
	if !v.NewTicket {
		t.Fatal("首次应报 NewTicket=true（调用方据此决定落不落审计）")
	}

	// 幂等：再登一次不该再建单子（登录可无限重试，每次建一条会把审批页刷满）。
	v2 := s.admitExternal(ctx, rec, id, false)
	if v2.Allowed || v2.ApprovalID != v.ApprovalID {
		t.Fatalf("重复登录应命中同一条待批单，得到 %+v", v2)
	}
	if v2.NewTicket {
		t.Fatal("重复登录不该报 NewTicket——那会让审计被登录重试刷成噪声")
	}
	// ★还要断言**审批页上没堆出孤儿待办**。只查 ApprovalID 稳定是不够的：
	// 先插审批单再插登记的写法下，每次重登都会往 approvals 塞一条新的 ap-xxx
	// （裸 INSERT + 新 uuid），而 ext_admissions 被主键挡住不动 —— 回读到的
	// ApprovalID 一直是第一条，用例照样绿，而管理员的审批页在往下堆。
	for i := 0; i < 3; i++ {
		s.admitExternal(ctx, rec, id, false)
	}
	if n := countApprovals(t, s, store.ApprovalKindExtUser); n != 1 {
		t.Fatalf("5 次登录只该有 1 条准入审批单，得到 %d 条孤儿待办", n)
	}
}

// countApprovals 数某一类审批单的条数（直接查库——这条不变式的现场就在表里）。
func countApprovals(t *testing.T, s *Server, kind string) int {
	t.Helper()
	as := s.extAdmitStore()
	if as == nil {
		t.Fatal("需要 SQLite 后端")
	}
	list, err := as.PendingExtAdmissions(context.Background())
	if err != nil {
		t.Fatalf("读待批失败：%v", err)
	}
	seen := map[string]bool{}
	for _, a := range list {
		seen[a.ApprovalID] = true
	}
	return len(seen)
}

// TestAdmitApprovalAllowsAfterApprove 批准后放行；拒绝后一直拒。
func TestAdmitApprovalAllowsAfterApprove(t *testing.T) {
	s, _, _ := newFailServer(t)
	ctx := context.Background()
	as := s.extAdmitStore()
	if as == nil {
		t.Fatal("SQLite 后端应支持准入登记")
	}
	rec := admitSrc(store.AdmitApproval, nil, nil)

	// 批准
	v := s.admitExternal(ctx, rec, ident("ok", "ok@ex.com"), false)
	if _, err := as.DecideExtAdmission(ctx, v.ApprovalID, store.AdmitApproved, "入职已确认", "admin"); err != nil {
		t.Fatalf("批准失败：%v", err)
	}
	if got := s.admitExternal(ctx, rec, ident("ok", "ok@ex.com"), false); !got.Allowed {
		t.Fatalf("批准后应放行：%s", got.Reason)
	}

	// 拒绝
	v2 := s.admitExternal(ctx, rec, ident("no", "no@ex.com"), false)
	if _, err := as.DecideExtAdmission(ctx, v2.ApprovalID, store.AdmitRejected, "外包已离场", "admin"); err != nil {
		t.Fatalf("拒绝失败：%v", err)
	}
	got := s.admitExternal(ctx, rec, ident("no", "no@ex.com"), false)
	if got.Allowed {
		t.Fatal("被拒绝的身份必须一直拒")
	}
	if got.Pending {
		t.Fatal("已拒绝不是「待批」——审计与页面上必须分得开")
	}
	if !strings.Contains(got.Reason, "外包已离场") {
		t.Fatalf("拒绝理由要带回给用户，得到 %q", got.Reason)
	}
}

// TestAdmitApprovalOnlyGatesNewAccounts 审批只判首次：已有账号的人不必天天再批。
func TestAdmitApprovalOnlyGatesNewAccounts(t *testing.T) {
	s, _, _ := newFailServer(t)
	rec := admitSrc(store.AdmitApproval, nil, nil)
	// bound=true 表示这个 subject 在白帝已有账号
	if v := s.admitExternal(context.Background(), rec, ident("old", "old@ex.com"), true); !v.Allowed {
		t.Fatalf("已建号的人不该再被审批闸挡住（否则老用户每天都要管理员点一次）：%s", v.Reason)
	}
}

// TestAdmitFilterAppliesEveryLogin 域/组白名单**每次登录都判**，包括已有账号的人。
//
// ★这是本组最容易写反的一条：把过滤也做成"只判首次"的话，目录侧
// 「把人移出允许组」这个动作对已建号的人**永远不生效**。
func TestAdmitFilterAppliesEveryLogin(t *testing.T) {
	s, _, _ := newFailServer(t)
	ctx := context.Background()
	rec := admitSrc(store.AdmitAuto, nil, []string{"vpn-users"})

	// 已有账号（bound=true）但不在组里 → 必须被拒
	v := s.admitExternal(ctx, rec, ident("gone", "gone@ex.com", "other-group"), true)
	if v.Allowed {
		t.Fatal("已建号但已被移出允许组的人必须被拒——只判首次的话「移出组」永远不生效")
	}
	if !strings.Contains(v.Reason, "组") {
		t.Fatalf("拒绝原因要点名是组白名单，得到 %q", v.Reason)
	}
	// 在组里 → 放行
	if got := s.admitExternal(ctx, rec, ident("in", "in@ex.com", "vpn-users"), true); !got.Allowed {
		t.Fatalf("在允许组内应放行：%s", got.Reason)
	}
}

// TestAdmitFilterDomain 邮箱域白名单；判不了（没带邮箱）一律拒。
func TestAdmitFilterDomain(t *testing.T) {
	s, _, _ := newFailServer(t)
	ctx := context.Background()
	rec := admitSrc(store.AdmitAuto, []string{"corp.com"}, nil)

	if v := s.admitExternal(ctx, rec, ident("a", "a@corp.com"), false); !v.Allowed {
		t.Fatalf("域命中应放行：%s", v.Reason)
	}
	if v := s.admitExternal(ctx, rec, ident("b", "b@gmail.com"), false); v.Allowed {
		t.Fatal("域不在白名单应被拒")
	}
	// ★判不了 → 拒。这是准入闸，fail-closed 是唯一正确方向。
	v := s.admitExternal(ctx, rec, ident("c", ""), false)
	if v.Allowed {
		t.Fatal("配了域白名单但认证源没返回邮箱时必须拒（fail-closed）")
	}
	if !strings.Contains(v.Reason, "fail-closed") && !strings.Contains(v.Reason, "无法核对") {
		t.Fatalf("原因要说清是判不了而不是不匹配，得到 %q", v.Reason)
	}
}

// TestAdmitFilterDomainAndGroupAreAND 两项都配则两项都要过。
//
// ★用 OR 的话，「再加一道组白名单」这个动作会**放宽**域白名单——
// 管理员以为在收紧，实际在放松。
func TestAdmitFilterDomainAndGroupAreAND(t *testing.T) {
	s, _, _ := newFailServer(t)
	ctx := context.Background()
	rec := admitSrc(store.AdmitAuto, []string{"corp.com"}, []string{"vpn"})
	cases := []struct {
		name  string
		id    authsrc.Identity
		allow bool
	}{
		{"域组都过", ident("a", "a@corp.com", "vpn"), true},
		{"域过组不过", ident("b", "b@corp.com", "other"), false},
		{"组过域不过", ident("c", "c@gmail.com", "vpn"), false},
		{"都不过", ident("d", "d@gmail.com", "other"), false},
	}
	for _, c := range cases {
		if got := s.admitExternal(ctx, rec, c.id, false); got.Allowed != c.allow {
			t.Errorf("%s：期望 allow=%v，得到 %v（%s）", c.name, c.allow, got.Allowed, got.Reason)
		}
	}
}

// TestAdmitPolicyRejectedAtSave 非法 admitPolicy 保存即拒。
//
// ★不校验的话，填 "Approval"（大写 A）会被归一成 auto——管理员在页面上看着
// 「需要审批」，实际每个人照样自动建号进来，全程零报错。
func TestAdmitPolicyRejectedAtSave(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
		"id": "s1", "name": "AD", "kind": "ad", "enabled": true,
		"config": map[string]any{"host": "x", "admitPolicy": "Approval"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("非法 admitPolicy 应 400，得到 %d：%v", code, out)
	}
	// 合法值照常保存，并且被清洗过的白名单写回了库。
	code, _ = doJSON(t, h, "POST", "/api/v1/authsrc/sources", adminToken(), map[string]any{
		"id": "s1", "name": "AD", "kind": "ad", "enabled": true,
		"config": map[string]any{"host": "x", "admitPolicy": "approval",
			"allowedDomains": []string{"corp.com", " corp.com ", ""}},
	})
	if code != http.StatusOK {
		t.Fatalf("合法配置应保存成功，得到 %d", code)
	}
	_, list := doJSON(t, h, "GET", "/api/v1/authsrc/sources", adminToken(), nil)
	raw, _ := json.Marshal(list["sources"])
	var srcs []store.AuthSourceRec
	_ = json.Unmarshal(raw, &srcs)
	for _, x := range srcs {
		if x.ID != "s1" {
			continue
		}
		var c struct {
			Policy  string   `json:"admitPolicy"`
			Domains []string `json:"allowedDomains"`
			Host    string   `json:"host"`
		}
		_ = json.Unmarshal([]byte(x.Config), &c)
		if c.Policy != store.AdmitApproval {
			t.Errorf("admitPolicy 没落库：%q", c.Policy)
		}
		if len(c.Domains) != 1 {
			t.Errorf("白名单应去空去重成 1 条，得到 %v", c.Domains)
		}
		// ★其余字段不能被写回抹掉。
		if c.Host != "x" {
			t.Errorf("写回准入设置时把其余配置抹掉了：host=%q", c.Host)
		}
	}
}

// TestDeviceApprovalRejectsExtAdmissionTicket 设备处置路径不得处置外部准入单。
//
// ★没有这道 kind 闸的话：管理员在审批页点「批准」一条外部准入单 → 走设备联动路径
// → 按 approval_id 查不到设备 → 按「迁移前遗留的单子」返回 found=false →
// handler 照常回 200 并落一条「审批通过」的审计，而那个人**仍然进不来**。
func TestDeviceApprovalRejectsExtAdmissionTicket(t *testing.T) {
	s, h, _ := newFailServer(t)
	ctx := context.Background()
	rec := admitSrc(store.AdmitApproval, nil, nil)
	v := s.admitExternal(ctx, rec, ident("zhou", "zhou@ex.com"), false)
	if v.ApprovalID == "" {
		t.Fatal("没拿到准入单号")
	}
	code, _ := doJSON(t, h, "POST", "/api/v1/approvals/"+v.ApprovalID+"/decide", adminToken(),
		map[string]string{"decision": "approved"})
	if code == http.StatusOK {
		t.Fatal("设备审批路径处置了一条外部准入单并回了 200——审批单变 approved 而人还是进不来")
	}
	// 而且那条准入登记不能被改动。
	as := s.extAdmitStore()
	adm, ok, _ := as.ExtAdmission(ctx, rec.ID, ident("zhou", "").Subject)
	if !ok || adm.Status != store.AdmitPending {
		t.Fatalf("准入登记不该被设备路径动过：%+v", adm)
	}
}

// TestDecideExtAdmissionEndpoint 端点：批准/重复处置/不存在。
func TestDecideExtAdmissionEndpoint(t *testing.T) {
	s, h, _ := newFailServer(t)
	rec := admitSrc(store.AdmitApproval, nil, nil)
	v := s.admitExternal(context.Background(), rec, ident("qian", "qian@ex.com"), false)

	code, out := doJSON(t, h, "GET", "/api/v1/authsrc/admissions", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("列表 %d", code)
	}
	if arr, _ := out["admissions"].([]any); len(arr) != 1 {
		t.Fatalf("应有 1 条待批，得到 %v", out["admissions"])
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/authsrc/admissions/"+v.ApprovalID+"/decide", adminToken(),
		map[string]string{"decision": "approved", "reason": "已核实"}); code != http.StatusOK {
		t.Fatalf("批准应 200，得到 %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/authsrc/admissions/"+v.ApprovalID+"/decide", adminToken(),
		map[string]string{"decision": "rejected"}); code != http.StatusConflict {
		t.Fatalf("重复处置应 409，得到 %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/authsrc/admissions/ap-nope/decide", adminToken(),
		map[string]string{"decision": "approved"}); code != http.StatusNotFound {
		t.Fatalf("不存在应 404，得到 %d", code)
	}
	// 处置要落审计，且措辞不得声称"已建号"（账号要等他下次登录才建）。
	e, ok := findAudit(auditRows(t, h), "批准外部身份准入")
	if !ok {
		t.Fatal("处置没落审计")
	}
	if !strings.Contains(e.Event, "下次登录时才会建号") {
		t.Fatalf("措辞要说清账号还没建：%q", e.Event)
	}
}

// ── 端到端：准入闸的**位置** ──

// fakePwAuth 一个总是认证成功的口令认证源（测试注入缝用）。
type fakePwAuth struct{ id authsrc.Identity }

func (f fakePwAuth) Authenticate(_ context.Context, _, _ string) (authsrc.Identity, error) {
	return f.id, nil
}
func (f fakePwAuth) Probe(context.Context) error { return nil }

// TestAdmitGateBlocksAccountCreation 被准入闸拒绝时**不得建号**。
//
// ★这条是纯函数用例覆盖不到的：admitExternal 判得再对，只要它被接在
// BindExternalUser **之后**，账号照建不误——而"账号已经存在、已经落进组织树、
// 已经被组织授权覆盖到了"正是本行动要防的全部内容。
// 只有走完整条 authenticateExternal 才验得到 users 表里没多出行。
func TestAdmitGateBlocksAccountCreation(t *testing.T) {
	s, h, _ := newFailServer(t)
	ctx := context.Background()

	aw, _ := s.store.(store.AuthSourceStore)
	if aw == nil {
		t.Fatal("需要 SQLite 后端")
	}
	rec := admitSrc(store.AdmitApproval, nil, nil)
	if _, err := aw.SaveAuthSource(ctx, rec); err != nil {
		t.Fatalf("存认证源失败：%v", err)
	}
	id := ident("newguy", "newguy@ex.com")
	s.testPasswordAuth = func(store.AuthSourceRec) (authsrc.PasswordAuthenticator, error) {
		return fakePwAuth{id: id}, nil
	}

	before := countUsers(t, s)
	_, _, _, hit, err := s.authenticateExternal(
		httptest.NewRequest(http.MethodPost, "/api/v1/portal/login", nil), "newguy", "pw", "")
	if hit {
		t.Fatal("准入未获批准，不该认定为登录成功")
	}
	d := asAdmitDenied(err)
	if d == nil {
		t.Fatalf("应回准入拒绝错误，得到 %v", err)
	}
	if !d.Pending() {
		t.Fatalf("首次应是「待批」而不是确定性拒绝：%s", d.Error())
	}
	// ★核心断言：users 表一行都不许多。
	if after := countUsers(t, s); after != before {
		t.Fatalf("被准入闸拒绝却建了号：改造前 %d 行 → 现在 %d 行。"+
			"闸接在 BindExternalUser 之后就是这个症状", before, after)
	}
	// 而且不该被计进爆破锁定（口令是对的，用户什么都没做错）。
	if s.lockout != nil && len(s.lockout.Active()) != 0 {
		t.Fatalf("准入拒绝不该计入爆破锁定：%v", s.lockout.Active())
	}
	// 待批审计要有一条，且与「口令错」分得开。
	e, ok := findAudit(auditRows(t, h), "等待准入批准")
	if !ok {
		t.Fatal("待批没落审计")
	}
	if e.Verdict == "deny" {
		t.Fatalf("待批不是拒绝，verdict 应与确定性拒绝分开，得到 %q", e.Verdict)
	}

	// 批准后再登：这次才建号。
	as := s.extAdmitStore()
	list, _ := as.PendingExtAdmissions(ctx)
	if len(list) != 1 {
		t.Fatalf("应有 1 条待批，得到 %d", len(list))
	}
	if _, err := as.DecideExtAdmission(ctx, list[0].ApprovalID, store.AdmitApproved, "已核实", "admin"); err != nil {
		t.Fatalf("批准失败：%v", err)
	}
	cred, _, _, hit2, err2 := s.authenticateExternal(
		httptest.NewRequest(http.MethodPost, "/api/v1/portal/login", nil), "newguy", "pw", "")
	if !hit2 || err2 != nil {
		t.Fatalf("批准后应登录成功：hit=%v err=%v", hit2, err2)
	}
	if after := countUsers(t, s); after != before+1 {
		t.Fatalf("批准后应恰好建 1 个号：%d → %d", before, after)
	}
	// 建号要留痕（改造前完全不记）。
	if _, ok := findAudit(auditRows(t, h), "外部认证源自动建号"); !ok {
		t.Fatalf("建号没落审计（账号 %s）", cred.Account)
	}
}

// countUsers 目录用户行数。
func countUsers(t *testing.T, s *Server) int {
	t.Helper()
	b, err := s.store.Users(context.Background())
	if err != nil {
		t.Fatalf("读用户失败：%v", err)
	}
	return len(b.Users)
}
