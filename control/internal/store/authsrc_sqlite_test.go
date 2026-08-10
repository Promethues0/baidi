package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func newAuthSrcStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "authsrc.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// 迁移回填：既有库升级上来时 auth_sources 是空的，必须补出 local 这条。
// 缺了它，界面上会显示「没有任何认证源」，让人以为登录已经不工作了。
func TestSeedLocalAuthSource(t *testing.T) {
	st := newAuthSrcStore(t)
	srcs, err := st.AuthSources(context.Background())
	if err != nil {
		t.Fatalf("读认证源失败：%v", err)
	}
	if len(srcs) != 1 || srcs[0].ID != "local" {
		t.Fatalf("应恰好回填出一条 local，实得 %+v", srcs)
	}
	// ★原来那 5 条（AD/RADIUS/OAuth/短信/商密证书）必须不在了：
	// 留着一个编造用户数的假磁贴，比没有这个磁贴更不诚实。
	for _, s := range srcs {
		if s.Kind != "local" {
			t.Fatalf("不该再有编造的种子认证源：%+v", s)
		}
	}
	// 幂等：再开一次不该变成两条。
	if err := st.seedLocalAuthSource(); err != nil {
		t.Fatalf("重复回填失败：%v", err)
	}
	srcs, _ = st.AuthSources(context.Background())
	if len(srcs) != 1 {
		t.Fatalf("回填不幂等，实得 %d 条", len(srcs))
	}
}

// ★这条守的是本轮最重要的一个洞：**外部目录里叫 admin 的账号，不能变成本地 admin**。
//
// 绑定必须以 (源, subject) 为键。若按用户名绑定/复用本地账号，
// 谁能在 AD 里新建一个叫 admin 的账号，谁就能登录成本地管理员——
// 而审计日志里看到的是一次完全正常的「admin 登录成功」。
func TestBindExternalUser_同名不得复用本地账号(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	localAdmin, found, err := st.Credential(ctx, "admin")
	if err != nil || !found {
		t.Fatalf("本地 admin 应存在：err=%v found=%v", err, found)
	}
	if localAdmin.Role != "admin" {
		t.Fatalf("前提不成立：本地 admin 的 role 应为 admin，实得 %q", localAdmin.Role)
	}

	ext, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{
		Subject: "CN=admin,OU=Users,DC=corp", Username: "admin", DisplayName: "冒充者",
	})
	if err != nil {
		t.Fatalf("绑定失败：%v", err)
	}
	if ext.ID == localAdmin.ID {
		t.Fatal("外部的 admin 复用了本地 admin 账号——外部目录的控制权变成了本地管理员的控制权")
	}
	if ext.Role == "admin" {
		t.Fatalf("外部账号不得自带 admin 角色（实得 %q）："+
			"外部目录说你是谁，不代表你在白帝里是管理员", ext.Role)
	}
	if ext.Account == "admin" {
		t.Fatalf("撞名时账号应加来源后缀，实得 %q", ext.Account)
	}
	// ★外部账号不得有本地口令：否则认证源被停用/删除后，
	// 那个账号会退回成"用某个本地口令也能登录"。
	if ext.PassHash != "" {
		t.Fatalf("外部账号的 pass_hash 必须为空，实得 %q", ext.PassHash)
	}
}

// 加了来源后缀仍撞名时必须继续消歧——两个不同 subject 绝不能共用一个 account。
//
// ★account 是令牌主体（JWT Sub）与 JIT 授予/封禁/posture 的键，共号 = 后来者
// 直接继承前者的全部授权，而审计日志看起来完全正常。同源两个用户名都归一成
// 同一个字符串是现实可达的：UserFilter 按 mail 唯一命中、UsernameAttr 却配了
// displayName 这类非唯一属性时就会发生。
func TestBindExternalUser_后缀撞名仍须消歧(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	// 本地已有 admin → 第一个外部 admin 拿到 admin@ad-1
	first, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{
		Subject: "CN=a,OU=U,DC=corp", Username: "admin", DisplayName: "甲",
	})
	if err != nil {
		t.Fatalf("首个外部 admin 绑定失败：%v", err)
	}
	// 同源第二个人，用户名归一后同样是 admin
	second, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{
		Subject: "CN=b,OU=U,DC=corp", Username: "admin", DisplayName: "乙",
	})
	if err != nil {
		t.Fatalf("第二个外部 admin 绑定失败：%v", err)
	}

	if second.ID == first.ID {
		t.Fatal("两个不同 subject 被绑到了同一个本地用户")
	}
	if strings.EqualFold(second.Account, first.Account) {
		t.Fatalf("两个不同身份共用了同一个 account %q——后来者会继承前者的 JIT 授予与令牌主体", second.Account)
	}
	// 两条记录都要能按各自 subject 找回来（消歧不能以丢绑定为代价）
	for _, tc := range []struct {
		subject string
		want    string
	}{{"CN=a,OU=U,DC=corp", first.Account}, {"CN=b,OU=U,DC=corp", second.Account}} {
		got, ok, err := st.UserBySubject(ctx, "ad-1", tc.subject)
		if err != nil || !ok {
			t.Fatalf("subject %s 应能找回：err=%v ok=%v", tc.subject, err, ok)
		}
		if got.Account != tc.want {
			t.Fatalf("subject %s 找回的账号是 %q，应为 %q", tc.subject, got.Account, tc.want)
		}
	}
}

// 绑定行指向的用户被清掉后，同一 subject 再登录必须能重建——
// UserBySubject 的注释就是这么声明的，而裸 INSERT 会撞上没被删的旧主键，
// 让该身份**永久**登录失败，且面貌是「认证服务暂时不可用」。
func TestBindExternalUser_陈旧绑定可重建(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	first, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{
		Subject: "CN=c,OU=U,DC=corp", Username: "zhang.wei", DisplayName: "张伟",
	})
	if err != nil {
		t.Fatalf("绑定失败：%v", err)
	}
	// 模拟"用户行被清掉、绑定行还在"（运维直改库的常见形态）
	if _, err := st.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, first.ID); err != nil {
		t.Fatalf("删用户失败：%v", err)
	}
	if _, ok, _ := st.UserBySubject(ctx, "ad-1", "CN=c,OU=U,DC=corp"); ok {
		t.Fatal("前提不成立：用户已删，UserBySubject 应报未绑定")
	}

	again, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{
		Subject: "CN=c,OU=U,DC=corp", Username: "zhang.wei", DisplayName: "张伟",
	})
	if err != nil {
		t.Fatalf("陈旧绑定应可重建，实得错误：%v", err)
	}
	if again.ID == first.ID {
		t.Fatal("重建应产生新的用户行")
	}
	got, ok, err := st.UserBySubject(ctx, "ad-1", "CN=c,OU=U,DC=corp")
	if err != nil || !ok || got.ID != again.ID {
		t.Fatalf("重建后绑定应指向新用户：err=%v ok=%v id=%q want=%q", err, ok, got.ID, again.ID)
	}
}

// 同一 subject 重复登录必须映射到同一个本地用户（不是每次新建）。
// 而 subject 变了就必须是另一个人，哪怕用户名一模一样。
func TestBindExternalUser_按subject而非用户名认人(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	a1, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{
		Subject: "CN=zhang,OU=Users,DC=corp", Username: "zhang.wei2",
	})
	if err != nil {
		t.Fatalf("首次绑定失败：%v", err)
	}
	a2, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{
		Subject: "CN=zhang,OU=Users,DC=corp", Username: "zhang.wei2",
	})
	if err != nil {
		t.Fatalf("二次绑定失败：%v", err)
	}
	if a1.ID != a2.ID {
		t.Fatalf("同一 subject 应映射到同一本地用户：%s vs %s", a1.ID, a2.ID)
	}

	// 用户名相同、subject 不同 → 必须是另一个人。
	b, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{
		Subject: "CN=zhang-impostor,OU=Users,DC=corp", Username: "zhang.wei2",
	})
	if err != nil {
		t.Fatalf("第三次绑定失败：%v", err)
	}
	if b.ID == a1.ID {
		t.Fatal("subject 不同却映射到了同一个本地用户——按用户名认人了")
	}

	// 空 subject 必须拒绝：没有权威标识就没法安全绑定。
	if _, err := st.BindExternalUser(ctx, "ad-1", ExternalIdentity{Username: "nosubject"}); err == nil {
		t.Fatal("空 subject 必须拒绝绑定")
	}
}

// 删除认证源要连同绑定一起清。留着孤儿绑定的话，管理员删掉再重建同名源时，
// 老绑定会把新源的用户接到旧的本地账号上——一个凭空出现的越权路径。
func TestDeleteAuthSource_连同绑定一起清(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	rec, err := st.SaveAuthSource(ctx, AuthSourceRec{ID: "ad-x", Name: "测试 AD", Kind: "ad", Enabled: true})
	if err != nil {
		t.Fatalf("建源失败：%v", err)
	}
	if _, err := st.BindExternalUser(ctx, rec.ID, ExternalIdentity{
		Subject: "CN=u1,DC=corp", Username: "u1",
	}); err != nil {
		t.Fatalf("绑定失败：%v", err)
	}
	if _, ok, _ := st.UserBySubject(ctx, rec.ID, "CN=u1,DC=corp"); !ok {
		t.Fatal("前提不成立：绑定应存在")
	}
	if err := st.DeleteAuthSource(ctx, rec.ID); err != nil {
		t.Fatalf("删源失败：%v", err)
	}
	if _, ok, _ := st.UserBySubject(ctx, rec.ID, "CN=u1,DC=corp"); ok {
		t.Fatal("删除认证源后绑定仍在——重建同名源会把新用户接到旧账号上")
	}
	// 本地目录不可删。
	if err := st.DeleteAuthSource(ctx, "local"); err == nil {
		t.Fatal("本地目录必须不可删除")
	}
}

// 凭据指纹必须能在**不解密**的前提下出现在清单里。
//
// ★这条守的是一个"功能看着有、实际不工作"的缺口：指纹存在的唯一意义是让管理员
// 核对"两端配的是不是同一把"。最初的实现只在写入时算指纹返回给调用方，清单里
// 永远是空的——界面上显示成 ••••，看起来像"没配指纹"，实际是"从来没存过"。
// 修法是写入时把指纹一起落库，而**不是**在列表里解密明文去算
// （那会在一条人人可读的路径上引入解密调用，与"只写不读"自相矛盾）。
func TestAuthSourceSecret_指纹不解密即可读到(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	rec, err := st.SaveAuthSource(ctx, AuthSourceRec{Name: "AD", Kind: "ad", Enabled: true})
	if err != nil {
		t.Fatalf("建源失败：%v", err)
	}
	if err := st.SaveAuthSourceSecret(ctx, AuthSourceSecret{
		SourceID: rec.ID, Nonce: []byte("n"), Cipher: []byte("c"), Fingerprint: "deadbeef",
	}); err != nil {
		t.Fatalf("写凭据失败：%v", err)
	}

	// 清单路径
	srcs, err := st.AuthSources(ctx)
	if err != nil {
		t.Fatalf("读清单失败：%v", err)
	}
	var got AuthSourceRec
	for _, s := range srcs {
		if s.ID == rec.ID {
			got = s
		}
	}
	if !got.HasSecret {
		t.Fatal("hasSecret 应为 true")
	}
	if got.SecretFingerprint != "deadbeef" {
		t.Fatalf("清单里应带出指纹，实得 %q——指纹功能不工作，界面会显示成「未配置指纹」", got.SecretFingerprint)
	}

	// 详情路径同样要有
	one, ok, err := st.AuthSourceByID(ctx, rec.ID)
	if err != nil || !ok {
		t.Fatalf("读详情失败：err=%v ok=%v", err, ok)
	}
	if one.SecretFingerprint != "deadbeef" {
		t.Fatalf("详情里应带出指纹，实得 %q", one.SecretFingerprint)
	}

	// 改凭据要换指纹（而不是保留旧的）。
	if err := st.SaveAuthSourceSecret(ctx, AuthSourceSecret{
		SourceID: rec.ID, Nonce: []byte("n2"), Cipher: []byte("c2"), Fingerprint: "cafebabe",
	}); err != nil {
		t.Fatalf("改凭据失败：%v", err)
	}
	one, _, _ = st.AuthSourceByID(ctx, rec.ID)
	if one.SecretFingerprint != "cafebabe" {
		t.Fatalf("改凭据后指纹应更新，实得 %q——不更新会让管理员以为还是旧的那把", one.SecretFingerprint)
	}
}

// ★外部账号必须真正落进组织：org_id 是 SubjectIndex 的 JOIN 键，只写 org_key
// 会让这批人"页面上在外包部门里、授权与策略却一个都覆盖不到"。
//
// 两个方向各一条断言，正是这个洞两头都不报错的原因：
//   - 资源侧把资源授权给该组织 → 展开里必须有他（此前是 fail-closed：连不上）；
//   - 策略侧种子策略 ap-ext-strict（ScopeOrgs=["ext"]）→ 覆盖必须成立
//     （此前是 fail-open：该强制二次认证的人静默走单因素，谁也看不见）。
func TestBindExternalUser_落进组织并被主体展开覆盖(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	c, err := st.BindExternalUser(ctx, "ldap-1", ExternalIdentity{
		Subject: "CN=wu.tao,OU=Vendor,DC=corp", Username: "wu.tao", DisplayName: "吴涛",
	})
	if err != nil {
		t.Fatalf("绑定失败：%v", err)
	}
	b, err := st.Users(ctx)
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	var bound DirUser
	for _, u := range b.Users {
		if u.Account == c.Account {
			bound = u
		}
	}
	if bound.OrgID == "" {
		t.Fatal("外部账号的 org_id 为空：SubjectIndex 按 org_id JOIN，这批人不会被任何组织授权/策略覆盖")
	}

	ix, err := st.SubjectIndex(ctx)
	if err != nil {
		t.Fatalf("SubjectIndex: %v", err)
	}
	hit := func(accs []string) bool {
		for _, a := range accs {
			if a == strings.ToLower(c.Account) {
				return true
			}
		}
		return false
	}
	if !hit(ix.OrgAccounts[bound.OrgID]) {
		t.Errorf("外部账号未出现在自己所属组织 %s 的展开里：%v", bound.OrgID, ix.OrgAccounts[bound.OrgID])
	}
	// 子树继承：授权给根组织也应覆盖他
	orgs, _ := st.OrgUnits(ctx)
	for _, o := range orgs {
		if o.ParentID == "" && !hit(ix.OrgAccounts[o.ID]) {
			t.Errorf("授权给根组织 %s 未覆盖外部账号（子树继承断了）", o.ID)
		}
	}
	// 种子策略 ap-ext-strict 的适用范围（ScopeOrgs=["ext"]）必须真的圈到他
	if !hit(ix.OrgAccounts["ext"]) {
		t.Error("绑「外包人员」组织的认证策略覆盖不到外部账号——该强制二次认证的人会静默走单因素")
	}
}

// 组织被管理员删掉之后，下一个外部身份首登要能把它建回来——
// 没有组织归属的外部账号谁都管不到，而且从页面上看不出来。
func TestBindExternalUser_外部组织缺失时当场建出(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()
	// 先腾空并删掉 ext（种子策略引用着它，先解除绑定）
	users, _ := st.Users(ctx)
	for _, u := range users.Users {
		if u.OrgID == externalOrgUnitID {
			if err := st.SetUserOrg(ctx, u.ID, "dev"); err != nil {
				t.Fatalf("SetUserOrg: %v", err)
			}
		}
	}
	pols, _ := st.AuthPolicies(ctx)
	for _, p := range pols {
		if len(p.ScopeOrgs) > 0 {
			p.ScopeOrgs = []string{"dev"}
			if _, err := st.SaveAuthPolicy(ctx, p); err != nil {
				t.Fatalf("改策略范围: %v", err)
			}
		}
	}
	if err := st.DeleteOrgUnit(ctx, externalOrgUnitID); err != nil {
		t.Fatalf("删外部组织: %v", err)
	}

	c, err := st.BindExternalUser(ctx, "oidc-1", ExternalIdentity{
		Subject: "sub-9527", Username: "sun.li", DisplayName: "孙丽",
	})
	if err != nil {
		t.Fatalf("绑定失败：%v", err)
	}
	orgs, _ := st.OrgUnits(ctx)
	var ext Org
	for _, o := range orgs {
		if o.ID == externalOrgUnitID {
			ext = o
		}
	}
	if ext.ID == "" {
		t.Fatal("外部组织缺失时未被建回来")
	}
	if ext.Path != "/root/"+externalOrgUnitID+"/" {
		t.Errorf("物化 path 必须与 SaveOrgUnit 同算法（父 path + id + /），得到 %q", ext.Path)
	}
	ix, _ := st.SubjectIndex(ctx)
	found := false
	for _, a := range ix.OrgAccounts[externalOrgUnitID] {
		if a == strings.ToLower(c.Account) {
			found = true
		}
	}
	if !found {
		t.Error("新建的外部组织没能把账号展开出来")
	}
}

// 存量行回填：本轮之前 BindExternalUser 只写 org_key='ext'、org_id 为空。
// 补列/补写必须配回填，否则那批账号永远在 SubjectIndex 之外（无报错、无痕迹）。
func TestBackfillExternalUserOrg(t *testing.T) {
	path := filepath.Join(t.TempDir(), "extorg.db")
	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open#1: %v", err)
	}
	ctx := context.Background()
	c, err := s1.BindExternalUser(ctx, "ldap-1", ExternalIdentity{
		Subject: "CN=legacy,OU=Vendor,DC=corp", Username: "legacy.user",
	})
	if err != nil {
		t.Fatalf("绑定失败：%v", err)
	}
	// 退回旧形态：org_id 清空 + 抹掉回填标记
	if _, err := s1.db.ExecContext(ctx, `UPDATE users SET org_id='' WHERE account=?`, c.Account); err != nil {
		t.Fatalf("退回旧形态: %v", err)
	}
	if _, err := s1.db.ExecContext(ctx, `DELETE FROM settings WHERE k=?`, extUserOrgBackfillMarker); err != nil {
		t.Fatalf("删标记: %v", err)
	}
	s1.Close()

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open#2: %v", err)
	}
	defer s2.Close()
	b, _ := s2.Users(ctx)
	for _, u := range b.Users {
		if u.Account == c.Account && u.OrgID == "" {
			t.Fatal("既有外部账号的 org_id 未被回填：这批人永远不在任何组织授权/策略的覆盖里")
		}
	}
}
