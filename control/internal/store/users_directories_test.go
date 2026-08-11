package store

import (
	"context"
	"testing"
)

// 访问者目录页顶部的身份源分栏必须来自真实数据。
//
// 钉住的是本轮修掉的那个残留：Users() 曾以 s.Memory.Users(ctx) 打底、只覆盖组织树/
// 用户组/用户清单，Directories 原样继承种子的「本地目录 124 / 总部 AD 域 1160」——
// 库里只有 8 个用户，页面顶部却是两个凭空数字，而同一个响应里的用户清单是真的。
func TestUserDirectoriesFromRealData(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	b, err := st.Users(ctx)
	if err != nil {
		t.Fatalf("读访问者目录失败：%v", err)
	}
	// 1) 没配任何认证源时**只有本地目录**：那个凭空的「总部 AD 域」不该存在。
	if len(b.Directories) != 1 {
		t.Fatalf("未配置外部认证源时应只有本地目录一条，实得 %+v", b.Directories)
	}
	local := b.Directories[0]
	if local.Key != "local" || local.Type != "local" {
		t.Fatalf("唯一一条应是本地目录，实得 %+v", local)
	}
	if local.Users != len(b.Users) {
		t.Errorf("本地目录账号数应等于真实用户数：目录 %d、清单 %d", local.Users, len(b.Users))
	}
	if local.Users == 124 {
		t.Error("本地目录账号数仍是种子的 124：Directories 没有脱种子")
	}

	// 2) 建几个用户 → 计数跟着变（证明它是现算的，不是某个写死的数）。
	before := local.Users
	for _, acct := range []string{"dir.a", "dir.b", "dir.c"} {
		if _, err := st.CreateUser(ctx, DirUser{Name: acct, Account: acct}); err != nil {
			t.Fatalf("建用户 %s 失败：%v", acct, err)
		}
	}
	b, err = st.Users(ctx)
	if err != nil {
		t.Fatalf("读访问者目录失败：%v", err)
	}
	if got := b.Directories[0].Users; got != before+3 {
		t.Errorf("新建 3 个用户后本地目录应为 %d，实得 %d", before+3, got)
	}
	if b.Directories[0].Users != len(b.Users) {
		t.Errorf("本地目录账号数与用户清单长度必须同源：%d vs %d", b.Directories[0].Users, len(b.Users))
	}
}

// 外部目录只在真配了认证源时出现，计数 = auth_source_bindings 的真实绑定条数；
// 且外部账号不能同时被算进本地目录（同一个人在两张卡片上各数一次）。
func TestUserDirectoriesExternalFollowsAuthSources(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	b, _ := st.Users(ctx)
	localBefore := b.Directories[0].Users

	if _, err := st.SaveAuthSource(ctx, AuthSourceRec{
		ID: "as-ad", Name: "总部 AD", Kind: "ad", Enabled: true, Priority: 3, Config: "{}",
	}); err != nil {
		t.Fatalf("保存认证源失败：%v", err)
	}
	// 刚配好、还没人登录过：目录出现，但账号数是 0，而不是一个"目录里有多少人"的猜数。
	b, err := st.Users(ctx)
	if err != nil {
		t.Fatalf("读访问者目录失败：%v", err)
	}
	if len(b.Directories) != 2 {
		t.Fatalf("配置外部认证源后应有本地 + AD 两条，实得 %+v", b.Directories)
	}
	ad := b.Directories[1]
	if ad.Key != "as-ad" || ad.Name != "总部 AD" || ad.Type != "ad" {
		t.Fatalf("外部目录字段应与 auth_sources 落库那份一致，实得 %+v", ad)
	}
	if ad.Users != 0 {
		t.Errorf("还没有人经该源登录过，账号数应为 0，实得 %d", ad.Users)
	}

	// 两个 subject 各登录一次 → 两条绑定；同一 subject 重复登录不重复计数。
	for _, sub := range []string{"ad-1", "ad-2", "ad-1"} {
		if _, err := st.BindExternalUser(ctx, "as-ad", ExternalIdentity{Subject: sub, Username: sub}); err != nil {
			t.Fatalf("绑定外部身份 %s 失败：%v", sub, err)
		}
	}
	b, _ = st.Users(ctx)
	if got := b.Directories[1].Users; got != 2 {
		t.Errorf("外部目录应计出 2 个已绑定账号，实得 %d", got)
	}
	if got := b.Directories[0].Users; got != localBefore {
		t.Errorf("外部账号不该被算进本地目录：绑定前 %d、绑定后 %d", localBefore, got)
	}
	// 用户清单里确实多了那两个人（外部账号建在 users 表里）——所以本地目录的口径
	// 必须是"没有外部绑定的账号"，不能拿清单长度当本地数。
	if len(b.Users) != localBefore+2 {
		t.Errorf("用户清单应含新建的 2 个外部账号：%d vs %d", len(b.Users), localBefore+2)
	}
}

// 态势总览的设备统计来自 trusted_devices 台账，空库就是全 0——
// 不再是种子里那句「在线 186 / 240，在线率 78%」。
func TestOverviewDeviceStatFromLedger(t *testing.T) {
	st := newAuthSrcStore(t)
	ctx := context.Background()

	ov, err := st.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if ov.Devices.Total != 0 || ov.Devices.Trusted != 0 || ov.Devices.Rate != 0 {
		t.Fatalf("一台设备都没登记时设备统计应全 0，实得 %+v", ov.Devices)
	}
	if ov.Sessions != 0 {
		t.Errorf("store 层不知道会话这回事，Sessions 应为 0（由 api 层按网关上报注入），实得 %d", ov.Sessions)
	}

	// 登记 3 台：2 台自动授信 + 1 台待审批 → 台账口径逐项可数。
	for _, fp := range []string{"fp-1", "fp-2"} {
		if _, _, err := st.EnrollDevice(ctx, "zhang.wei", fp, "MBP", "macOS", DeviceBindAuto); err != nil {
			t.Fatalf("登记设备 %s 失败：%v", fp, err)
		}
	}
	if _, _, err := st.EnrollDevice(ctx, "li.fang", "fp-3", "ThinkPad", "Windows", DeviceBindApproval); err != nil {
		t.Fatalf("登记待审批设备失败：%v", err)
	}
	ov, err = st.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if ov.Devices.Total != 3 || ov.Devices.Trusted != 2 || ov.Devices.Pending != 1 || ov.Devices.Revoked != 0 {
		t.Fatalf("设备统计应与台账逐项一致，实得 %+v", ov.Devices)
	}
	if ov.Devices.Rate <= 0.66 || ov.Devices.Rate >= 0.67 {
		t.Errorf("纳管率应为 2/3，实得 %v", ov.Devices.Rate)
	}
	// 设备防线的 TOP 实体必须是台账里真实存在的那台待审批设备。
	var dev DefenseLine
	for _, d := range ov.Defense {
		if d.Key == "device" {
			dev = d
		}
	}
	if len(dev.Top) != 1 || dev.Top[0] != "li.fang · ThinkPad" {
		t.Errorf("设备防线 TOP 应是台账里那台待审批设备，实得 %v", dev.Top)
	}
	if dev.Risk == 0 {
		t.Error("有待审批设备时设备防线风险分不应为 0")
	}
}
