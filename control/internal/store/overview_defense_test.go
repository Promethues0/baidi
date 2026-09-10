package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ── wave11 行动 12：态势总览三道防线 ──
//
// 被修的两条坏形态：
//
//	① 账号防线的风险分与 TOP 取自 users.risk **死列**（全仓只有 INSERT、没有一处
//	   UPDATE，是建号那一刻写下的值）。wave9 已因此把用户目录页那一列改成现算，
//	   安全概览这一半没跟上——同一个账号在两页上给出相反的结论，而概览这页正是
//	   管理员用来决定"今天该盯谁"的入口。
//	② 「风险终端 TOP5」返回的是**账号名**，且与「风险账号 TOP5」是同一批条目：
//	   两张卡显示同一份数据、各起一个名字，看的人以为交叉印证了两次。
//
// 这几条用例都做过变异实跑（把修复回退成旧写法，确认真的变红），逐条记在断言旁。

// mkPosture 落一份 posture 上报（TS 用当前时刻，避免与"取最新一份"的排序纠缠）。
func mkPosture(t *testing.T, st *SQLiteStore, user, dev, plat, verdict string, score int) {
	t.Helper()
	err := st.SavePostureReport(context.Background(), PostureReport{
		User: user, Device: dev, Platform: plat, OS: "15.1",
		Verdict: verdict, Score: score, Level: "low", TS: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("落 posture 失败：%v", err)
	}
}

// TestAccountDefenseIgnoresDeadRiskColumn 账号防线只认现算判定，不认 users.risk。
//
// 变异实跑：把 accountDefense 里的判据换回 `u.Risk == "high"`，本用例第一段变红
// （种子里 li.fang / ext.zhou 恒为 high，会凭空出现在 TOP 里）。
func TestAccountDefenseIgnoresDeadRiskColumn(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// 库里 li.fang 的 users.risk 就是 "high"（种子写死）。先确认这个前提还在，
	// 否则本用例会在种子改动后悄悄变成一条什么都没测的绿灯。
	b, err := st.Users(ctx)
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	var seeded bool
	for _, u := range b.Users {
		if u.Account == "li.fang" && u.Risk == "high" {
			seeded = true
		}
	}
	if !seeded {
		t.Skip("种子已不再给 li.fang 写死 risk=high，本用例失去被测前提")
	}

	ov, err := st.Overview(ctx, 0)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	acct := defenseOf(t, ov, "account")
	if len(acct.Top) != 0 {
		t.Fatalf("users.risk 那一列不该进 TOP（它是建号那天的死值），实得 %v", acct.Top)
	}

	// 现在给一个**别的**账号真上报一次 block：TOP 必须换成他。
	mkPosture(t, st, "chen.jing", "FP-CHEN", "Windows", DisposalBlock, 40)
	ov, err = st.Overview(ctx, 0)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	acct = defenseOf(t, ov, "account")
	if len(acct.Top) != 1 || acct.Top[0] != "chen.jing" {
		t.Fatalf("账号防线 TOP 应只有真被判 block 的 chen.jing，实得 %v", acct.Top)
	}
}

// TestAccountDefenseCountsDegradeAsHigh 折算表只有一份：degrade 与 block 同为 high。
//
// ★这条钉的是 store.RiskOfDisposal 被 api.riskOfAccount 与本页共用。
// 变异实跑：把 RiskOfDisposal 里的 DisposalDegrade 挪去 low，本用例变红
// （degrade 是"高敏资源已被摘掉"，在概览上不列出来管理员就看不到降权正在发生）。
func TestAccountDefenseCountsDegradeAsHigh(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mkPosture(t, st, "li.fang", "FP-A", "macOS", DisposalDegrade, 20)
	mkPosture(t, st, "wang.qiang", "FP-B", "macOS", DisposalGray, 10)
	mkPosture(t, st, "chen.jing", "FP-C", "macOS", DisposalAllow, 0)

	ov, err := st.Overview(ctx, 0)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	acct := defenseOf(t, ov, "account")
	if len(acct.Top) != 1 || acct.Top[0] != "li.fang" {
		t.Fatalf("只有 degrade/block 计高危（gray=low、allow=none 不进 TOP），实得 %v", acct.Top)
	}
	// 三个人报过、其余账号没报过：Unknown 必须是"其余那些"，不是 0。
	if acct.Unknown != ov.Users.Total-3 {
		t.Fatalf("Unknown 应为 %d（未上报过的账号数），实得 %d", ov.Users.Total-3, acct.Unknown)
	}
}

// TestAccountDefenseUnknownIsNotSafe 从未上报的账号既不算高危、也不算安全。
//
// ★这是本项目「不可判定 != false」在这页上的落点：TOP 空 + Unknown>0 说的是
// "没有判定材料"，TOP 空 + Unknown==0 才是"确实一个高危都没有"。塌成一个字的话，
// 一套刚装好、客户端根本没铺开的系统会显示成"账号防线全绿"。
//
// 变异实跑：把 accountDefense 里 `unknown++` 那两处删掉，本用例变红。
func TestAccountDefenseUnknownIsNotSafe(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	ov, err := st.Overview(ctx, 0)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	acct := defenseOf(t, ov, "account")
	if acct.Unknown == 0 {
		t.Fatal("一份 posture 都没有时 Unknown 不该是 0——那与「全员判定通过」同形")
	}
	if !strings.Contains(acct.Note, "不可判定") {
		t.Fatalf("口径说明必须点出「不可判定」这件事，实得 %q", acct.Note)
	}
	// 认不出的处置值同样是"判不出来"，不能被当成 allow 悄悄计成安全。
	mkPosture(t, st, "li.fang", "FP-A", "macOS", "看不懂的判定", 0)
	ov, err = st.Overview(ctx, 0)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	acct2 := defenseOf(t, ov, "account")
	if acct2.Unknown != acct.Unknown {
		t.Fatalf("认不出的处置值应仍计为不可判定（%d），实得 %d", acct.Unknown, acct2.Unknown)
	}
}

// TestEndpointDefenseIsDeviceDimension 终端防线是**设备**维度，条目形如
// 「平台 · 指纹短码 · 判定档 · 账号」，且同一账号的多台机器各占一行。
//
// 变异实跑：把 endpointDefense 的 TOP 换回 `r.User`，本用例变红（两台机器折成
// 一条、且与账号防线逐字相同——那正是改造前的形态）。
func TestEndpointDefenseIsDeviceDimension(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	mkPosture(t, st, "li.fang", "aaaaaaaaaaaaaaaaaaaa", "macOS", DisposalBlock, 40)
	mkPosture(t, st, "li.fang", "bbbbbbbbbbbbbbbbbbbb", "Windows", DisposalDegrade, 20)

	ov, err := st.Overview(ctx, 0)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	ep := defenseOf(t, ov, "endpoint")
	if len(ep.Top) != 2 {
		t.Fatalf("同一账号的两台机器应各占一行，实得 %v", ep.Top)
	}
	// 严厉度高的排前面（block > degrade）。
	if !strings.Contains(ep.Top[0], "已阻断") || !strings.Contains(ep.Top[1], "已降权") {
		t.Fatalf("终端行应按处置严厉度排序，实得 %v", ep.Top)
	}
	// 平台 + 指纹短码（带省略号）+ 账号三样都在。
	if !strings.Contains(ep.Top[0], "macOS 15.1") || !strings.Contains(ep.Top[0], "li.fang") {
		t.Fatalf("终端行应带平台与账号，实得 %q", ep.Top[0])
	}
	if !strings.Contains(ep.Top[0], "aaaaaaaaaaaa…") {
		t.Fatalf("指纹截断必须带省略号（否则短码看起来像完整指纹，拿去搜一无所获），实得 %q", ep.Top[0])
	}

	// 账号防线此刻只有一条 li.fang——两张卡不许出现逐字相同的条目。
	acct := defenseOf(t, ov, "account")
	for _, a := range acct.Top {
		for _, e := range ep.Top {
			if a == e {
				t.Fatalf("两张卡显示了同一件事：%q", a)
			}
		}
	}
}

// TestEndpointDefenseRiskUnknownWithoutReports 一份上报都没有时风险分必须缺席。
//
// ★0 分会被仪表渲染成绿色的「良好」，那是一句没有证据的安全断言——与网关指标
// 「采不到就报不可判定，绝不补 0」同一条纪律，而这一格恰恰是全新部署的常态形状。
//
// 变异实跑：把 endpointDefense 的 `if len(dg.devices) > 0` 去掉（恒 intp(worst)），
// 本用例变红。
func TestEndpointDefenseRiskUnknownWithoutReports(t *testing.T) {
	st := openTestStore(t)
	ov, err := st.Overview(context.Background(), 0)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	ep := defenseOf(t, ov, "endpoint")
	if ep.Risk != nil {
		t.Fatalf("没有任何终端上报时风险分应缺席（不可判定），实得 %d", *ep.Risk)
	}
	if !strings.Contains(ep.Note, "不可判定") {
		t.Fatalf("口径说明要说清是「不可判定」而不是「零风险」，实得 %q", ep.Note)
	}
	// 另外两条线的风险分永远算得出来（users 状态 / 攻击源记账都是确定的事实）。
	if defenseOf(t, ov, "attack").Risk == nil || defenseOf(t, ov, "account").Risk == nil {
		t.Fatal("隐身防线与账号防线的风险分不该缺席——它们的判定材料恒在")
	}
}

// TestEndpointDefenseOrphanDevicesAreUnknown 台账里有、却没有任何合规判定的终端
// 必须单列成不可判定，不能悄悄消失。
//
// 变异实跑：把 devicesWithoutVerdict 的返回值改成恒 0，本用例变红。
func TestEndpointDefenseOrphanDevicesAreUnknown(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	// 先造一台有判定的终端（台账由 posture 自动登记），再手工插一台只有台账没有判定的。
	mkPosture(t, st, "li.fang", "FP-OK", "macOS", DisposalAllow, 0)
	if _, err := st.db.ExecContext(ctx,
		`INSERT INTO trusted_devices(id,account,fingerprint,name,platform,status,first_seen,last_seen,
		 approved_by,approved_at,approval_id,revoke_reason,asset_class,tags)
		 VALUES('d-orphan','li.fang','FP-NOREPORT','孤儿机','macOS',?,0,0,'',0,'','','enterprise','[]')`,
		DeviceStatusTrusted); err != nil {
		t.Fatalf("插台账行失败：%v", err)
	}
	ov, err := st.Overview(ctx, 0)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	ep := defenseOf(t, ov, "endpoint")
	if ep.Unknown != 1 {
		t.Fatalf("台账里那台没有判定的终端应计为不可判定 1 台，实得 %d", ep.Unknown)
	}
	if !strings.Contains(ep.Note, "授信台账") {
		t.Fatalf("口径说明要点名这批终端的出处，实得 %q", ep.Note)
	}
}

// TestPostureDigestNotTruncatedByListLimit 聚合不走 ListLimit(500) 那条查询。
//
// ★PostureReports() 带上限却**不告诉调用方被截断了**（终端合规页显式渲染 truncated，
// 聚合这条路径没有那个出口）。改造前两条防线正是从它取数：26 个账号 × 20 台就能
// 撑满 500 行，之后总览只统计"最近的那 500 台"，而页面上一个字都不说。
//
// 变异实跑：把 postureDigest 换回 `s.PostureReports(ctx)`，本用例变红。
func TestPostureDigestNotTruncatedByListLimit(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	// 造 ListLimit+ 台设备。单账号上限 20 台，故用足够多的账号铺开
	// （posture_reports 不与 users 表关联，账号名任取）。
	accounts := ListLimit/MaxDevicesPerAccount + 2
	want := 0
	for a := 0; a < accounts; a++ {
		for i := 0; i < MaxDevicesPerAccount; i++ {
			mkPosture(t, st, fmt.Sprintf("bulk-%03d", a), fmt.Sprintf("fp-%03d-%02d", a, i), "macOS", DisposalAllow, 0)
			want++
		}
	}
	if want <= ListLimit {
		t.Fatalf("用例只造出 %d 台，没越过 ListLimit=%d，测不出截断", want, ListLimit)
	}
	dg, err := st.postureDigest(ctx)
	if err != nil {
		t.Fatalf("postureDigest: %v", err)
	}
	if len(dg.devices) != want {
		t.Fatalf("聚合应看到全部 %d 台（不受 ListLimit=%d 截断），实得 %d", want, ListLimit, len(dg.devices))
	}
	// 终端防线的风险分也必须来自全量而不是最近的那 500 台。
	if len(dg.worstByAccount) != accounts {
		t.Fatalf("跨设备最差判定应覆盖全部 %d 个账号，实得 %d", accounts, len(dg.worstByAccount))
	}
}
