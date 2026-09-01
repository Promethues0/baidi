package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// 注意：全新库 seed() 会经 RecordAudit 灌 8 条种子日志（已入链）。
// 用例一律以「基线 + 增量」写断言，不与种子条数硬耦合。

func openAuditStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mustRecord(t *testing.T, st *SQLiteStore, ts, category, actor, ip, event, verdict string) {
	t.Helper()
	if err := st.RecordAudit(context.Background(), AuditEntry{
		Time: ts, Category: category, User: actor, SrcIP: ip, Event: event, Verdict: verdict,
	}); err != nil {
		t.Fatalf("record audit: %v", err)
	}
}

func mustVerify(t *testing.T, st *SQLiteStore) AuditVerifyResult {
	t.Helper()
	res, err := st.VerifyAuditChain(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

func maxSeq(t *testing.T, st *SQLiteStore) int64 {
	t.Helper()
	var n int64
	if err := st.db.QueryRow(`SELECT COALESCE(MAX(seq),0) FROM audit_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// 正常链：连续落库后全链校验通过，seq 连续递增。
func TestAuditChainVerifyOK(t *testing.T) {
	st := openAuditStore(t)
	base := mustVerify(t, st)
	if !base.OK {
		t.Fatalf("种子链就应通过: %+v", base)
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	for i, ev := range []string{"管理员登录成功", "保存受控资源「res-a」", "拒发敲门令牌"} {
		mustRecord(t, st, now, []string{"auth", "admin", "security"}[i], "admin", "10.0.0.9", ev, "ok")
	}
	res := mustVerify(t, st)
	if !res.OK || res.Checked != base.Checked+3 || res.BrokenAt != 0 {
		t.Fatalf("正常链应通过且 checked=+3: base %+v now %+v", base, res)
	}
	if got := maxSeq(t, st); got != int64(base.Checked)+3 {
		t.Fatalf("seq 应连续到 %d, got %d", base.Checked+3, got)
	}
}

// 篡改检测：手工 UPDATE 中间一行后，verify 指出断点 seq。
func TestAuditChainDetectsTamper(t *testing.T) {
	st := openAuditStore(t)
	now := time.Now().Format("2006-01-02 15:04:05")
	for i := 0; i < 4; i++ {
		mustRecord(t, st, now, "admin", "admin", "10.0.0.9", "操作", "ok")
	}
	target := maxSeq(t, st) - 2
	if _, err := st.db.Exec(`UPDATE audit_log SET event='洗白后的事件' WHERE seq=?`, target); err != nil {
		t.Fatal(err)
	}
	res := mustVerify(t, st)
	if res.OK || res.BrokenAt != target || int64(res.Checked) != target-1 {
		t.Fatalf("篡改 seq=%d 应在该行断链: %+v", target, res)
	}
}

// 抽行检测：删掉中间一行同样断链（后继行的 prev 对不上）。
func TestAuditChainDetectsDeletion(t *testing.T) {
	st := openAuditStore(t)
	now := time.Now().Format("2006-01-02 15:04:05")
	for i := 0; i < 3; i++ {
		mustRecord(t, st, now, "admin", "admin", "10.0.0.9", "操作", "ok")
	}
	target := maxSeq(t, st) - 1
	if _, err := st.db.Exec(`DELETE FROM audit_log WHERE seq=?`, target); err != nil {
		t.Fatal(err)
	}
	res := mustVerify(t, st)
	if res.OK || res.BrokenAt != target+1 {
		t.Fatalf("抽掉 seq=%d 应在 seq=%d 处断链: %+v", target, target+1, res)
	}
}

// 旧库回填：模拟补列前的存量行（mac 为 NULL），回填补算全链且幂等。
func TestAuditChainBackfillLegacyRows(t *testing.T) {
	st := openAuditStore(t)
	base := mustVerify(t, st)
	// 模拟旧库存量行：绕开 RecordAudit 直插（无 seq/mac）
	for i := 0; i < 3; i++ {
		if _, err := st.db.Exec(`INSERT INTO audit_log(ts,category,actor,src_ip,event,verdict) VALUES(?,?,?,?,?,?)`,
			"2026-01-01 08:00:00", "auth", "legacy", "10.1.1.1", "历史登录", "ok"); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.backfillAuditChain(); err != nil {
		t.Fatal(err)
	}
	res := mustVerify(t, st)
	if !res.OK || res.Checked != base.Checked+3 {
		t.Fatalf("回填后全链应通过: base %+v now %+v", base, res)
	}
	// 幂等：再跑一遍不改已有 mac
	var mac1 string
	if err := st.db.QueryRow(`SELECT mac FROM audit_log WHERE seq=1`).Scan(&mac1); err != nil {
		t.Fatal(err)
	}
	if err := st.backfillAuditChain(); err != nil {
		t.Fatal(err)
	}
	var mac2 string
	if err := st.db.QueryRow(`SELECT mac FROM audit_log WHERE seq=1`).Scan(&mac2); err != nil {
		t.Fatal(err)
	}
	if mac1 != mac2 {
		t.Fatal("回填应幂等：已有 mac 不得被改写")
	}
	// 回填后新增行接在链尾
	mustRecord(t, st, time.Now().Format("2006-01-02 15:04:05"), "admin", "admin", "10.0.0.9", "新操作", "ok")
	if res := mustVerify(t, st); !res.OK || res.Checked != base.Checked+4 {
		t.Fatalf("回填后追加应续链: %+v", res)
	}
}

// 留存轮转：清理超期行后 verify 仍通过（锚点接续），后续落库继续成链。
func TestAuditPurgeKeepsChainVerifiable(t *testing.T) {
	st := openAuditStore(t)
	ctx := context.Background()
	base := mustVerify(t, st)
	// 两条一年前的 + 两条现在的
	for i := 0; i < 2; i++ {
		mustRecord(t, st, "2025-01-01 08:00:00", "auth", "old", "10.1.1.1", "陈年记录", "ok")
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	for i := 0; i < 2; i++ {
		mustRecord(t, st, now, "admin", "admin", "10.0.0.9", "近期操作", "ok")
	}
	// 划界按链序：过期行之前的整段（含更早的种子行）一起清掉
	n, err := st.PurgeExpiredAudit(ctx, 180)
	if err != nil || n != int64(base.Checked)+2 {
		t.Fatalf("应清理 %d 条（种子+陈年）, got %d err %v", base.Checked+2, n, err)
	}
	res := mustVerify(t, st)
	if !res.OK || res.Checked != 2 {
		t.Fatalf("清理后 verify 应通过（从锚点起算）: %+v", res)
	}
	// 清理后继续落库，链不断
	mustRecord(t, st, now, "security", "admin", "10.0.0.9", "清理后的新记录", "ok")
	if res := mustVerify(t, st); !res.OK || res.Checked != 3 {
		t.Fatalf("清理后追加应续链: %+v", res)
	}
	// 全部清空的极端情形：锚点顶上，追加照常成链
	// （直接 UPDATE ts 只为构造「全表过期」；清空后链从锚点重新开始，不受此破坏影响）
	if _, err := st.db.Exec(`UPDATE audit_log SET ts='2025-01-01 08:00:00'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PurgeExpiredAudit(ctx, 180); err != nil {
		t.Fatal(err)
	}
	mustRecord(t, st, now, "admin", "admin", "10.0.0.9", "空表后的首条", "ok")
	if res := mustVerify(t, st); !res.OK || res.Checked != 1 {
		t.Fatalf("空表后追加应从锚点续链: %+v", res)
	}
	// days=0 不清理
	if n, err := st.PurgeExpiredAudit(ctx, 0); err != nil || n != 0 {
		t.Fatalf("days=0 应不清理, got %d err %v", n, err)
	}
}

// 导出：按类别与时间窗过滤，顺序为落库序（种子行 ts 在窗外，不干扰断言）。
func TestAuditExportFilters(t *testing.T) {
	st := openAuditStore(t)
	ctx := context.Background()
	mustRecord(t, st, "2026-08-01 10:00:00", "auth", "u1", "10.1.1.1", "登录", "ok")
	mustRecord(t, st, "2026-08-02 10:00:00", "admin", "adm", "10.0.0.9", "改配置", "ok")
	mustRecord(t, st, "2026-08-03 10:00:00", "auth", "u2", "10.1.1.2", "再登录", "fail")

	collect := func(category, from, to string) []AuditEntry {
		var out []AuditEntry
		if err := st.ExportAudit(ctx, AuditQuery{Category: category, From: from, To: to}, func(e AuditEntry) error {
			out = append(out, e)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := collect("auth", "2026-08-01 00:00:00", "2026-08-03 23:59:59"); len(got) != 2 || got[0].User != "u1" || got[1].User != "u2" {
		t.Fatalf("category=auth+时间窗应 2 条按落库序: %+v", got)
	}
	if got := collect("", "2026-08-02 00:00:00", "2026-08-02 23:59:59"); len(got) != 1 || got[0].Category != "admin" {
		t.Fatalf("时间窗应只含 8/2 那条: %+v", got)
	}
	all := collect("", "", "")
	if len(all) < 3 || all[len(all)-1].User != "u2" {
		t.Fatalf("无条件应含全部（含种子）且以最后落库行收尾: %d 条", len(all))
	}
}

// 检索与导出必须**同构**：同一组条件，两边选出的行必须一模一样。
//
// ★这条钉的是一个已经发生过的形态：ExportAudit 自己拼了一份 WHERE，只认
// category/from/to 三维，账号与源 IP 两维压根传不进来——而页面上刚筛过的正是那两维。
// 症状是「屏幕上筛出 12 条、导出的 CSV 里是 8 万条」，两侧都不报错，
// 而管理员会以为这份 CSV 就是他刚看到的那些行，拿去交差。
// 现在两者共用 auditWhere；这条测试保证它们不会再分家。
func TestAuditExportMatchesSearch(t *testing.T) {
	st := openAuditStore(t)
	ctx := context.Background()
	mustRecord(t, st, "2026-08-01 10:00:00", "auth", "u1", "10.1.1.1", "登录成功", "ok")
	mustRecord(t, st, "2026-08-01 11:00:00", "auth", "u1", "10.1.1.1", "登录失败", "fail")
	mustRecord(t, st, "2026-08-02 10:00:00", "admin", "adm", "10.0.0.9", "改配置", "ok")
	mustRecord(t, st, "2026-08-03 10:00:00", "auth", "u2", "10.1.1.2", "再登录", "fail")
	mustRecord(t, st, "2026-08-04 10:00:00", "security", "u1", "203.0.113.7", "拒绝越权", "deny")

	cases := []struct {
		name string
		q    AuditQuery
	}{
		{"不限", AuditQuery{}},
		{"按类别", AuditQuery{Category: "auth"}},
		{"按账号", AuditQuery{Actor: "u1"}},
		{"按源 IP 前缀", AuditQuery{SrcIP: "10.1."}},
		{"按关键词", AuditQuery{Keyword: "登录"}},
		{"按日期区间", AuditQuery{From: "2026-08-02", To: "2026-08-03"}},
		{"账号 + 类别 + 区间", AuditQuery{Actor: "u1", Category: "auth", From: "2026-08-01", To: "2026-08-01"}},
		{"空结果", AuditQuery{Actor: "no-such-user"}},
	}
	for _, c := range cases {
		// 检索侧：Limit 给足，避免分页上限干扰比对。
		sq := c.q
		sq.Limit = 500
		found, total, err := st.SearchAudit(ctx, sq)
		if err != nil {
			t.Fatalf("%s：SearchAudit: %v", c.name, err)
		}
		var exported []AuditEntry
		if err := st.ExportAudit(ctx, c.q, func(e AuditEntry) error {
			exported = append(exported, e)
			return nil
		}); err != nil {
			t.Fatalf("%s：ExportAudit: %v", c.name, err)
		}
		if len(exported) != total {
			t.Fatalf("%s：导出 %d 行，检索说共 %d 行——两侧 WHERE 已经分家",
				c.name, len(exported), total)
		}
		// 逐条比对（顺序不同：检索是新→旧，导出是落库序），按 seq 归一。
		seqOf := func(rows []AuditEntry) map[int64]bool {
			m := map[int64]bool{}
			for _, e := range rows {
				m[e.Seq] = true
			}
			return m
		}
		gotS, gotE := seqOf(found), seqOf(exported)
		if len(gotS) != len(gotE) {
			t.Fatalf("%s：两侧行数不一致 %d vs %d", c.name, len(gotS), len(gotE))
		}
		for seq := range gotS {
			if !gotE[seq] {
				t.Fatalf("%s：检索选中的第 %d 条不在导出结果里", c.name, seq)
			}
		}
	}
}

// 时间边界：`From`/`To` 既可能是「YYYY-MM-DD」（列表页），也可能是补好时分秒的
// 完整时间戳（导出 handler 先过 normDayBound）。两种都要**按原意**生效。
//
// ★两边都补的话会拼出 "2026-08-01 10:00:00 00:00:00"——它在字符串序上**大于**
// "2026-08-01 10:00:00"，于是「从这一刻起」会把恰好落在这一秒的行排除掉。
// 差一条记录，没有任何报错，而审计导出的用途正是"把某一时刻起的全部记录交出去"。
func TestAuditWhereHandlesBothTimeForms(t *testing.T) {
	st := openAuditStore(t)
	ctx := context.Background()
	mustRecord(t, st, "2026-08-01 09:59:59", "auth", "u0", "10.1.1.1", "早一秒", "ok")
	mustRecord(t, st, "2026-08-01 10:00:00", "auth", "u1", "10.1.1.1", "正好这一秒", "ok")
	mustRecord(t, st, "2026-08-01 10:00:01", "auth", "u2", "10.1.1.2", "晚一秒", "ok")

	count := func(q AuditQuery) []string {
		var evs []string
		if err := st.ExportAudit(ctx, q, func(e AuditEntry) error {
			evs = append(evs, e.Event)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return evs
	}

	// 库里有种子审计行，所以断言按**成员归属**判而不是数总数。
	has := func(evs []string, want string) bool {
		for _, e := range evs {
			if e == want {
				return true
			}
		}
		return false
	}

	// ① 完整时间戳的下界是**闭区间**：恰好落在这一秒的那行必须在内，早一秒的必须在外。
	got := count(AuditQuery{From: "2026-08-01 10:00:00", Keyword: "秒"})
	if !has(got, "正好这一秒") {
		t.Fatalf("From 为完整时间戳时必须含边界那一秒——两边都补时分秒会把它排除掉，实得 %v", got)
	}
	if has(got, "早一秒") {
		t.Fatalf("下界之前的行不该在内，实得 %v", got)
	}
	// ② 完整时间戳的上界同样是闭区间。
	got = count(AuditQuery{To: "2026-08-01 10:00:00", Keyword: "秒"})
	if !has(got, "正好这一秒") {
		t.Fatalf("To 为完整时间戳时必须含边界那一秒，实得 %v", got)
	}
	if has(got, "晚一秒") {
		t.Fatalf("上界之后的行不该在内，实得 %v", got)
	}
	// ③ 只给日期时按整日展开（与列表页同口径）：三条都在。
	got = count(AuditQuery{From: "2026-08-01", To: "2026-08-01", Keyword: "秒"})
	for _, want := range []string{"早一秒", "正好这一秒", "晚一秒"} {
		if !has(got, want) {
			t.Fatalf("只给日期应覆盖整日，缺 %q，实得 %v", want, got)
		}
	}
	// ④ 反向：前一天不该有这三条中的任何一条（否则上面三条恒真也说明不了什么）。
	got = count(AuditQuery{To: "2026-07-31", Keyword: "秒"})
	for _, no := range []string{"早一秒", "正好这一秒", "晚一秒"} {
		if has(got, no) {
			t.Fatalf("7 月 31 日之前不该出现 %q，实得 %v", no, got)
		}
	}
}
