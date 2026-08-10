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
		if err := st.ExportAudit(ctx, category, from, to, func(e AuditEntry) error {
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
