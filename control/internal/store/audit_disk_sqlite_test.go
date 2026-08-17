package store

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── wave8 行动 6：按磁盘水位轮转审计（FR-AUDIT-10 的另一半）──
//
// 这一组守的是文件头 ①②③ 那三条「按 PRD 字面实现就会坏」的地方。

func openDiskStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "audit-disk.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// seedDays 每天灌 n 条审计，最早的一天在 daysAgo 天前。
func seedDays(t *testing.T, st *SQLiteStore, daysAgo, n int) {
	t.Helper()
	ctx := context.Background()
	for d := daysAgo; d >= 0; d-- {
		day := time.Now().AddDate(0, 0, -d)
		for i := 0; i < n; i++ {
			e := AuditEntry{
				Time:     day.Format("2006-01-02") + fmt.Sprintf(" %02d:00:00", i%24),
				Category: "admin", User: "tester", SrcIP: "127.0.0.1",
				Event:   fmt.Sprintf("第 %d 天第 %d 条", d, i),
				Verdict: "ok",
			}
			if err := st.RecordAudit(ctx, e); err != nil {
				t.Fatalf("灌审计失败：%v", err)
			}
		}
	}
}

// todayCount 当天的审计行数（种子库自带若干行，故一切期望值都从数据里现算，
// 不写死——写死的话用例是在断言"种子有几条"，而不是在断言被测行为）。
func todayCount(t *testing.T, st *SQLiteStore) int64 {
	t.Helper()
	var n int64
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE substr(ts,1,10)>=?`,
		time.Now().Format("2006-01-02")).Scan(&n); err != nil {
		t.Fatalf("计数失败：%v", err)
	}
	return n
}

func rowCount(t *testing.T, st *SQLiteStore) int64 {
	t.Helper()
	var n int64
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatalf("计数失败：%v", err)
	}
	return n
}

// TestPurgeByDiskDisabledByDefault 未配置阈值 = 不做任何事。
// 自动删审计是破坏性策略，必须由部署方明确要求。
func TestPurgeByDiskDisabledByDefault(t *testing.T) {
	st := openDiskStore(t)
	seedDays(t, st, 5, 20)
	before := rowCount(t, st)
	r, err := st.PurgeAuditByDisk(context.Background(), 0)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Enabled || r.Deleted != 0 || rowCount(t, st) != before {
		t.Fatalf("未配置阈值不该删任何东西：%+v", r)
	}
}

// TestPurgeByDiskJudgesAuditShareNotFilesystem 判据是**审计库占了多大**，
// 不是文件系统满没满（文件头 ①）。
//
// ★这是本组最要紧的一条：一台盘被别的东西占满的机器上，按文件系统占用率触发
// 会把全部审计历史删光，而磁盘依旧是满的——付出全部证据，一个字节没换回来。
// 测试里审计库是个几百 KB 的小文件，占文件系统远不到 1%，所以哪怕真实磁盘
// 已经用了 90%，阈值 1% 也**不该**触发。
func TestPurgeByDiskJudgesAuditShareNotFilesystem(t *testing.T) {
	st := openDiskStore(t)
	seedDays(t, st, 10, 50)
	before := rowCount(t, st)

	d, err := st.AuditDiskStat(context.Background())
	if err != nil {
		t.Fatalf("水位实测失败：%v", err)
	}
	if !d.FSSupported {
		t.Skip("当前平台测不出文件系统容量")
	}
	if d.UsedPct() < 1 {
		t.Skip("这台机器的文件系统几乎是空的，本用例的对照失去意义")
	}
	// 阈值取 1%：文件系统占用率**远超**它（上面刚断言 >=1），
	// 而审计库自占率是千分之几。判据用错的实现会在这里把库删空。
	r, err := st.PurgeAuditByDisk(context.Background(), 1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r.Triggered || r.Deleted != 0 {
		t.Fatalf("审计库自占率远低于 1%%，不该触发（判据串成文件系统占用率了）：%+v", r)
	}
	if rowCount(t, st) != before {
		t.Fatalf("一行都不该删，剩 %d / 原 %d", rowCount(t, st), before)
	}
	if r.UsedPct > 5 {
		t.Errorf("UsedPct 应为审计库自占率（很小），得到 %d%%——像是填成了文件系统占用率", r.UsedPct)
	}
}

// synthStat 造一份水位读数：让审计库"占"文件系统 pct%，共 rows 行。
// 真实机器上这个比例永远是千分之几，够不到最小阈值 1%——
// 不注入的话，触发之后的整段逻辑在任何一台正常机器上都跑不到。
func synthStat(rows int64, pct int) AuditDiskStat {
	const dbBytes = 1 << 20 // 1 MiB
	return AuditDiskStat{
		Rows: rows, DBBytes: dbBytes, FSSupported: true,
		FSTotalBytes: uint64(dbBytes * 100 / int64(pct)),
	}
}

// TestPurgeByDiskKeepsToday 删到只剩当天就停（文件头 ③）。
//
// 此刻正在发生的事，其记录不该是最先被删的那一段。造一个「怎么删都还超标」的
// 水位（阈值 1%，自占 90%），按字面实现会把库删空。
func TestPurgeByDiskKeepsToday(t *testing.T) {
	st := openDiskStore(t)
	seedDays(t, st, 4, 25)
	total, today := rowCount(t, st), todayCount(t, st)
	if today == 0 || today == total {
		t.Fatalf("夹具不成立：需要既有当天也有历史（今天 %d / 共 %d）", today, total)
	}

	r, err := st.purgeByDiskStat(context.Background(), synthStat(total, 90), 1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !r.Triggered {
		t.Fatalf("自占 90%% 超阈值 1%%，必须触发：%+v", r)
	}
	left := rowCount(t, st)
	if left == 0 {
		t.Fatal("库被删空了——当天审计是正在发生的取证材料，必须留下")
	}
	// 恰好剩下当天：历史一天不留（阈值怎么都够不着），当天一条不删。
	if left != today {
		t.Fatalf("应恰好剩下当天那 %d 条，剩 %d", today, left)
	}
	if r.Deleted != total-today {
		t.Fatalf("应删掉全部 %d 条历史，得到 %d", total-today, r.Deleted)
	}
	if !strings.Contains(r.Note, "只剩当天") {
		t.Fatalf("停手的原因要如实回给审计，得到 %q", r.Note)
	}
	// 轮转后链仍可校验（与按天共用同一处落锚点实现）。
	res, err := st.VerifyAuditChain(context.Background())
	if err != nil || !res.OK {
		t.Fatalf("按水位回收后链断了：%+v err=%v", res, err)
	}
}

// TestPurgeByDiskStopsAtTarget 达到目标行数即停，不多删一天（文件头 ②）。
//
// ★不能"删一天→重量文件大小→还超→再删"：SQLite 不 VACUUM 文件根本不变小，
// 那种写法会一路删到一行不剩。这里验的是按目标行数收敛。
func TestPurgeByDiskStopsAtTarget(t *testing.T) {
	st := openDiskStore(t)
	seedDays(t, st, 5, 20)
	total, today := rowCount(t, st), todayCount(t, st)

	// 自占 4%、阈值 2% → 目标行数 = 总行数的一半。
	r, err := st.purgeByDiskStat(context.Background(), synthStat(total, 4), 2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !r.Triggered {
		t.Fatalf("必须触发：%+v", r)
	}
	target := total / 2
	left := rowCount(t, st)
	if left > target {
		t.Fatalf("没删到目标行数：剩 %d > 目标 %d", left, target)
	}
	// ★与「删到文件变小为止」那个坏实现的分水岭：它会一路删到只剩当天（或一行不剩），
	// 因为 SQLite 不 VACUUM 文件根本不缩，条件永远不满足。
	if left <= today {
		t.Fatalf("删过头了（一路删到只剩当天）：剩 %d，当天有 %d——目标行数没起作用", left, today)
	}
	if r.Note != "" {
		t.Fatalf("正常收敛不该带停止原因，得到 %q", r.Note)
	}
	if r.Deleted != total-left || r.Days == 0 {
		t.Fatalf("回报与实际不符：deleted=%d days=%d，实删 %d", r.Deleted, r.Days, total-left)
	}
}

// TestPurgeByDiskUnmeasurableDeletesNothing 水位测不出来时一行都不删。
// 判不了水位就去删证据，是拿确定的损失赌一个不确定的收益。
//
// ★用注入的读数而不是靠平台差异：靠平台的话这条在 Linux CI 上永远 skip，
// 等于没有这条用例。
func TestPurgeByDiskUnmeasurableDeletesNothing(t *testing.T) {
	st := openDiskStore(t)
	seedDays(t, st, 3, 10)
	before := rowCount(t, st)
	for _, d := range []AuditDiskStat{
		{Rows: before, DBBytes: 1 << 20, FSSupported: false, FSTotalBytes: 1 << 21}, // 平台无 Statfs
		{Rows: before, DBBytes: 1 << 20, FSSupported: true, FSTotalBytes: 0},        // 容量读成 0
	} {
		r, err := st.purgeByDiskStat(context.Background(), d, 1)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Measurable || r.Triggered || r.Deleted != 0 {
			t.Fatalf("不可判定时不该删：%+v", r)
		}
		if rowCount(t, st) != before {
			t.Fatalf("一行都不该删，剩 %d / 原 %d", rowCount(t, st), before)
		}
	}
}

// TestPurgeByDiskKeepsChainIntact 按水位回收与按天留存**共用**同一处划界+落锚点实现，
// 轮转后全链仍可校验。各写一份的话总有一条会忘记落锚点，
// 而症状是 verify 把首条留存行报成篡改。
func TestPurgeByDiskKeepsChainIntact(t *testing.T) {
	st := openDiskStore(t)
	seedDays(t, st, 6, 30)
	if _, err := st.PurgeExpiredAudit(context.Background(), 3); err != nil {
		t.Fatalf("按天清理失败：%v", err)
	}
	res, err := st.VerifyAuditChain(context.Background())
	if err != nil {
		t.Fatalf("链校验失败：%v", err)
	}
	if !res.OK {
		t.Fatalf("轮转后链断了：%+v", res)
	}
	if res.Checked == 0 {
		t.Fatal("一条都没校验到，用例失去意义")
	}
}
