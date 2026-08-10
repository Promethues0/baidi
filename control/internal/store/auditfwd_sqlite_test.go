package store

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newFwdStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "fwd.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mustEntry(t *testing.T, st *SQLiteStore, event string) {
	t.Helper()
	if err := st.RecordAudit(context.Background(), AuditEntry{
		Time: time.Now().Format("2006-01-02 15:04:05"), Category: "admin",
		User: "admin", SrcIP: "10.0.0.1", Event: event, Verdict: "ok",
	}); err != nil {
		t.Fatalf("落审计失败: %v", err)
	}
}

func TestAuditForwardTarget_增删改查(t *testing.T) {
	st := newFwdStore(t)
	ctx := context.Background()

	rec, err := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{
		Name: "SOC syslog", Kind: "syslog", Enabled: true,
		Config: `{"host":"siem.corp.example","port":6514,"tls":true}`,
	})
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if !strings.HasPrefix(rec.ID, "af-") {
		t.Fatalf("应自动生成 id，实得 %q", rec.ID)
	}
	if rec.HasSecret || rec.Dropped != 0 || rec.Queued != 0 {
		t.Errorf("新建出口应无凭据无积压无丢弃：%+v", rec)
	}

	// 改名不动 last_* / dropped / start_audit_id（保存动作不许伪造发送状态）。
	if err := st.RecordAuditForwardResult(ctx, rec.ID, AuditForwardOK, "已投递 3 条", 1700000000); err != nil {
		t.Fatalf("记录结果失败: %v", err)
	}
	again, err := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{
		ID: rec.ID, Name: "SOC syslog（改名）", Kind: "syslog", Enabled: false, Config: rec.Config,
	})
	if err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	if again.Name != "SOC syslog（改名）" || again.Enabled {
		t.Errorf("改名/停用未生效：%+v", again)
	}
	if again.LastStatus != AuditForwardOK || again.LastOKAt != 1700000000 {
		t.Errorf("保存配置不得覆盖上次发送结果：%+v", again)
	}
	if again.StartAuditID != rec.StartAuditID {
		t.Errorf("保存配置不得重置 start_audit_id：%d → %d", rec.StartAuditID, again.StartAuditID)
	}

	// 失败结果不碰 last_ok_at：运维就是靠"上次成功距今多久"判断外送是不是断了。
	if err := st.RecordAuditForwardResult(ctx, rec.ID, AuditForwardFail, "连接被拒", 1700000900); err != nil {
		t.Fatalf("记录失败结果: %v", err)
	}
	after, _, _ := st.AuditForwardTargetByID(ctx, rec.ID)
	if after.LastOKAt != 1700000000 || after.LastAt != 1700000900 || after.LastStatus != AuditForwardFail {
		t.Errorf("失败不该覆盖 last_ok_at：%+v", after)
	}
}

// 审计落库即入队：每个**启用中**的出口各一行；停用的出口不入队。
func TestAuditForwardEnqueueOnlyForEnabledTargets(t *testing.T) {
	st := newFwdStore(t)
	ctx := context.Background()
	on, _ := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{Name: "on", Kind: "syslog", Enabled: true})
	off, _ := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{Name: "off", Kind: "syslog", Enabled: false})

	mustEntry(t, st, "第一条")
	mustEntry(t, st, "第二条")

	items, err := st.ClaimAuditForwardBatch(ctx, on.ID, time.Now().Unix(), 100)
	if err != nil {
		t.Fatalf("取批失败: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("启用中的出口应有 2 条待发，实得 %d", len(items))
	}
	// 载荷必须是审计表里那一条本身：链的 seq/mac 一并带出去，且顺序 = 落库序。
	if items[0].Entry.Event != "第一条" || items[1].Entry.Event != "第二条" {
		t.Errorf("队列顺序应为落库序：%v", items)
	}
	for _, it := range items {
		if it.Entry.Seq == 0 || it.Entry.MAC == "" {
			t.Fatalf("外送载荷必须带链 seq/mac（这是 SIEM 侧能独立验真的依据）：%+v", it.Entry)
		}
	}
	if items[1].Entry.Seq != items[0].Entry.Seq+1 {
		t.Errorf("seq 应连续：%d → %d", items[0].Entry.Seq, items[1].Entry.Seq)
	}

	offItems, _ := st.ClaimAuditForwardBatch(ctx, off.ID, time.Now().Unix(), 100)
	if len(offItems) != 0 {
		t.Fatalf("停用的出口不该入队，实得 %d 条", len(offItems))
	}

	// 停用之后新产生的审计也不入队（"停用外送后不再入队"）。
	if _, err := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{
		ID: on.ID, Name: on.Name, Kind: on.Kind, Enabled: false, Config: on.Config}); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	mustEntry(t, st, "停用后的一条")
	items2, _ := st.ClaimAuditForwardBatch(ctx, on.ID, time.Now().Unix(), 100)
	if len(items2) != 2 {
		t.Fatalf("停用后不该再入队（原有积压保留），期望仍是 2 条，实得 %d", len(items2))
	}
	if n, _ := st.auditForwardEnabledCount(ctx); n != 0 {
		t.Fatalf("此刻不该有启用中的出口，实得 %d", n)
	}
}

// 历史不重发：出口建立**之前**的审计一条都不进队列。
//
// ★这正是本功能选「独立队列表」而不是「audit_log 加 forwarded 列」的原因：
// 加列那条路要靠一次性回填把既有行标成已处理，漏了回填就会在开启外送的那一刻
// 把 180 天历史整段重发。这里的"不重发"是结构性的，不依赖任何回填。
func TestAuditForwardDoesNotResendHistory(t *testing.T) {
	st := newFwdStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		mustEntry(t, st, fmt.Sprintf("历史第 %d 条", i))
	}
	tgt, err := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{Name: "siem", Kind: "syslog", Enabled: true})
	if err != nil {
		t.Fatalf("建出口失败: %v", err)
	}
	items, _ := st.ClaimAuditForwardBatch(ctx, tgt.ID, time.Now().Unix(), 100)
	if len(items) != 0 {
		t.Fatalf("新建出口不得补发历史，实得 %d 条", len(items))
	}
	if tgt.StartAuditID == 0 {
		t.Error("应记下建立时的审计水位，页面据此如实说明历史不会补发")
	}
	mustEntry(t, st, "新的一条")
	items, _ = st.ClaimAuditForwardBatch(ctx, tgt.ID, time.Now().Unix(), 100)
	if len(items) != 1 || items[0].Entry.Event != "新的一条" {
		t.Fatalf("只应外送配置生效之后的审计，实得 %+v", items)
	}
}

// 队列上界与丢弃计数：满了丢**新**保旧，丢弃累计可见，审计本身照落不误。
func TestAuditForwardQueueBoundAndDropCount(t *testing.T) {
	st := newFwdStore(t)
	ctx := context.Background()
	st.SetAuditForwardQueueMax(3)
	if st.AuditForwardQueueMax() != 3 {
		t.Fatalf("上界注入未生效：%d", st.AuditForwardQueueMax())
	}
	tgt, _ := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{Name: "siem", Kind: "syslog", Enabled: true})

	for i := 0; i < 5; i++ {
		mustEntry(t, st, fmt.Sprintf("第 %d 条", i))
	}
	items, _ := st.ClaimAuditForwardBatch(ctx, tgt.ID, time.Now().Unix(), 100)
	if len(items) != 3 {
		t.Fatalf("队列应被上界卡住在 3 条，实得 %d", len(items))
	}
	// 丢新保旧：留下的是连续的最早三条，SIEM 侧的 seq 仍然连续。
	if items[0].Entry.Event != "第 0 条" || items[2].Entry.Event != "第 2 条" {
		t.Errorf("应丢新保旧（留下连续的最早一段）：%v", items)
	}
	after, _, _ := st.AuditForwardTargetByID(ctx, tgt.ID)
	if after.Dropped != 2 {
		t.Fatalf("丢弃计数应为 2（且必须可见），实得 %d", after.Dropped)
	}
	if after.Queued != 3 {
		t.Fatalf("积压数应为 3，实得 %d", after.Queued)
	}
	// 审计本身一条都不能少——外送丢了不等于审计丢了。
	b, err := st.Audit(ctx)
	if err != nil {
		t.Fatalf("读审计失败: %v", err)
	}
	var seen int
	for _, l := range b.Logs {
		if strings.HasPrefix(l.Event, "第 ") {
			seen++
		}
	}
	if seen != 5 {
		t.Fatalf("审计必须全部落库（5 条），实得 %d", seen)
	}
	// 上界置 0 落回默认值，而不是"关闭上界"。
	st.SetAuditForwardQueueMax(0)
	if st.AuditForwardQueueMax() != DefaultForwardQueueMax {
		t.Fatalf("非正上界应落回默认值，实得 %d", st.AuditForwardQueueMax())
	}
}

// 失败留队 + 退避 + 计次；成功才出队。一条都不丢。
func TestAuditForwardRetryKeepsItems(t *testing.T) {
	st := newFwdStore(t)
	ctx := context.Background()
	tgt, _ := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{Name: "siem", Kind: "http", Enabled: true})
	mustEntry(t, st, "要送的一条")

	now := time.Now().Unix()
	items, _ := st.ClaimAuditForwardBatch(ctx, tgt.ID, now, 100)
	if len(items) != 1 {
		t.Fatalf("应有 1 条待发，实得 %d", len(items))
	}
	// 模拟一次失败：留队 + 推迟 60s。
	if err := st.RetryAuditForwardBatch(ctx, []int64{items[0].ID}, now+60, "对端 502"); err != nil {
		t.Fatalf("留队失败: %v", err)
	}
	if got, _ := st.ClaimAuditForwardBatch(ctx, tgt.ID, now, 100); len(got) != 0 {
		t.Fatal("退避期内不该被取出")
	}
	got, _ := st.ClaimAuditForwardBatch(ctx, tgt.ID, now+61, 100)
	if len(got) != 1 {
		t.Fatalf("退避到期后应重新可取，实得 %d", len(got))
	}
	if got[0].Attempts != 1 {
		t.Errorf("失败次数应计为 1，实得 %d", got[0].Attempts)
	}
	if got[0].Entry.Event != "要送的一条" {
		t.Errorf("留队记录内容不应改变：%+v", got[0].Entry)
	}
	// 成功才出队。
	if err := st.AckAuditForwardBatch(ctx, []int64{got[0].ID}); err != nil {
		t.Fatalf("出队失败: %v", err)
	}
	if rest, _ := st.ClaimAuditForwardBatch(ctx, tgt.ID, now+61, 100); len(rest) != 0 {
		t.Fatalf("成功后应出队，实得 %d", len(rest))
	}
}

// 删除出口连同凭据与积压一起清：孤儿密文会被同 id 重建的出口静默继承，
// 孤儿队列则永远没人消费、白占上界名额把一个还活着的出口挤到开始丢弃。
func TestDeleteAuditForwardTargetPurgesQueueAndSecret(t *testing.T) {
	st := newFwdStore(t)
	ctx := context.Background()
	tgt, _ := st.SaveAuditForwardTarget(ctx, AuditForwardTarget{Name: "siem", Kind: "http", Enabled: true})
	if err := st.SaveAuditForwardSecret(ctx, AuditForwardSecret{
		TargetID: tgt.ID, Nonce: []byte("n"), Cipher: []byte("c"), Fingerprint: "abcd1234"}); err != nil {
		t.Fatalf("存凭据失败: %v", err)
	}
	mustEntry(t, st, "积压一条")

	if err := st.DeleteAuditForwardTarget(ctx, tgt.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, found, _ := st.AuditForwardTargetByID(ctx, tgt.ID); found {
		t.Fatal("出口应已删除")
	}
	if _, found, _ := st.AuditForwardSecret(ctx, tgt.ID); found {
		t.Fatal("凭据应随出口一起删除（同 id 重建会静默继承）")
	}
	if items, _ := st.ClaimAuditForwardBatch(ctx, tgt.ID, time.Now().Unix(), 100); len(items) != 0 {
		t.Fatalf("积压应随出口一起清理，实得 %d 条", len(items))
	}
	// 凭据缺少 target id（AAD）时必须拒绝写入。
	if err := st.SaveAuditForwardSecret(ctx, AuditForwardSecret{Nonce: []byte("n")}); err == nil {
		t.Fatal("空 target id 应被拒绝（AAD 就是它）")
	}
}

// 无出口时审计照常落库、队列为空（零配置路径不受影响）。
func TestRecordAuditWithoutTargets(t *testing.T) {
	st := newFwdStore(t)
	ctx := context.Background()
	mustEntry(t, st, "没有外送出口时的一条")
	res, err := st.VerifyAuditChain(ctx)
	if err != nil || !res.OK {
		t.Fatalf("防篡改链应完好：%+v %v", res, err)
	}
	var n int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_forward_queue`).Scan(&n); err != nil {
		t.Fatalf("查队列失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("没有出口就不该有队列行，实得 %d", n)
	}
}
