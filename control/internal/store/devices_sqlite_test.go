package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// EnrollDevice 幂等：同 (账号,指纹) 第二次只刷新 last_seen 与平台，不新增行、不改状态。
func TestEnrollDeviceIdempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	d1, created, err := s.EnrollDevice(ctx, "Li.Fang", "FP-1", "MBP", "macOS", DeviceBindApproval)
	if err != nil || !created {
		t.Fatalf("首次登记应 created: %v %v", created, err)
	}
	if d1.Account != "li.fang" {
		t.Fatalf("账号应规范化成小写（与令牌主体、posture_reports.user 同键）: %q", d1.Account)
	}
	if d1.Status != DeviceStatusPending || d1.ApprovalID == "" {
		t.Fatalf("审批绑定模式首登应 pending + 生成审批单: %+v", d1)
	}

	if _, _, err := s.SetDeviceStatus(ctx, d1.ID, DeviceStatusTrusted, "admin", ""); err != nil {
		t.Fatalf("批准失败: %v", err)
	}
	d2, created, err := s.EnrollDevice(ctx, "li.fang", "FP-1", "改个名", "macOS", DeviceBindApproval)
	if err != nil || created {
		t.Fatalf("二次登记不应 created: %v %v", created, err)
	}
	if d2.ID != d1.ID {
		t.Fatal("二次登记不得新建行")
	}
	if d2.Status != DeviceStatusTrusted {
		t.Fatalf("二次登记不得改状态: %v", d2.Status)
	}
	if d2.Name != "MBP" {
		t.Fatalf("已有名称不得被上报覆盖（管理员维护的台账优先）: %q", d2.Name)
	}
}

// ★吊销不因"设备又上报了"复活——那等于给吊销配了个静默的有效期。
func TestEnrollDeviceDoesNotResurrectRevoked(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	d, _, _ := s.EnrollDevice(ctx, "li.fang", "FP-R", "", "macOS", DeviceBindAuto)
	if d.Status != DeviceStatusTrusted {
		t.Fatalf("auto 绑定应直接 trusted: %v", d.Status)
	}
	if _, _, err := s.SetDeviceStatus(ctx, d.ID, DeviceStatusRevoked, "admin", "遗失"); err != nil {
		t.Fatal(err)
	}
	again, _, err := s.EnrollDevice(ctx, "li.fang", "FP-R", "", "macOS", DeviceBindAuto)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != DeviceStatusRevoked {
		t.Fatalf("已吊销设备再次上报必须仍是 revoked, got %v", again.Status)
	}
	if again.LastSeen < d.LastSeen {
		t.Fatal("last_seen 应仍被刷新（它是陈旧判定的依据，吊销设备也要看得出还活着）")
	}
}

// 单账号设备上限：第 21 台被拒；删掉一台即腾出名额。
func TestEnrollDeviceCap(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var first Device
	for i := 0; i < MaxDevicesPerAccount; i++ {
		d, _, err := s.EnrollDevice(ctx, "li.fang", fmt.Sprintf("FP-%02d", i), "", "macOS", DeviceBindAuto)
		if err != nil {
			t.Fatalf("第 %d 台应成功: %v", i+1, err)
		}
		if i == 0 {
			first = d
		}
	}
	if _, _, err := s.EnrollDevice(ctx, "li.fang", "FP-OVER", "", "macOS", DeviceBindAuto); !errors.Is(err, ErrDeviceCap) {
		t.Fatalf("超限应回 ErrDeviceCap, got %v", err)
	}
	// 已登记设备不受上限影响（否则满额之后所有终端连 posture 都刷不动了）。
	if _, created, err := s.EnrollDevice(ctx, "li.fang", "FP-00", "", "macOS", DeviceBindAuto); err != nil || created {
		t.Fatalf("已登记设备在满额下仍应可刷新: %v %v", created, err)
	}
	if _, err := s.DeleteDevice(ctx, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, created, err := s.EnrollDevice(ctx, "li.fang", "FP-OVER", "", "macOS", DeviceBindAuto); err != nil || !created {
		t.Fatalf("腾出名额后应可登记: %v %v", created, err)
	}
}

// DeleteDevice 两表同删（口径统一的执行处）。
func TestDeleteDeviceAlsoDropsPostureReport(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	d, _, _ := s.EnrollDevice(ctx, "li.fang", "FP-D", "", "macOS", DeviceBindAuto)
	if err := s.SavePostureReport(ctx, rep("li.fang", "FP-D", "allow", 0, time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.PostureReportFor(ctx, "li.fang", "FP-D"); ok {
		t.Fatal("删设备必须同删它的 posture 报告，否则会留下设备页看不见的孤儿报告")
	}
	if _, err := s.DeleteDevice(ctx, d.ID); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("重复删除应回 ErrDeviceNotFound, got %v", err)
	}
}

// 陈旧清理：跳过 revoked；被清的设备连同报告一起走。
func TestPurgeStaleDevices(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	old := time.Now().Add(-400 * 24 * time.Hour).Unix()
	for _, fp := range []string{"FP-S1", "FP-S2", "FP-FRESH"} {
		if _, _, err := s.EnrollDevice(ctx, "li.fang", fp, "", "macOS", DeviceBindAuto); err != nil {
			t.Fatal(err)
		}
		if err := s.SavePostureReport(ctx, rep("li.fang", fp, "allow", 0, old)); err != nil {
			t.Fatal(err)
		}
	}
	d2, _, _ := s.DeviceByFingerprint(ctx, "li.fang", "FP-S2")
	if _, _, err := s.SetDeviceStatus(ctx, d2.ID, DeviceStatusRevoked, "admin", "离职"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE trusted_devices SET last_seen=? WHERE fingerprint<>'FP-FRESH'`, old); err != nil {
		t.Fatal(err)
	}

	victims, err := s.PurgeStaleDevices(ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(victims) != 1 || victims[0].Fingerprint != "FP-S1" {
		t.Fatalf("应只清掉 FP-S1（revoked 与新鲜设备都留下）: %+v", victims)
	}
	if _, ok, _ := s.PostureReportFor(ctx, "li.fang", "FP-S1"); ok {
		t.Fatal("被清设备的 posture 报告也应一并删除")
	}
	if _, ok, _ := s.DeviceByFingerprint(ctx, "li.fang", "FP-S2"); !ok {
		t.Fatal("已吊销设备不得被陈旧清理带走——清掉吊销记录等于给吊销配了个静默的有效期")
	}
}

// 审批与设备状态同事务翻转（不另起一套审批流）。
func TestDecideApprovalFlipsDevice(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	d, _, _ := s.EnrollDevice(ctx, "li.fang", "FP-AP", "", "macOS", DeviceBindApproval)
	if d.ApprovalID == "" {
		t.Fatal("审批绑定模式应生成审批单")
	}
	dev, linked, err := s.DecideApproval(ctx, d.ApprovalID, "approved", "核验通过", "admin")
	if err != nil || !linked {
		t.Fatalf("审批应联动设备: %v %v", linked, err)
	}
	if dev.Status != DeviceStatusTrusted || dev.ApprovedBy != "admin" {
		t.Fatalf("通过后设备应 trusted 且记录批准人: %+v", dev)
	}
	// 审批队列里不再有它。
	b, err := s.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Approvals) != 0 {
		t.Fatalf("已处置的审批单不应再出现在待办队列: %+v", b.Approvals)
	}
	// 没有关联设备的审批单（迁移前遗留）→ linked=false，不报错也不假装改了什么。
	if _, err := s.db.Exec(`INSERT INTO approvals(id,usr,device,fingerprint,submitted_at,reason,status,timeline,decided_at,decide_reason)
VALUES('ap-orphan','x','x','x','2026-01-01','x','pending','[]','','')`); err != nil {
		t.Fatal(err)
	}
	if _, linked, err := s.DecideApproval(ctx, "ap-orphan", "approved", "", "admin"); err != nil || linked {
		t.Fatalf("孤儿审批单应 linked=false: %v %v", linked, err)
	}
}

// 审批重放：已处置的单子再判一次必须回 ErrApprovalDecided，且**设备一字不改**。
//
// ★放过去的后果不是"多写一行"：一张已驳回的单子再"通过"一次，就能把 revoked 的设备
// 悄悄改回 trusted，而审批行与时间线仍停在「驳回」——设备的实际授信状态与事后复盘
// 的唯一依据永久矛盾。不存在的 id 同理必须能被调用方分辨（否则 handler 会落一条
// 「审批 xxx：通过」的审计，而那件事根本没发生）。
func TestDecideApprovalRejectsReplayAndUnknownID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	d, _, _ := s.EnrollDevice(ctx, "alice", "FP-AAA", "", "macOS", DeviceBindApproval)
	rejected, _, err := s.DecideApproval(ctx, d.ApprovalID, "rejected", "不认识这台机器", "admin1")
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Status != DeviceStatusRevoked {
		t.Fatalf("驳回后设备应 revoked: %+v", rejected)
	}

	// 重放：同一张单子改判「通过」。
	if _, _, err := s.DecideApproval(ctx, d.ApprovalID, "approved", "再来一次", "admin2"); !errors.Is(err, ErrApprovalDecided) {
		t.Fatalf("已处置的审批单重放应回 ErrApprovalDecided，实得 %v", err)
	}
	after, ok, _ := s.DeviceByFingerprint(ctx, "alice", "FP-AAA")
	if !ok || after.Status != DeviceStatusRevoked || after.ApprovedBy == "admin2" || after.RevokeReason == "" {
		t.Fatalf("重放不得改动设备（状态/批准人/吊销理由都应保持驳回那一刻的样子）: %+v", after)
	}

	// 不存在的审批 id：可分辨的哨兵错误，而不是"静默成功"。
	if _, linked, err := s.DecideApproval(ctx, "ap-nonexistent", "approved", "", "admin2"); !errors.Is(err, ErrApprovalNotFound) || linked {
		t.Fatalf("不存在的审批 id 应回 ErrApprovalNotFound，实得 linked=%v err=%v", linked, err)
	}
}

// 设备名长度：同一列两个写入口必须一套口径。
//
// posture 上报的 os 字段完全由终端自报（handler 只限体积 32 KiB），拿它当设备名而不截断的话，
// 任意 role=user 账号就能把一大坨文本塞进设备台账 + 一条安全审计 + 每次 GET /devices 的响应。
func TestEnrollDeviceClampsSelfReportedName(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	long := strings.Repeat("超长设备名", 4000) // 远超 DeviceNameMaxRunes
	d, created, err := s.EnrollDevice(ctx, "alice", "FP-LONG", long, "macOS", DeviceBindAuto)
	if err != nil || !created {
		t.Fatalf("登记失败: %v %v", created, err)
	}
	if n := len([]rune(d.Name)); n != DeviceNameMaxRunes {
		t.Fatalf("设备名应被截到 %d 字，实得 %d", DeviceNameMaxRunes, n)
	}
	// 落库的那一份也必须是截断后的（返回值对了库里没对，等于没修）。
	got, ok, _ := s.DeviceByFingerprint(ctx, "alice", "FP-LONG")
	if !ok || len([]rune(got.Name)) != DeviceNameMaxRunes {
		t.Fatalf("库里的设备名未被截断: %d 字", len([]rune(got.Name)))
	}
	// 管理员手输的那条路径仍然是**拒绝**（他看得见提示），口径上界与这里同一个常量。
	if _, err := s.RenameDevice(ctx, d.ID, strings.Repeat("x", DeviceNameMaxRunes+1)); err == nil {
		t.Fatal("RenameDevice 应拒绝超长名字")
	}
}

// 准入设置：脏值收敛到安全默认；perUserQuota 恒为内置上限（不接受前端回传值）。
func TestDeviceTrustSettingNormalize(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	got, err := s.SaveDeviceTrustSetting(ctx, DeviceTrustSetting{
		Mode: "什么鬼", BindMethod: "也不对", StaleDays: -3, PerUserQuota: 9999})
	if err != nil {
		t.Fatal(err)
	}
	// Mode 的兜底方向是 observe：一个拼错的枚举值不该把全体终端锁在门外。
	if got.Mode != DeviceTrustObserve || got.BindMethod != DeviceBindApproval {
		t.Fatalf("脏值应收敛到 observe + 审批绑定: %+v", got)
	}
	if got.StaleDays != DefaultStaleDays {
		t.Fatalf("非法 staleDays 应回默认: %d", got.StaleDays)
	}
	if got.PerUserQuota != MaxDevicesPerAccount {
		t.Fatalf("perUserQuota 是只读展示值，必须恒为内置上限: %d", got.PerUserQuota)
	}
	back, err := s.DeviceTrustSetting(ctx)
	if err != nil || back != got {
		t.Fatalf("读回应与写入一致: %+v %+v %v", back, got, err)
	}
	// 库里存了坏 JSON（人手改过 / 版本回滚）时读出默认值而不是报错：
	// 这份配置在敲门热路径上被读，一条坏 JSON 不该让全体终端接不进来。
	if err := s.SetSetting(ctx, deviceTrustSettingKey, "{坏掉的"); err != nil {
		t.Fatal(err)
	}
	if bad, err := s.DeviceTrustSetting(ctx); err != nil || bad.Mode != DeviceTrustObserve {
		t.Fatalf("坏 JSON 应回默认: %+v %v", bad, err)
	}
}

// ★迁移回填：升级前只在 posture_reports 里留过痕的终端，必须出现在设备台账里且为 trusted。
//
// 不回填的后果不是"页面少点数据"，而是切到 strict 准入的那一刻全体存量终端被判
// 未登记、集体拒发敲门令牌。回填成 trusted 保住升级前后的语义一致（升级前的事实判据
// 就是"该账号用这个指纹上报过 posture"）。
func TestBackfillTrustedDevicesFromPostureReports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backfill.db")
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	for _, fp := range []string{"FP-OLD-1", "FP-OLD-2"} {
		if err := st.SavePostureReport(ctx, rep("li.fang", fp, "allow", 0, 1700000000)); err != nil {
			t.Fatal(err)
		}
	}
	// 造出"升级前"的库形态：只有 posture 报告，没有设备台账，也没有回填标记。
	if _, err := st.db.Exec(`DELETE FROM trusted_devices`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM settings WHERE k=?`, trustedDevicesBackfillMarker); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st2, err := OpenSQLite(path) // 升级：migrate 里跑回填
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	for _, fp := range []string{"FP-OLD-1", "FP-OLD-2"} {
		d, ok, err := st2.DeviceByFingerprint(ctx, "li.fang", fp)
		if err != nil || !ok {
			t.Fatalf("存量设备 %s 应被回填进台账: %v %v", fp, ok, err)
		}
		if d.Status != DeviceStatusTrusted {
			t.Fatalf("存量设备应回填为 trusted（保住升级前后语义一致）, got %v", d.Status)
		}
		if d.ApprovedBy != DeviceApproverBackfill {
			t.Fatalf("批准人应如实标为迁移回填，不冒充某个管理员: %q", d.ApprovedBy)
		}
	}

	// ★一次性标记的意义：管理员吊销后，再次启动不得把它重新回填成 trusted
	//（"重启即复活"）。这里连标记一起删掉再开一次，验证 NOT EXISTS 那道守卫也拦得住。
	d, _, _ := st2.DeviceByFingerprint(ctx, "li.fang", "FP-OLD-1")
	if _, _, err := st2.SetDeviceStatus(ctx, d.ID, DeviceStatusRevoked, "admin", "回收"); err != nil {
		t.Fatal(err)
	}
	if _, err := st2.db.Exec(`DELETE FROM settings WHERE k=?`, trustedDevicesBackfillMarker); err != nil {
		t.Fatal(err)
	}
	st2.Close()
	st3, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("reopen2: %v", err)
	}
	defer st3.Close()
	if d, _, _ := st3.DeviceByFingerprint(ctx, "li.fang", "FP-OLD-1"); d.Status != DeviceStatusRevoked {
		t.Fatalf("回填不得复活已吊销设备, got %v", d.Status)
	}
}

// 全新库上回填空转是**正确**结果（posture_reports 从不播种），且不该留下任何设备。
func TestBackfillNoopOnFreshDatabase(t *testing.T) {
	s := openTestStore(t)
	b, err := s.Devices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Devices) != 0 {
		t.Fatalf("全新库不应有任何设备（刻意不给演示设备）: %+v", b.Devices)
	}
	if len(b.Approvals) != 0 {
		t.Fatalf("全新库不应有任何绑定审批（播一批对不上设备的申请只会制造假象）: %+v", b.Approvals)
	}
	if b.Settings.Mode != DeviceTrustObserve {
		t.Fatalf("默认准入模式应是 observe（与 posture 的 observe 默认一致）: %+v", b.Settings)
	}
}

// 设备清单派生字段：陈旧标记 + posture 现况；报告缺失时判定为空串而不是 allow。
func TestDeviceListDerivedFields(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, _, err := s.EnrollDevice(ctx, "li.fang", "FP-NOREP", "", "macOS", DeviceBindAuto); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.EnrollDevice(ctx, "li.fang", "FP-REP", "", "macOS", DeviceBindAuto); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePostureReport(ctx, rep("li.fang", "FP-REP", "block", 40, time.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE trusted_devices SET last_seen=? WHERE fingerprint='FP-NOREP'`,
		time.Now().Add(-90*24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	b, err := s.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byFP := map[string]Device{}
	for _, d := range b.Devices {
		byFP[d.Fingerprint] = d
	}
	if v := byFP["FP-NOREP"].Verdict; v != "" {
		t.Fatalf("从未上报的设备判定应为空串，不得渲染成 allow: %q", v)
	}
	if !byFP["FP-NOREP"].Stale {
		t.Fatal("90 天未上报应被标记陈旧（默认 30 天阈值）")
	}
	if byFP["FP-REP"].Verdict != "block" || byFP["FP-REP"].Stale {
		t.Fatalf("刚上报的设备应带最新判定且不陈旧: %+v", byFP["FP-REP"])
	}
}
