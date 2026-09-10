package store

import (
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/standby"
)

func openStandbyStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "sb.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestStandbyEmptyTableMeansNotConfigured 空表 = 未配置备机，不是"零台在线"。
// 新表刻意不做回填：既有库此前没有温备这回事，空表恰好就是既有部署的真实形态。
func TestStandbyEmptyTableMeansNotConfigured(t *testing.T) {
	s := openStandbyStore(t)
	ns, err := s.StandbyNodes(t.Context())
	if err != nil {
		t.Fatalf("读空表不该报错: %v", err)
	}
	if len(ns) != 0 {
		t.Fatalf("空表应回空切片，得到 %+v", ns)
	}
}

// TestStandbyPullDoesNotFakeSync 「来拉过」不等于「同步成功」。
//
// 拉取由主机直接观测（发出去字节），成功与否只有备机知道。若 NoteStandbyPull
// 顺手把 last_sync_at 也推了，一台"每 10 分钟准时来拉、每次校验都失败"的备机
// 会在页面上一路绿灯——而那正是切换那天会发现自己没有备份的情形。
func TestStandbyPullDoesNotFakeSync(t *testing.T) {
	s := openStandbyStore(t)
	ctx := t.Context()
	if err := s.NoteStandbyPull(ctx, "standby-1", "", 1000); err != nil {
		t.Fatal(err)
	}
	n := singleStandby(t, s)
	if n.LastPullAt != 1000 {
		t.Errorf("拉取时间应落库: %+v", n)
	}
	if n.LastSyncAt != 0 {
		t.Fatalf("拉取不得推进 last_sync_at（0 = 从未成功同步）: %+v", n)
	}

	// 成功回报后再拉一次：拉取不得把已有的成功时间抹掉
	if err := s.SaveStandbyStatus(ctx, standby.Node{NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600}, true, 2000); err != nil {
		t.Fatal(err)
	}
	if err := s.NoteStandbyPull(ctx, "standby-1", "", 3000); err != nil {
		t.Fatal(err)
	}
	n = singleStandby(t, s)
	if n.LastSyncAt != 2000 || n.LastPullAt != 3000 {
		t.Fatalf("两个时间各记各的: %+v", n)
	}
	if n.Addr != "10.0.0.2" {
		t.Fatalf("拉取请求里没有落点，不得用空串把已知落点抹掉: %+v", n)
	}
}

// TestStandbyFailKeepsLastSuccess 失败回报保留上一次成功的时间戳与备份头。
// 抹掉的话页面就说不出「上次成功是 X，之后一直在失败」——而那正是运维要的那句话。
func TestStandbyFailKeepsLastSuccess(t *testing.T) {
	s := openStandbyStore(t)
	ctx := t.Context()
	ok := standby.Node{NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600,
		BackupVersion: "0.3.0", BackupCreatedAt: "2026-08-11 10:00:00", BackupSHA256: "deadbeef"}
	if err := s.SaveStandbyStatus(ctx, ok, true, 2000); err != nil {
		t.Fatal(err)
	}
	fail := standby.Node{NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600, LastDetail: "主机回 503"}
	if err := s.SaveStandbyStatus(ctx, fail, false, 5000); err != nil {
		t.Fatal(err)
	}
	n := singleStandby(t, s)
	switch {
	case n.LastSyncAt != 2000:
		t.Errorf("last_sync_at 应停在上次成功: %+v", n)
	case n.LastStatus != "fail" || n.LastDetail != "主机回 503":
		t.Errorf("失败状态与详情应更新: %+v", n)
	case n.BackupVersion != "0.3.0" || n.BackupSHA256 != "deadbeef":
		t.Errorf("失败那次没有新备份头，不得抹成未知: %+v", n)
	case n.UpdatedAt != 5000:
		t.Errorf("updated_at 应是本次回报时间: %+v", n)
	}
}

// TestStandbyFirstReportIsFail 第一次回报就是失败：建行、但 last_sync_at 保持"从未"。
func TestStandbyFirstReportIsFail(t *testing.T) {
	s := openStandbyStore(t)
	if err := s.SaveStandbyStatus(t.Context(),
		standby.Node{NodeID: "standby-1", IntervalSec: 600, LastDetail: "校验失败"}, false, 900); err != nil {
		t.Fatal(err)
	}
	n := singleStandby(t, s)
	if n.LastSyncAt != 0 || n.LastStatus != "fail" {
		t.Fatalf("首次即失败应记为「从未成功同步」: %+v", n)
	}
}

// TestStandbyVersionColumnsRoundTrip 备机版本身份四列的落库与读回（wave11 行动 18-③）。
func TestStandbyVersionColumnsRoundTrip(t *testing.T) {
	s := openStandbyStore(t)
	in := standby.Node{
		NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600,
		NodeSemver: "0.4.0", NodeBuild: "aaaaaaa · 2026-09-10T00:00:00Z",
		ControlSemver: "0.3.0", ControlBuild: "bbbbbbb · 2026-09-01T00:00:00Z",
	}
	if err := s.SaveStandbyStatus(t.Context(), in, true, 2000); err != nil {
		t.Fatal(err)
	}
	n := singleStandby(t, s)
	if n.NodeSemver != "0.4.0" || n.ControlSemver != "0.3.0" {
		t.Fatalf("两个语义版本要分别落库: %+v", n)
	}
	if n.NodeBuild != in.NodeBuild || n.ControlBuild != in.ControlBuild {
		t.Fatalf("两个构建标识要分别落库: %+v", n)
	}
}

// TestStandbyVersionIsOverwrittenEvenWithEmpty 版本身份**每轮覆写、包括覆写成空**。
//
// 与备份头那三列（失败轮次保留旧值）刻意相反，理由是取数方式不同：
// 备份头在失败那轮没有新值可报，保留旧值才不会把"上次备份是 0.3.0 的"抹掉；
// 而版本身份是**每轮实测**的（备机跑一次 `baidi-control -version`）——
// 这一轮探不到就是这一轮探不到。留着上一轮的好值，会让「备机上的 baidi-control
// 被删了 / 被换成一个跑不起来的二进制」在页面上永远显示成上次那个正常版本。
//
// ★变异检验：把 UPDATE 里那四列改成备份头那种 `CASE WHEN excluded.x='' THEN 旧值` 写法，
// 这条立刻红。
func TestStandbyVersionIsOverwrittenEvenWithEmpty(t *testing.T) {
	s := openStandbyStore(t)
	ctx := t.Context()
	first := standby.Node{NodeID: "standby-1", IntervalSec: 600,
		NodeSemver: "0.4.0", ControlSemver: "0.4.0", ControlBuild: "aaaaaaa"}
	if err := s.SaveStandbyStatus(ctx, first, true, 2000); err != nil {
		t.Fatal(err)
	}
	// 下一轮：备机还在（NodeSemver 有值），但同机 baidi-control 探不到了。
	second := standby.Node{NodeID: "standby-1", IntervalSec: 600, NodeSemver: "0.4.0"}
	if err := s.SaveStandbyStatus(ctx, second, true, 3000); err != nil {
		t.Fatal(err)
	}
	n := singleStandby(t, s)
	if n.ControlSemver != "" || n.ControlBuild != "" {
		t.Fatalf("探不到就该落回不可判定，不得保留上一轮的好值: %+v", n)
	}
	if n.NodeSemver != "0.4.0" {
		t.Fatalf("这一轮真的报上来的那半要照常更新: %+v", n)
	}
}

// TestStandbyLegacyRowsHaveNoVersion 补列不回填：既有行读出来是空串（不可判定）。
//
// ★这是「补列迁移必须配回填」那条纪律的**正确应用**而不是例外：回填方向必须恒定为
// "不生效 / 不下结论"，而空串在 standby.versionVerdict 里恰好就是 unknown。
// 回填成主机版本 = 替一台还没说过话的备机宣布"我们一致"，
// 而这四列存在的全部意义就是发现"它和主机不是同一版"。
func TestStandbyLegacyRowsHaveNoVersion(t *testing.T) {
	s := openStandbyStore(t)
	// 模拟补列前建的行：只走 NoteStandbyPull（那条 INSERT 不碰这四列）。
	if err := s.NoteStandbyPull(t.Context(), "standby-old", "10.0.0.9", 1000); err != nil {
		t.Fatal(err)
	}
	n := singleStandby(t, s)
	if n.NodeSemver != "" || n.ControlSemver != "" || n.NodeBuild != "" || n.ControlBuild != "" {
		t.Fatalf("既有行的版本四列必须是空（不可判定），绝不能被补成任何值: %+v", n)
	}
}

func singleStandby(t *testing.T, s *SQLiteStore) standby.Node {
	t.Helper()
	ns, err := s.StandbyNodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 1 {
		t.Fatalf("应恰好一台备机，得到 %d", len(ns))
	}
	return ns[0]
}
