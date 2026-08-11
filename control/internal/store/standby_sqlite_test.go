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
