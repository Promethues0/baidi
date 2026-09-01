package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 主机侧定期自动备份（NFR-AVL-04）。
//
// ★缺陷原样：`upgrade.CreateBackup` 全仓只有两个非测试调用方——管理员手点导出
// （产物直接 stream 给浏览器，服务器上一个字节都不落）与备机来拉时现造。
// 单机部署（参考形态、也是演示站的形态）因此**一份自动备份都没有**，
// 而 SCOPE 长期按「接近真」记账。
func TestAutoBackupWritesAndPrunes(t *testing.T) {
	h, srv := newTestServerWithSrv(t)
	_ = h
	dir := t.TempDir()
	cfg := AutoBackupConfig{Dir: dir, Interval: time.Hour, Passphrase: "backup-pass-1234", Keep: 2}
	srv.autoBackup = &autoBackupState{info: autoBackupInfo{Enabled: true, Dir: dir, Keep: 2, Interval: time.Hour}}

	// 跑三次，每次的文件名带秒级时间戳——手工错开，避免同秒覆盖。
	for i := 0; i < 3; i++ {
		srv.RunAutoBackup(t.Context(), cfg, 2)
		if i < 2 {
			time.Sleep(1100 * time.Millisecond)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var baks []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "baidi-backup-") {
			baks = append(baks, e.Name())
		}
		// ★半截文件绝不能留下：直接往目标名写的话，进程被杀会留下一个与完整备份
		//   同名、有大小、时间也新的文件，恢复那天才发现它解不开。
		if strings.HasPrefix(e.Name(), ".partial-") {
			t.Fatalf("不该留下半截的临时文件：%s", e.Name())
		}
	}
	if len(baks) != 2 {
		t.Fatalf("保留份数应为 2，实得 %d：%v", len(baks), baks)
	}
	st := srv.autoBackupSnapshot()
	if st.LastOKAt == 0 || st.LastSize == 0 {
		t.Fatalf("成功之后要记下时刻与大小，实得 %+v", st)
	}
	// 备份文件权限 0600：里面是 CA 私钥与全部凭据。
	fi, err := os.Stat(filepath.Join(dir, baks[0]))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("备份含 CA 私钥与全部凭据，权限应为 0600，实得 %v", fi.Mode().Perm())
	}
}

// 未配置时**明说未启用**，不静默、也不画绿色。
func TestAutoBackupDisabledIsExplicit(t *testing.T) {
	_, srv := newTestServerWithSrv(t)

	cases := []struct {
		name string
		cfg  AutoBackupConfig
		want string
	}{
		{"缺目录", AutoBackupConfig{Interval: time.Hour, Passphrase: "x1234567890"}, "备份目录"},
		{"缺口令", AutoBackupConfig{Dir: t.TempDir(), Interval: time.Hour}, "备份口令"},
		{"间隔非法", AutoBackupConfig{Dir: t.TempDir(), Passphrase: "x1234567890"}, "间隔"},
	}
	for _, c := range cases {
		srv.autoBackup = &autoBackupState{}
		srv.StartAutoBackupLoop(t.Context(), c.cfg)
		st := srv.autoBackupSnapshot()
		if st.Enabled {
			t.Fatalf("%s：不该判为已启用", c.name)
		}
		if !strings.Contains(st.Reason, c.want) {
			t.Fatalf("%s：原因要说清缺什么，实得 %q", c.name, st.Reason)
		}
		// /diag 上必须是 warn 而不是 skip——「没有任何自动备份」是每套部署都该关心的事，
		// 不会因为当初没配就变得不严重。
		chk := srv.checkAutoBackup()
		if chk.Status != "warn" {
			t.Fatalf("%s：/diag 应判 warn，实得 %q", c.name, chk.Status)
		}
		if !strings.Contains(chk.Hint, "BAIDI_BACKUP_DIR") {
			t.Fatalf("%s：提示要给出怎么开，实得 %q", c.name, chk.Hint)
		}
	}
}
