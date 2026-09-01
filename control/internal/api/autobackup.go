package api

// 主机侧定期自动备份（PRD NFR-AVL-04「配置定期自动备份与恢复」）。
//
// ★缺的一直是**主机侧**这一半：`upgrade.CreateBackup` 全仓只有两个非测试调用方——
// 管理员手点导出（产物直接 stream 给浏览器，服务器上一个字节都不落）与备机来拉时现造。
// 单机部署（参考形态、也是演示站的形态）因此**一份自动备份都没有**：
// 没有 .timer、没有 ticker、install-remote.sh 也不装任何定时任务。
// 而 SCOPE 里 AVL-04 长期按「接近真」记账——真的那半是备机拉取，
// 可备机本身要另配一台机器，单机部署一条也享受不到。
//
// 三条纪律：
//   ① **原样复用** backupSources + upgrade.CreateBackup，绝不另造一种格式
//      （理由已写在 standby.go：两种格式意味着恢复那天要猜用哪个工具）；
//   ② 未配置目录或口令时**明说未启用**，不画绿色——"定期备份"这件事一旦被
//      渲染成已开启而实际没跑，恢复那天才发现是最坏的一种；
//   ③ 「最近一次成功」只由**真的写盘成功那一次**更新（同 notify 的 last_status
//      只由真正发出那次写入）。

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"baidi.dev/control/internal/upgrade"
)

// AutoBackupConfig 自动备份的运行参数（全部来自环境变量，见 config）。
type AutoBackupConfig struct {
	Dir        string        // 空 = 不启用
	Interval   time.Duration // <=0 = 不启用
	Passphrase string        // 空 = 不启用（备份里装着 CA 私钥与全部凭据，不允许不加密）
	Keep       int           // 保留份数，<=0 取 7
}

// autoBackupInfo 最近一次自动备份的结果（**纯数据**，可安全复制）。
//
// ★与持锁的 autoBackupState 分开：合成一个结构的话，取快照时那句
// `c := *s.autoBackup` 会把 sync.Mutex 一起复制走——go vet 会报
// 「assignment copies lock value」，而真正的风险是复制出来的那把锁
// 与原锁毫无关系，任何基于它的同步都是假的。
type autoBackupInfo struct {
	// Enabled 是否真的在跑。false 时下面几格一律无意义。
	Enabled bool
	// Reason Enabled=false 时的原因（缺目录 / 缺口令 / 间隔非法），页面原样显示。
	Reason string
	Dir    string
	// LastOKAt / LastBytes 只在**真的写盘成功**那一次更新。
	LastOKAt int64
	LastFile string
	LastSize int64
	// LastErrAt / LastErr 最近一次失败（成功后不清空：一次成功不代表上一次失败没发生过，
	// 页面把两者并排显示，管理员自己判断）。
	LastErrAt int64
	LastErr   string
	Keep      int
	Interval  time.Duration
}

// autoBackupState = 一把锁 + 那份纯数据。
type autoBackupState struct {
	mu   sync.Mutex
	info autoBackupInfo
}

// autoBackupSnapshot 取一份**值拷贝**（不含锁），调用方随便读。
func (s *Server) autoBackupSnapshot() autoBackupInfo {
	s.autoBackup.mu.Lock()
	defer s.autoBackup.mu.Unlock()
	return s.autoBackup.info
}

// StartAutoBackupLoop 启动定期自动备份。未配置时**不静默返回**——
// 打一行告警并把原因记进状态，让页面能如实说「未启用」而不是什么都不显示。
func (s *Server) StartAutoBackupLoop(ctx context.Context, cfg AutoBackupConfig) {
	if s.autoBackup == nil {
		s.autoBackup = &autoBackupState{}
	}
	keep := cfg.Keep
	if keep <= 0 {
		keep = 7
	}
	set := func(reason string) {
		s.autoBackup.mu.Lock()
		s.autoBackup.info.Enabled = false
		s.autoBackup.info.Reason = reason
		s.autoBackup.mu.Unlock()
		slog.Warn("主机侧定期自动备份未启用", "原因", reason)
	}
	switch {
	case strings.TrimSpace(cfg.Dir) == "":
		set("未配置备份目录（BAIDI_BACKUP_DIR）")
		return
	case strings.TrimSpace(cfg.Passphrase) == "":
		// 不允许"不加密地存一份"：备份里装着 CA 私钥、三把签名私钥与审计链密钥。
		set("未配置备份口令（BAIDI_BACKUP_PASSPHRASE）——备份含 CA 私钥与全部凭据，不允许不加密存盘")
		return
	case cfg.Interval <= 0:
		set("备份间隔非法（BAIDI_BACKUP_INTERVAL <= 0）")
		return
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		set("备份目录不可创建：" + err.Error())
		return
	}
	s.autoBackup.mu.Lock()
	s.autoBackup.info.Enabled = true
	s.autoBackup.info.Reason = ""
	s.autoBackup.info.Dir = cfg.Dir
	s.autoBackup.info.Keep = keep
	s.autoBackup.info.Interval = cfg.Interval
	s.autoBackup.mu.Unlock()
	slog.Info("主机侧定期自动备份已启用", "目录", cfg.Dir, "间隔", cfg.Interval.String(), "保留份数", keep)

	go func() {
		// 启动先跑一次：装完机就该有一份，而不是等第一个周期到。
		s.RunAutoBackup(ctx, cfg, keep)
		t := time.NewTicker(cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			s.RunAutoBackup(ctx, cfg, keep)
		}
	}()
}

// RunAutoBackup 跑一次备份。导出给测试用——同一条代码路径，不做第二份实现。
func (s *Server) RunAutoBackup(ctx context.Context, cfg AutoBackupConfig, keep int) {
	fail := func(err error) {
		s.autoBackup.mu.Lock()
		s.autoBackup.info.LastErrAt = time.Now().Unix()
		s.autoBackup.info.LastErr = err.Error()
		s.autoBackup.mu.Unlock()
		slog.Error("定期自动备份失败", "err", err.Error())
		s.auditBG(ctx, "system", "定期自动备份失败："+err.Error(), "fail")
	}
	sources, cleanup, err := s.backupSources(ctx)
	if err != nil {
		fail(err)
		return
	}
	defer cleanup()

	name := "baidi-backup-" + time.Now().Format("20060102-150405") + ".bdbak"
	final := filepath.Join(cfg.Dir, name)
	// ★先写临时文件再 rename：直接往目标名写的话，进程被杀 / 磁盘满会留下一个
	//   **半截的备份**，而它看起来与完整备份没有区别（同名、有大小、时间也新）。
	tmp, err := os.CreateTemp(cfg.Dir, ".partial-*")
	if err != nil {
		fail(err)
		return
	}
	tmpName := tmp.Name()
	meta := upgrade.BackupMeta{
		Version: Version, CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		Note: "定期自动备份",
	}
	if err := upgrade.CreateBackup(tmp, meta, cfg.Passphrase, sources); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		fail(err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		fail(err)
		return
	}
	if err := os.Chmod(tmpName, 0o600); err != nil { // 里面是 CA 私钥与全部凭据
		os.Remove(tmpName)
		fail(err)
		return
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		fail(err)
		return
	}
	fi, _ := os.Stat(final)
	var size int64
	if fi != nil {
		size = fi.Size()
	}
	s.autoBackup.mu.Lock()
	s.autoBackup.info.LastOKAt = time.Now().Unix()
	s.autoBackup.info.LastFile = final
	s.autoBackup.info.LastSize = size
	s.autoBackup.mu.Unlock()
	s.auditBG(ctx, "system",
		fmt.Sprintf("定期自动备份完成：%s（%d 字节）", name, size), "ok")

	pruneBackups(cfg.Dir, keep)
}

// pruneBackups 只保留最近 keep 份。
//
// ★按**文件名**排序而不是 mtime：文件名里的时间戳是备份**内容**的时刻，
// 而 mtime 会被 rsync / 冷备复制等操作改写，那时删掉的可能正是最老也最该留的那份。
func pruneBackups(dir string, keep int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "baidi-backup-") && strings.HasSuffix(e.Name(), ".bdbak") {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return
	}
	sort.Strings(names) // 名字里是 YYYYMMDD-HHMMSS，字典序 = 时间序
	for _, n := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			slog.Warn("清理旧备份失败", "file", n, "err", err.Error())
		}
	}
}

// checkAutoBackup /diag 的「主机侧定期自动备份」检查项（NFR-AVL-04）。
//
// ★**未启用时判 warn 而不是 skip**，与 checkNAT / checkAuditForward 那两条
// 刻意相反：那两个是"没用这个功能"，而"没有任何自动备份"是每套部署都该关心的事——
// 恢复那天没有备份，不会因为当初没配就变得不严重。
func (s *Server) checkAutoBackup() DiagCheck {
	c := DiagCheck{Key: "auto-backup", Category: "system", Name: "主机侧定期自动备份"}
	if s.autoBackup == nil {
		c.Status = "warn"
		c.Summary = "自动备份未初始化"
		return c
	}
	st := s.autoBackupSnapshot()
	if !st.Enabled {
		c.Status = "warn"
		c.Summary = "未启用主机侧定期自动备份：" + st.Reason
		c.Hint = "配置 BAIDI_BACKUP_DIR + BAIDI_BACKUP_PASSPHRASE（见 deploy/config.env.example）。" +
			"备机拉取那条路只在部署了温备节点时才有——单机部署不配这两项就是一份自动备份都没有。"
		c.Items = []DiagItem{{Label: "手工导出", Value: "系统管理页仍可随时导出一份（产物直接下载，服务器上不留）"}}
		return c
	}
	c.Metric = fmt.Sprintf("每 %s 一次 · 保留 %d 份 · %s", st.Interval, st.Keep, st.Dir)
	items := []DiagItem{}
	switch {
	case st.LastOKAt == 0:
		items = append(items, DiagItem{Label: "最近一次成功", Value: "尚未成功过"})
	default:
		items = append(items, DiagItem{Label: "最近一次成功",
			Value: fmt.Sprintf("%s · %s（%d 字节）", tsText(st.LastOKAt), filepath.Base(st.LastFile), st.LastSize)})
	}
	if st.LastErrAt > 0 {
		// ★成功之后也照样显示最近一次失败：一次成功不代表上一次失败没发生过。
		items = append(items, DiagItem{Label: "最近一次失败",
			Value: tsText(st.LastErrAt) + " · " + st.LastErr})
	}
	c.Items = items
	switch {
	case st.LastOKAt == 0 && st.LastErrAt > 0:
		c.Status = "fail"
		c.Summary = "自动备份已启用但**一次都没成功过**：" + st.LastErr
	case st.LastOKAt == 0:
		c.Status = "warn"
		c.Summary = "自动备份已启用，但还没有产出过一份（刚启动？）"
	case time.Now().Unix()-st.LastOKAt > int64(st.Interval/time.Second)*3:
		// 连续三个周期没成功 = 它其实已经不工作了，而目录里那份旧备份看起来一切正常。
		c.Status = "fail"
		c.Summary = fmt.Sprintf("最近一次成功备份是 %s，已超过 3 个周期——自动备份实际已停止工作", tsText(st.LastOKAt))
	default:
		c.Status = "pass"
		c.Summary = "定期自动备份正常，最近一次 " + tsText(st.LastOKAt)
	}
	return c
}
