package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ── 按磁盘水位轮转审计（PRD FR-AUDIT-10 的另一半）──
//
// PRD 原文：「满足『最大占用磁盘空间百分比』或『期望保留天数』任一条件即删除最早一天的
// 日志」。保留天数那一半早就有了（PurgeExpiredAudit）；水位这一半此前只有测量
// （AuditDiskStat）没有消费方——诊断页显示占用率，但没有任何东西据此动作。
//
// 落地时有三个地方按字面实现就会坏，逐条记在这里：
//
// ① **判据不能用「文件系统占用率」，只能用「审计库自己占了文件系统多大」。**
//
//	FSTotal 满了可能跟审计一点关系都没有（别的服务、镜像、日志）。按文件系统占用率
//	触发的话，一次与审计无关的磁盘告急会把**全部审计历史删光**，而磁盘依旧是满的——
//	付出了全部证据，一个字节都没换回来。判据换成 DBBytes/FSTotal 之后，
//	「删除能不能改善」与「要不要删除」这两件事才是同一个判断。
//	文件系统整体的水位仍然要看，但那是 /diag 的 audit-disk 告警，不是删除触发器。
//
// ② **删完文件不会变小**——SQLite 不 VACUUM 就不把页还给文件系统。
//
//	所以「删一天 → 重新量文件大小 → 还超 → 再删一天」会一路删到一行不剩，
//	而 DBBytes 从头到尾纹丝不动。这里改成先按当前平均行宽算出**目标行数**，
//	删到行数达标即止。实际效果是**封住增长**（腾出的页由后续 INSERT 复用），
//	不是把文件缩小——运维 `ls -l` 看不到变化是正常的，这句必须写在日志与审计里，
//	否则下一个人会以为功能没生效，然后把阈值一路调低直到把库删空。
//	（不做 VACUUM 是有意的：它要全库锁 + 临时占用约 2× 空间，而这条路径恰恰是在
//	磁盘紧张时触发的，正是最不该申请两倍空间的时刻。）
//
// ③ **当天的记录不删。**
//
//	一天就撑爆阈值时，按字面实现会把「此刻正在发生的事」的记录删掉——那是取证材料里
//	最不该先没的一段。这里删到只剩当天就停，改由日志 + /diag + 告警去喊。
//
// ④ **每次按水位删都落审计**（调用方 api.purgeAuditOnce 负责写）：删了多少行、
//
//	覆盖到哪一天、触发时的水位是多少。「证据被轮转掉了」与「证据凭空少了一段」
//	在库里长得一模一样，区别只在有没有这条记录。

// AuditDiskPurgeMaxDays 单轮最多回收多少天，防止一次调用把库扫空。
// 清理循环 24h 跑一次 + 启动跑一次，够慢的收敛速度换来的是「不会一把删过头」。
const AuditDiskPurgeMaxDays = 30

// AuditDiskPurge 一次按水位轮转的结果（如实描述，供日志与审计逐字引用）。
type AuditDiskPurge struct {
	// Enabled 是否配置了水位阈值（BAIDI_AUDIT_MAX_DISK_PERCENT > 0）。
	Enabled bool
	// Measurable 判据能不能测（平台无 Statfs / 库读不出时为 false）。
	// ★测不出来一律**不删**：判不了水位就去删证据，是拿确定的损失赌一个不确定的收益。
	Measurable bool
	// UsedPct 判据水位 = 审计库文件 ÷ 文件系统总容量（不是文件系统占用率，见 ①）。
	UsedPct   int
	MaxPct    int
	Triggered bool
	// Deleted / Days 实际删除的行数与天数。
	Deleted int64
	Days    int
	// OldestKept 清理后最早一条记录的时刻（空 = 库空了或没删）。
	OldestKept string
	// Note 未触发 / 提前停止的原因（"只剩当天的记录"等），如实回给日志与审计。
	Note string
}

// PurgeAuditByDisk 按磁盘水位回收审计（maxPct<=0 = 未启用，不做任何事）。
//
// 判据、行数目标、当天保护的理由见文件头 ①②③。
func (s *SQLiteStore) PurgeAuditByDisk(ctx context.Context, maxPct int) (AuditDiskPurge, error) {
	out := AuditDiskPurge{MaxPct: maxPct}
	if maxPct <= 0 {
		out.Note = "未配置审计磁盘水位上限（BAIDI_AUDIT_MAX_DISK_PERCENT），仅按保留天数轮转"
		return out, nil
	}
	out.Enabled = true
	d, err := s.AuditDiskStat(ctx)
	if err != nil {
		return out, err
	}
	return s.purgeByDiskStat(ctx, d, maxPct)
}

// purgeByDiskStat 判定 + 回收循环，**水位读数由参数给**。
//
// ★把测量拆出去是为了可测：真实机器上审计库占文件系统只有千分之几，
// 阈值最小 1% 也永远够不着触发点——把判定和测量焊在一起，
// 「触发之后到底怎么删」这一整段在任何一台正常机器上都跑不到，
// 于是 ①②③ 三条纪律（判据、目标行数、当天保护）一条都验不了。
func (s *SQLiteStore) purgeByDiskStat(ctx context.Context, d AuditDiskStat, maxPct int) (AuditDiskPurge, error) {
	out := AuditDiskPurge{MaxPct: maxPct, Enabled: true}
	if !d.FSSupported || d.FSTotalBytes == 0 {
		out.Note = "当前平台测不出文件系统容量，水位不可判定——不按水位删除任何审计"
		return out, nil
	}
	out.Measurable = true
	out.UsedPct = int(float64(d.DBBytes)/float64(d.FSTotalBytes)*100 + 0.5)
	if out.UsedPct < maxPct || d.Rows == 0 {
		return out, nil
	}
	out.Triggered = true

	// 目标行数：按当前平均行宽把「允许占用的字节数」折算成行数。
	// 之所以折算而不是删完再量文件大小，见文件头 ②。
	perRow := d.DBBytes / d.Rows
	if perRow < 1 {
		perRow = 1
	}
	maxBytes := int64(float64(d.FSTotalBytes) * float64(maxPct) / 100)
	targetRows := maxBytes / perRow
	today := time.Now().Format("2006-01-02")

	rows := d.Rows
	for out.Days < AuditDiskPurgeMaxDays && rows > targetRows {
		var oldest string
		err := s.db.QueryRowContext(ctx, `SELECT substr(MIN(ts),1,10) FROM audit_log`).Scan(&oldest)
		if errors.Is(err, sql.ErrNoRows) || oldest == "" {
			break
		}
		if err != nil {
			return out, err
		}
		if oldest >= today {
			// ③ 只剩当天：停手。此刻正在发生的事，其记录不该是最先被删的那一段。
			out.Note = fmt.Sprintf("已回收到只剩当天（%s）的记录，按水位的回收到此为止——"+
				"当天审计是正在发生的取证材料，不删；水位仍然偏高请扩容或缩短留存天数", today)
			break
		}
		// 删到 oldest 这一天的末尾（含）：cutoff 取次日零点。
		next, perr := time.Parse("2006-01-02", oldest)
		if perr != nil {
			return out, perr
		}
		n, derr := s.purgeAuditBefore(ctx, next.AddDate(0, 0, 1).Format("2006-01-02 15:04:05"))
		if derr != nil {
			return out, derr
		}
		if n == 0 {
			break // 划界删不动了（理论上不该发生），别空转
		}
		out.Deleted += n
		out.Days++
		rows -= n
	}
	if out.Days >= AuditDiskPurgeMaxDays && out.Note == "" {
		out.Note = fmt.Sprintf("单轮回收上限 %d 天已用尽，剩余部分留待下一轮", AuditDiskPurgeMaxDays)
	}
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MIN(ts),'') FROM audit_log`).Scan(&out.OldestKept)
	return out, nil
}
