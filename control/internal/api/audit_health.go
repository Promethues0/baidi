package api

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"baidi.dev/control/internal/store"
)

// ── 审计写入失败的信号（wave8 行动 6）──
//
// 全系统 190+ 个审计点最终都收敛到 auditAs / auditBG 两行 RecordAudit。
// 那两行此前是 `_ = s.writer.RecordAudit(...)`：磁盘写满、库被写锁卡住、
// 表损坏——任何一种，管理操作照常回 200，审计**静默停写**，而且：
//
//   - 防篡改链校验仍然全绿：VerifyAuditChain 重算的是**已存在行**的前缀连续性，
//     尾部整段根本没写进去不构成断链（缺失的行不在链上，链自然是连的）；
//   - 告警一条不响：11 条规则里没有一条看控制面自身的存储；
//   - 页面正常：审计中心照常渲染最近 200 条——只是它们停在了故障那一刻。
//
// 于是「全量留痕、事后可举证」这个第一性主张，恰在最需要它的时刻失效且无人知晓。
// 同一个仓库里，审计**外送**入队失败尚且 slog.Error，主审计写失败连一行日志都没有,
// 这个不对称本身就是判据。
//
// ★缺的不是回滚，是信号。「best-effort，写审计失败不影响主操作」是对的取舍——
// 让一次删不掉的日志把管理员的正常操作也一并否掉，换来的是可用性事故而不是安全。
//
// ★信号分三层，越靠前越不依赖那个正在坏掉的库：
//  1. slog.Error——**连同这条审计的全部字段一起打**。库写不进去时，进程日志
//     （journald/容器 stdout）是这条记录唯一的幸存副本；只打一句"审计写入失败"
//     等于承认记录已永久丢失。这一层在磁盘写满时照样有效。
//  2. 进程内累计计数 + 最近一次错误 → GET /audit 的 writeHealth、/diag 的
//     audit-write 检查项。**读路径在写失败时仍然可用**，这是它的价值所在。
//  3. 业务告警规则 audit_write_fail（走消息通道外发）。这一层**在整盘写满时会
//     跟着失败**——RaiseAlert 自己也要落库。它覆盖的是可恢复的那半（写锁争用、
//     单表权限、瞬时 I/O 错误），不是全部。三层都写下来，才不会有人以为
//     "配了告警就一定收得到"。

// auditWriteHealth 审计写入的健康读数（进程内，重启归零）。
//
// 重启归零是有意的：它回答的是「本次运行以来丢过审计没有」。
// 落库来记录"审计落不了库"这件事本身是循环依赖——真发生时那条也写不进去。
type auditWriteHealth struct {
	// Failures 自进程启动以来 RecordAudit 返回错误的次数 = **丢失的审计条数**。
	Failures int64 `json:"failures"`
	// FirstAt / LastAt 首次与最近一次失败的 Unix 秒（0 = 从未失败）。
	// 两个都要：只有 LastAt 的话看不出"这是刚开始"还是"已经烂了三天"。
	FirstAt int64 `json:"firstAt,omitempty"`
	LastAt  int64 `json:"lastAt,omitempty"`
	// LastErr 最近一次的错误原文（"database or disk is full" 之类，直接决定下一步动作）。
	LastErr string `json:"lastErr,omitempty"`
	// LastEvent 最近一条没能落库的审计内容。让管理员看得见丢的是什么——
	// "管理员改了一条策略"与"某账号第 6 次登录失败"，取证价值天差地别。
	LastEvent string `json:"lastEvent,omitempty"`
}

// auditWriteTracker 审计写入失败的计数器。
//
// 独立于 Server.mu：那把锁保护网关注册表等热数据，而这里只在**失败时**才写，
// 挂上去只会让两组无关的争用互相干扰。
type auditWriteTracker struct {
	mu sync.Mutex
	h  auditWriteHealth
}

// note 记一次失败。返回累计次数，供调用方在日志里带上。
func (t *auditWriteTracker) note(now int64, e store.AuditEntry, err error) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.h.Failures++
	if t.h.FirstAt == 0 {
		t.h.FirstAt = now
	}
	t.h.LastAt = now
	t.h.LastErr = err.Error()
	t.h.LastEvent = e.Category + " · " + e.User + " · " + e.Event
	return t.h.Failures
}

// snapshot 取一份读数副本。
func (t *auditWriteTracker) snapshot() auditWriteHealth {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.h
}

// recordAudit 落一条审计，失败即发信号（见文件头三层信号的说明）。
//
// 返回值刻意丢弃：调用方（190+ 个审计点）**不该**因为审计写不进去就改变主操作的
// 结果。要改的是"有没有人知道"，不是"这次操作算不算数"。
func (s *Server) recordAudit(ctx context.Context, e store.AuditEntry) {
	if err := s.writer.RecordAudit(ctx, e); err != nil {
		n := s.auditWrite.note(time.Now().Unix(), e, err)
		// ★整条审计的字段都打进日志：库里没有了，这就是唯一副本。
		slog.Error("审计写入失败——该条记录未落库，本行是它仅存的副本",
			"err", err.Error(), "累计丢失", n,
			"ts", e.Time, "category", e.Category, "actor", e.User,
			"srcIp", e.SrcIP, "verdict", e.Verdict, "event", e.Event)
	}
}

// checkAuditWrite /diag 检查项：控制面自身有没有把审计写丢过。
//
// ★这一项**不查库**，读的是进程内计数——正因为它不依赖那个可能正在坏掉的库，
// 库彻底写不进去时它仍然能给出结论。与紧邻的 audit-disk（查库、看水位、预测未来）
// 是两件事：一个是"已经出事了"，一个是"快要出事了"。
func (s *Server) checkAuditWrite() DiagCheck {
	c := DiagCheck{Key: "audit-write", Category: "storage", Name: "审计写入链路"}
	h := s.auditWrite.snapshot()
	if h.Failures == 0 {
		c.Status = "pass"
		c.Metric = "本次运行以来 0 条写入失败"
		c.Summary = "全部审计写入均已落库"
		// ★进程重启即归零，必须说出来：否则"刚重启完看着全绿"会被当成"一直没事"。
		c.Hint = "计数随控制面进程重启归零；跨重启的历史请查进程日志中的「审计写入失败」行"
		return c
	}
	c.Status = "fail"
	c.Metric = fmt.Sprintf("已丢失 %d 条（首次 %s，最近 %s）",
		h.Failures, tsText(h.FirstAt), tsText(h.LastAt))
	c.Summary = "审计记录写入失败——这些行根本没有落库，防篡改链校验查不出它们的缺失"
	c.Hint = "错误：" + h.LastErr + "；最近一条丢失的记录：" + h.LastEvent +
		"。请查进程日志中的「审计写入失败」行取回全部内容，并排查磁盘余量与库文件可写性"
	return c
}

// tsText Unix 秒转本地时刻文本；0 回破折号。
func tsText(sec int64) string {
	if sec == 0 {
		return "—"
	}
	return time.Unix(sec, 0).Format("01-02 15:04:05")
}

// ── 审计留存轮转（按天 + 按磁盘水位，PRD FR-AUDIT-10）──

// auditPurger 审计轮转能力（SQLiteStore 实现；Memory 种子后端没有）。
type auditPurger interface {
	PurgeExpiredAudit(ctx context.Context, days int) (int64, error)
	PurgeAuditByDisk(ctx context.Context, maxPct int) (store.AuditDiskPurge, error)
}

// StartAuditPurgeLoop 起审计留存轮转：启动清一次 + 每 24h 一次。
//
// ★这条循环挂在 Server 上而不是留在 main 里，为的是**删除能落审计**：
// 审计被轮转掉与审计凭空少一段，在库里长得完全一样，区别只在有没有留下这条记录。
// 按天那一条是常规运维（只记日志），按水位那一条是**非常规的证据回收**，必须落审计。
func (s *Server) StartAuditPurgeLoop(ctx context.Context, days, maxDiskPct int) {
	p, ok := s.writer.(auditPurger)
	if !ok {
		return
	}
	s.auditMaxDiskPct = maxDiskPct // 供 /diag 如实说出「配没配水位上限」
	if days <= 0 && maxDiskPct <= 0 {
		slog.Warn("审计留存轮转未启用：既没有保留天数也没有磁盘水位上限，审计库会无界增长")
		return
	}
	s.purgeAuditOnce(ctx, p, days, maxDiskPct)
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			s.purgeAuditOnce(ctx, p, days, maxDiskPct)
		}
	}()
}

// purgeAuditOnce 跑一轮：先按天，再按水位。
//
// 顺序有讲究：按天是既定留存策略（"180 天以外的本就不该留"），按水位是**超出策略的
// 额外回收**。先跑按天，能靠常规策略解决就不动用非常规的那条。
func (s *Server) purgeAuditOnce(ctx context.Context, p auditPurger, days, maxDiskPct int) {
	if days > 0 {
		n, err := p.PurgeExpiredAudit(ctx, days)
		switch {
		case err != nil:
			slog.Error("审计留存轮转失败（按天）", "err", err.Error())
		case n > 0:
			slog.Info("审计留存轮转完成（按天）", "deleted", n, "retentionDays", days)
		}
	}
	if maxDiskPct <= 0 {
		return
	}
	r, err := p.PurgeAuditByDisk(ctx, maxDiskPct)
	if err != nil {
		slog.Error("审计留存轮转失败（按磁盘水位）", "err", err.Error())
		// ★失败也要留痕：这条路径的失败意味着"该回收没回收"，磁盘会继续涨。
		s.auditBG(ctx, "system", fmt.Sprintf(
			"审计按磁盘水位回收失败（阈值 %d%%）：%s", maxDiskPct, err.Error()), "fail")
		return
	}
	if !r.Measurable {
		slog.Warn("审计磁盘水位不可判定，本轮不按水位回收", "note", r.Note)
		return
	}
	if !r.Triggered {
		return
	}
	// 删了证据就必须说清楚：删了多少、删到哪天、当时水位多少、为什么停。
	msg := fmt.Sprintf(
		"审计按磁盘水位回收：删除 %d 条（%d 天），触发水位 %d%%（审计库占文件系统，阈值 %d%%）；"+
			"现存最早记录 %s。★库文件不会因此变小（SQLite 未 VACUUM 不还盘），"+
			"腾出的空间由后续写入复用——效果是止住增长而不是缩小占用",
		r.Deleted, r.Days, r.UsedPct, r.MaxPct, orDashText(r.OldestKept))
	if r.Note != "" {
		msg += "；" + r.Note
	}
	slog.Warn("审计按磁盘水位回收", "deleted", r.Deleted, "days", r.Days,
		"usedPct", r.UsedPct, "maxPct", r.MaxPct, "note", r.Note)
	s.auditBG(ctx, "system", msg, "ok")
}

// orDashText 空串回破折号。
func orDashText(v string) string {
	if v == "" {
		return "—"
	}
	return v
}
