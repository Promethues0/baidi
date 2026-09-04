package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm3"
)

// ── 真实审计日志（管理操作 / 安全事件实时落库；覆盖 Memory 静态种子）──
//
// 防篡改：每行落库时算 mac = HMAC-SM3(key, prev_mac ‖ ts ‖ category ‖ actor ‖ src_ip ‖ event ‖ verdict)，
// 前后行经 prev_mac 串成链。持库文件写权限者改任何一行（或抽掉中间一行），
// VerifyAuditChain 全链重算即指出首个断点——审计的价值就在「事后不可抵赖」，
// 没有链时 UPDATE audit_log 一句话就能无痕洗白。
// SM3 与国密隧道同源（emmansun/gmsm，gateway 已用同一家，不引第二个国密依赖）。

// auditGenesis 链头的固定创世 prev（首条记录以它为 prev_mac 输入）。
const auditGenesis = "baidi-audit-genesis-v1"

// auditMAC 计算一条审计记录的链式 MAC（hex 小写）。
// 字段间以 \n 定界：裸拼接会让 ("ab","c") 与 ("a","bc") 同 MAC，字段间搬运内容不破链。
// 审计字段本身是单行文本（事件文案由代码常量拼出，不含换行），\n 不会出现在字段内。
func auditMAC(key []byte, prev, ts, category, actor, srcIP, event, verdict string) string {
	h := hmac.New(sm3.New, key)
	for i, f := range []string{prev, ts, category, actor, srcIP, event, verdict} {
		if i > 0 {
			h.Write([]byte{'\n'})
		}
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// loadOrCreateAuditKey 载入/生成审计链 HMAC 密钥（32 字节随机，hex 存盘）。
// 骨架照抄 auth/keys.go 的私钥落盘做法：0600 + 同目录临时文件原子改名。
func loadOrCreateAuditKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		key, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(key) < 16 {
			return nil, fmt.Errorf("密钥文件损坏（应为 ≥16 字节的 hex）: %s", path)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return key, nil
}

// rowQueryer 让链尾/锚点查询既能跑在 *sql.DB 也能跑在 *sql.Tx 上。
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// auditAnchor 读留存轮转后的链锚点（被清理段末行的 seq/mac）；从未轮转过即创世 (0, genesis)。
func auditAnchor(ctx context.Context, q rowQueryer) (seq int64, mac string, err error) {
	err = q.QueryRowContext(ctx, `SELECT v FROM audit_meta WHERE k='audit_anchor_mac'`).Scan(&mac)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, auditGenesis, nil
	}
	if err != nil {
		return 0, "", err
	}
	var seqStr string
	if err = q.QueryRowContext(ctx, `SELECT v FROM audit_meta WHERE k='audit_anchor_seq'`).Scan(&seqStr); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, "", err
	}
	seq, _ = strconv.ParseInt(seqStr, 10, 64)
	return seq, mac, nil
}

// auditChainTail 取链尾（最后一条已入链行的 seq/mac）；表空/全空时回退锚点或创世。
func auditChainTail(ctx context.Context, q rowQueryer) (seq int64, mac string, err error) {
	err = q.QueryRowContext(ctx,
		`SELECT COALESCE(seq,0), mac FROM audit_log WHERE mac IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&seq, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return auditAnchor(ctx, q)
	}
	if err != nil {
		return 0, "", err
	}
	return seq, mac, nil
}

// RecordAudit 追加一条审计日志条目并接入防篡改链，同时给启用中的外送出口入队。
// 读链尾与插入在同一事务内（DSN _txlock=immediate 起手即写锁）：并发落库不会分叉出两条同 prev 的链。
//
// ★外送入队与审计插入同事务（见 enqueueAuditForward 的注释）：
// 分两步写的话，进程在两步之间退出就会留下一条永远不会被外送的审计，两端都无痕。
func (s *SQLiteStore) RecordAudit(ctx context.Context, e AuditEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	prevSeq, prevMac, err := auditChainTail(ctx, tx)
	if err != nil {
		return err
	}
	// ★时刻缺失就补服务端当前时间。空 ts 是一种很坏的行：它对**所有按时间窗的查询**
	// 不可见（`ts >= cutoff` 恒假），却会被留存轮转删掉（`ts < cutoff` 恒真）——
	// 也就是"查不到但会消失"。自 wave8 行动 9 起态势总览按窗口聚合，这条路径必须堵上。
	// 补的是落库时刻而不是拒绝写入：审计是 best-effort 通道，宁可时间略有偏差也不能丢记录。
	if strings.TrimSpace(e.Time) == "" {
		e.Time = time.Now().Format("2006-01-02 15:04:05")
	}
	e.Seq = prevSeq + 1
	e.MAC = auditMAC(s.auditKey, prevMac, e.Time, e.Category, e.User, e.SrcIP, e.Event, e.Verdict)
	res, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log(ts,category,actor,src_ip,event,verdict,seq,mac) VALUES(?,?,?,?,?,?,?,?)`,
		e.Time, e.Category, e.User, e.SrcIP, e.Event, e.Verdict, e.Seq, e.MAC)
	if err != nil {
		return err
	}
	auditID, _ := res.LastInsertId()
	// 入队用的是**刚算出来的 seq/mac**，与库里那一行逐字节相同——外送出去的
	// 就是审计表里的那一条，不是"另算一份"。
	s.enqueueAuditForward(ctx, tx, auditID, e)
	return tx.Commit()
}

// backfillAuditChain 为既有行补算 seq/mac 全链（migrate 一次性调用，幂等）：
// 按 rowid（id）顺序走全表，已有 mac 的行跳过、其 mac 作为后继的 prev；只 UPDATE mac 为空的行。
// ★补列迁移必须配回填：只加列不填值时，旧行 mac 永久 NULL，verify 会把整条历史当断链。
func (s *SQLiteStore) backfillAuditChain() error {
	ctx := context.Background()
	var pending int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE mac IS NULL`).Scan(&pending); err != nil {
		return err
	}
	if pending == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	prevSeq, prevMac, err := auditAnchor(ctx, tx)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(ts,''), COALESCE(category,''), COALESCE(actor,''),
		COALESCE(src_ip,''), COALESCE(event,''), COALESCE(verdict,''), seq, mac FROM audit_log ORDER BY id`)
	if err != nil {
		return err
	}
	type upd struct {
		id, seq int64
		mac     string
	}
	var updates []upd
	for rows.Next() {
		var id int64
		var ts, cat, actor, ip, ev, vd string
		var seqN sql.NullInt64
		var macN sql.NullString
		if err := rows.Scan(&id, &ts, &cat, &actor, &ip, &ev, &vd, &seqN, &macN); err != nil {
			rows.Close()
			return err
		}
		if macN.Valid && macN.String != "" {
			prevMac, prevSeq = macN.String, seqN.Int64
			continue
		}
		prevSeq++
		prevMac = auditMAC(s.auditKey, prevMac, ts, cat, actor, ip, ev, vd)
		updates = append(updates, upd{id: id, seq: prevSeq, mac: prevMac})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, u := range updates {
		if _, err := tx.ExecContext(ctx, `UPDATE audit_log SET seq=?, mac=? WHERE id=?`, u.seq, u.mac, u.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// VerifyAuditChain 从锚点（或创世）起全链重算 MAC，指出首个断点。
// 只读不写：verify 本身不该在审计表上留下任何副作用。
func (s *SQLiteStore) VerifyAuditChain(ctx context.Context) (AuditVerifyResult, error) {
	_, prev, err := auditAnchor(ctx, s.db)
	if err != nil {
		return AuditVerifyResult{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(seq,0), COALESCE(ts,''), COALESCE(category,''),
		COALESCE(actor,''), COALESCE(src_ip,''), COALESCE(event,''), COALESCE(verdict,''), COALESCE(mac,'')
		FROM audit_log ORDER BY id`)
	if err != nil {
		return AuditVerifyResult{}, err
	}
	defer rows.Close()
	out := AuditVerifyResult{OK: true}
	for rows.Next() {
		var seq int64
		var ts, cat, actor, ip, ev, vd, mac string
		if err := rows.Scan(&seq, &ts, &cat, &actor, &ip, &ev, &vd, &mac); err != nil {
			return AuditVerifyResult{}, err
		}
		if auditMAC(s.auditKey, prev, ts, cat, actor, ip, ev, vd) != mac {
			return AuditVerifyResult{OK: false, Checked: out.Checked, BrokenAt: seq}, nil
		}
		prev = mac
		out.Checked++
	}
	return out, rows.Err()
}

// PurgeExpiredAudit 清理 days 天前的审计行（days<=0 不清理），返回删除行数。
// 划界按链序而非逐行看 ts：以「ts 已过期的最大 id」为边界整段删除，保证留下的是链的
// 连续后缀；随后把被删段末行的 seq/mac 写进 audit_meta 作锚点——没有锚点，
// 轮转等于亲手打断链，verify 会把首条留存行误判为篡改。
func (s *SQLiteStore) PurgeExpiredAudit(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	return s.purgeAuditBefore(ctx, time.Now().AddDate(0, 0, -days).Format("2006-01-02 15:04:05"))
}

// purgeAuditBefore 删除 ts < cutoff 的整段并落链锚点（按天留存与按水位轮转共用）。
// 划界与锚点的理由见 PurgeExpiredAudit 的注释——两条路径必须**共用**这一处实现，
// 各写一份的话总有一条会忘记落锚点，而症状是 verify 把首条留存行报成篡改。
func (s *SQLiteStore) purgeAuditBefore(ctx context.Context, cutoff string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var bid, bseq int64
	var bmac string
	err = tx.QueryRowContext(ctx,
		`SELECT id, COALESCE(seq,0), COALESCE(mac,'') FROM audit_log WHERE ts < ? ORDER BY id DESC LIMIT 1`,
		cutoff).Scan(&bid, &bseq, &bmac)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE id <= ?`, bid)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	for k, v := range map[string]string{
		"audit_anchor_mac": bmac,
		"audit_anchor_seq": strconv.FormatInt(bseq, 10),
	} {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO audit_meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v); err != nil {
			return 0, err
		}
	}
	return n, tx.Commit()
}

// ExportAudit 按条件流式遍历审计行（id 升序 = 落库序），逐行回调，不整表进内存。
//
// ★条件与 SearchAudit **共用 auditWhere**：此前这里自己拼了一份，只认
// category/from/to 三维，账号与源 IP 两维压根传不进来——而页面上刚筛过的正是那两维。
// 症状是「屏幕上筛出 12 条、导出的 CSV 里是 8 万条」，而管理员会以为这份 CSV
// 就是他刚才看到的那些行，拿去交差。
//
// AuditQuery 的 Limit/Offset 在这里刻意忽略：导出的定位就是**不受页面上限约束**
// 的全量出口（列表那半边有 500 上限并会当面说明被截断）。
func (s *SQLiteStore) ExportAudit(ctx context.Context, aq AuditQuery, fn func(AuditEntry) error) error {
	// seq/mac 与列表、外送同源：导出的 CSV 也要能被拿去独立验链，
	// 否则"导出一份给审计方"交出去的只是一堆无法自证的文本。
	cond, args := auditWhere(aq)
	q := `SELECT COALESCE(ts,''), COALESCE(category,''), COALESCE(actor,''), COALESCE(src_ip,''),
		COALESCE(event,''), COALESCE(verdict,''), COALESCE(seq,0), COALESCE(mac,'') FROM audit_log WHERE ` +
		cond + ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Time, &e.Category, &e.User, &e.SrcIP, &e.Event, &e.Verdict, &e.Seq, &e.MAC); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// SetAuditRetentionDays 注入审计留存天数的展示值。
// 调用点只有 main：把 purge 循环真正消费的 cfg.AuditRetentionDays 原样传进来，
// 保证审计页/诊断页展示的留存天数就是清理任务在用的那一份。
func (s *SQLiteStore) SetAuditRetentionDays(days int) {
	s.auditRetainDays = days
}

// AuditDiskStat 实测审计存储水位：行数 COUNT(*) + 库文件（含 WAL/SHM）大小 + 文件系统余量。
// 此前诊断页的"占用 62%"是 Memory 种子编的——运维对着编造的水位做不了任何决策。
func (s *SQLiteStore) AuditDiskStat(ctx context.Context) (AuditDiskStat, error) {
	d := AuditDiskStat{RetainDays: s.auditRetainDays}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&d.Rows); err != nil {
		return d, err
	}
	// WAL 模式下热数据可能大部分躺在 -wal 里，只量主库会明显偏小。
	for _, p := range []string{s.path, s.path + "-wal", s.path + "-shm"} {
		if fi, err := os.Stat(p); err == nil {
			d.DBBytes += fi.Size()
		}
	}
	d.FSTotalBytes, d.FSFreeBytes, d.FSSupported = fsUsage(filepath.Dir(s.path))
	return d, nil
}

// Audit 覆盖：日志从 audit_log 实时读取（最近 200 条），分类计数与今日总量按库聚合；
// 磁盘水位改为实测（AuditDiskStat），不再沿用 Memory 种子的编造值。
func (s *SQLiteStore) Audit(ctx context.Context) (AuditBundle, error) {
	out := AuditBundle{Categories: []KV{}, Logs: []AuditEntry{}}
	if ds, err := s.AuditDiskStat(ctx); err == nil {
		out.Disk = ds.ToDiskStat()
	}

	// 带上 seq/mac：列表、CSV 导出、外送三个出口同源（见 AuditEntry 的注释）。
	rows, err := s.db.QueryContext(ctx, auditRecentSQL)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Time, &e.Category, &e.User, &e.SrcIP, &e.Event, &e.Verdict, &e.Seq, &e.MAC); err != nil {
			rows.Close()
			return out, err
		}
		out.Logs = append(out.Logs, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	// 分类计数（全表口径，与页面「条 · 累计留痕」的文案一致），按固定顺序铺满全部类别
	// （缺失类计 0）。语义与改造前那条全表 GROUP BY 逐字相同，只是不再每请求重算——
	// 200 万行时它自己就要 1.32s，而大屏每 15s 打一发。理由与增量条件见 auditcat_sqlite.go。
	counts, err := s.auditCategoryCounts(ctx)
	if err != nil {
		return out, err
	}
	// 类别卡走唯一字典（见 AuditCategories）：此前这里手抄了一份，漏掉 policy/system，
	// 于是「保存安全基线」这类记录写进了库、却不在任何一张卡的计数里——
	// 卡片加起来比库里的总行数少，而少的那几条恰好是安全管理动作。
	for _, c := range AuditCategories {
		out.Categories = append(out.Categories, KV{Name: c.Label, Value: counts[c.Key]})
	}

	// 今日总量用**半开区间**而不是 `ts LIKE '今天%'`：参数化的 LIKE 里 SQLite 看不出
	// 那是个前缀常量，无论有没有索引都只能逐行比——200 万行实测无索引 321ms，
	// 建了 ts 索引也只是把全表扫换成全索引扫（225ms，计划里是 SCAN 不是 SEARCH）。
	// 换成 ts>=? AND ts<? 是一次索引定位 + 区间扫，实测 2ms。
	// 上界取次日零点（不含），别写成「今天 23:59:59」——那会漏掉 23:59:59 与
	// 次日零点之间那一秒里落的行，而这种缺一秒的账没人对得出来。
	today := time.Now()
	_ = s.db.QueryRowContext(ctx, auditTodayCountSQL,
		today.Format("2006-01-02")+" 00:00:00",
		today.AddDate(0, 0, 1).Format("2006-01-02")+" 00:00:00").Scan(&out.TodayTotal)
	return out, nil
}

// 首屏取行与今日总量的 SQL 抽成常量：EQP 守卫（audit_index_test.go）测的必须是
// **生产在跑的那一条**，测试里另抄一份的话，改了生产语句而守卫仍绿，等于没守。
const (
	// auditRecentSQL 首屏最近 200 条。
	//
	// ★`ORDER BY ts DESC, id DESC` 而不是原来的 `ORDER BY id DESC`：ts 索引的索引项
	// 就是 (ts, rowid)，这个排序恰是它的逆序，于是取一页 = 从索引尾部倒读，不用排序。
	// 另一半理由是**一致性**：SearchAudit 用的是同一个序，页面在"首屏快照"与
	// "检索结果"之间来回切时，同一批行的先后不该变。
	//
	// 代价说清楚：ts 为空的历史行（RecordAudit 补时刻之前落的）在 DESC 下排到最末，
	// 而改造前它们按 id 混在正常行里。这类行对所有按时间窗的查询本来就不可见
	// （见 RecordAudit 里那段注释），排在末尾与排在中间同样查不到它——不新增失效形态。
	auditRecentSQL = `SELECT ts,category,actor,src_ip,event,verdict,
COALESCE(seq,0),COALESCE(mac,'') FROM audit_log ORDER BY ts DESC, id DESC LIMIT 200`
	// auditTodayCountSQL 今日总量（半开区间，理由见调用点）。
	auditTodayCountSQL = `SELECT COUNT(*) FROM audit_log WHERE ts>=? AND ts<?`
)
