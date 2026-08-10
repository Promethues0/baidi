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

// RecordAudit 追加一条审计日志条目并接入防篡改链。
// 读链尾与插入在同一事务内（DSN _txlock=immediate 起手即写锁）：并发落库不会分叉出两条同 prev 的链。
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
	mac := auditMAC(s.auditKey, prevMac, e.Time, e.Category, e.User, e.SrcIP, e.Event, e.Verdict)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log(ts,category,actor,src_ip,event,verdict,seq,mac) VALUES(?,?,?,?,?,?,?,?)`,
		e.Time, e.Category, e.User, e.SrcIP, e.Event, e.Verdict, prevSeq+1, mac); err != nil {
		return err
	}
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
	cutoff := time.Now().AddDate(0, 0, -days).Format("2006-01-02 15:04:05")
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
// category 空 = 全部；from/to 为与 ts 同构的可比字符串（"2006-01-02 15:04:05"），空 = 不限。
func (s *SQLiteStore) ExportAudit(ctx context.Context, category, from, to string, fn func(AuditEntry) error) error {
	q := `SELECT COALESCE(ts,''), COALESCE(category,''), COALESCE(actor,''), COALESCE(src_ip,''),
		COALESCE(event,''), COALESCE(verdict,'') FROM audit_log`
	var conds []string
	var args []any
	if category != "" {
		conds = append(conds, "category=?")
		args = append(args, category)
	}
	if from != "" {
		conds = append(conds, "ts>=?")
		args = append(args, from)
	}
	if to != "" {
		conds = append(conds, "ts<=?")
		args = append(args, to)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Time, &e.Category, &e.User, &e.SrcIP, &e.Event, &e.Verdict); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Audit 覆盖：日志从 audit_log 实时读取（最近 200 条），分类计数与今日总量按库聚合；
// 磁盘水位等静态指标沿用 Memory 种子。
func (s *SQLiteStore) Audit(ctx context.Context) (AuditBundle, error) {
	base, _ := s.Memory.Audit(ctx) // 复用 Disk 等静态字段
	out := AuditBundle{Disk: base.Disk, Categories: []KV{}, Logs: []AuditEntry{}}

	rows, err := s.db.QueryContext(ctx, `SELECT ts,category,actor,src_ip,event,verdict FROM audit_log ORDER BY id DESC LIMIT 200`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Time, &e.Category, &e.User, &e.SrcIP, &e.Event, &e.Verdict); err != nil {
			rows.Close()
			return out, err
		}
		out.Logs = append(out.Logs, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	// 分类计数（全表），按固定顺序铺满四类（缺失类计 0）。
	counts := map[string]int{}
	crows, err := s.db.QueryContext(ctx, `SELECT category, COUNT(*) FROM audit_log GROUP BY category`)
	if err != nil {
		return out, err
	}
	for crows.Next() {
		var cat string
		var n int
		if err := crows.Scan(&cat, &n); err != nil {
			crows.Close()
			return out, err
		}
		counts[cat] = n
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return out, err
	}
	labels := []struct{ key, label string }{
		{"access", "访问决策"}, {"auth", "登录认证"}, {"admin", "管理操作"}, {"security", "安全事件"},
	}
	for _, l := range labels {
		out.Categories = append(out.Categories, KV{Name: l.label, Value: counts[l.key]})
	}

	today := time.Now().Format("2006-01-02")
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE ts LIKE ?`, today+"%").Scan(&out.TodayTotal)
	return out, nil
}
