package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
)

// ★编译期钉住：AuditForwardStore 不在 Store 接口里，coverage_guard_test 的
// 「漏写方法就静默落回 Memory 种子」守卫覆盖不到它。这一行是它的替代守卫——
// 接口加方法而这里没实现时，编译直接失败，而不是等到运行期发现类型断言不成立、
// 外送端点集体回 503。
var _ AuditForwardStore = (*SQLiteStore)(nil)

const auditFwdCols = `id,name,kind,enabled,config,start_audit_id,last_status,last_detail,last_at,last_ok_at,dropped,created_at,updated_at`

func (s *SQLiteStore) scanAuditForwardTarget(row interface{ Scan(...any) error }) (AuditForwardTarget, error) {
	var r AuditForwardTarget
	var enabled int
	var lastStatus, lastDetail sql.NullString
	var lastAt, lastOKAt, dropped, startID sql.NullInt64
	err := row.Scan(&r.ID, &r.Name, &r.Kind, &enabled, &r.Config, &startID,
		&lastStatus, &lastDetail, &lastAt, &lastOKAt, &dropped, &r.CreatedAt, &r.UpdatedAt)
	r.Enabled = enabled != 0
	r.StartAuditID = startID.Int64
	r.LastStatus, r.LastDetail = lastStatus.String, lastDetail.String
	r.LastAt, r.LastOKAt, r.Dropped = lastAt.Int64, lastOKAt.Int64, dropped.Int64
	return r, err
}

// AuditForwardTargets 返回全部外送出口（按创建时间）。响应里绝不含密文，只补元信息与积压数。
func (s *SQLiteStore) AuditForwardTargets(ctx context.Context) ([]AuditForwardTarget, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+auditFwdCols+` FROM audit_forward_targets ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditForwardTarget{}
	for rows.Next() {
		r, err := s.scanAuditForwardTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		has, fp, err := s.auditForwardSecretMeta(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].HasSecret, out[i].SecretFingerprint = has, fp
		if out[i].Queued, err = s.auditForwardQueued(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *SQLiteStore) AuditForwardTargetByID(ctx context.Context, id string) (AuditForwardTarget, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+auditFwdCols+` FROM audit_forward_targets WHERE id=?`, id)
	r, err := s.scanAuditForwardTarget(row)
	if err == sql.ErrNoRows {
		return AuditForwardTarget{}, false, nil
	}
	if err != nil {
		return AuditForwardTarget{}, false, err
	}
	has, fp, err := s.auditForwardSecretMeta(ctx, id)
	if err != nil {
		return AuditForwardTarget{}, false, err
	}
	r.HasSecret, r.SecretFingerprint = has, fp
	if r.Queued, err = s.auditForwardQueued(ctx, id); err != nil {
		return AuditForwardTarget{}, false, err
	}
	return r, true, nil
}

// auditForwardQueued 现算某出口的积压条数。
func (s *SQLiteStore) auditForwardQueued(ctx context.Context, id string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_forward_queue WHERE target_id=?`, id).Scan(&n)
	return n, err
}

// SaveAuditForwardTarget 新增 / 修改一个外送出口（upsert）。
//
// ★ON CONFLICT 分支刻意不含 created_at / start_audit_id，也**不碰 last_*、dropped**：
//   - 改一次配置就重置 start_audit_id，会让页面上"自 #N 起外送"随手变成一个假的水位；
//   - 覆盖 last_*（哪怕只是清空）等于让保存动作伪造一次"发送状态"，
//     而那几列的全部意义就是"真正发出去那一次的结果"；
//   - dropped 是累计事实，保存配置抹不掉已经丢过的那些条。
func (s *SQLiteStore) SaveAuditForwardTarget(ctx context.Context, rec AuditForwardTarget) (AuditForwardTarget, error) {
	if strings.TrimSpace(rec.ID) == "" {
		rec.ID = "af-" + uuid.NewString()[:8]
	}
	if strings.TrimSpace(rec.Config) == "" {
		rec.Config = "{}"
	}
	// 新建时把当前审计链尾的 id 记下来：这是"历史不会补发"这句话的依据。
	var startID int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(id),0) FROM audit_log`).Scan(&startID); err != nil {
		return AuditForwardTarget{}, err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_forward_targets(`+auditFwdCols+`)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind,
  enabled=excluded.enabled, config=excluded.config, updated_at=excluded.updated_at`,
		rec.ID, rec.Name, rec.Kind, b2i(rec.Enabled), rec.Config, startID,
		"", "", 0, 0, 0, nowStr(), nowStr())
	if err != nil {
		return AuditForwardTarget{}, err
	}
	out, _, err := s.AuditForwardTargetByID(ctx, rec.ID)
	return out, err
}

// DeleteAuditForwardTarget 删除出口，连同它的凭据与队列积压。
//
// ★凭据必须一起删：留着孤儿密文行的话，管理员删掉再用**同一个 id** 重建时，
// 新出口会静默继承旧凭据——一条谁都不记得设过的 token。
// ★队列也必须一起删：留着的话它永远不会被消费（没有出口去取它），
// 只是白白占着上界的名额，最终把一个**还活着的**出口挤到开始丢弃。
func (s *SQLiteStore) DeleteAuditForwardTarget(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM audit_forward_secrets WHERE target_id=?`,
		`DELETE FROM audit_forward_queue WHERE target_id=?`,
		`DELETE FROM audit_forward_targets WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// auditForwardSecretMeta 只读凭据的**元信息**（是否存在 + 指纹），绝不触碰密文。
func (s *SQLiteStore) auditForwardSecretMeta(ctx context.Context, id string) (bool, string, error) {
	var fp sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT fingerprint FROM audit_forward_secrets WHERE target_id=?`, id).Scan(&fp)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, fp.String, nil
}

func (s *SQLiteStore) SaveAuditForwardSecret(ctx context.Context, sec AuditForwardSecret) error {
	if strings.TrimSpace(sec.TargetID) == "" {
		return fmt.Errorf("审计外送凭据缺少 target id（AAD 就是它，不能为空）")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_forward_secrets(target_id,nonce,cipher,fingerprint,updated_at) VALUES(?,?,?,?,?)
ON CONFLICT(target_id) DO UPDATE SET nonce=excluded.nonce, cipher=excluded.cipher,
  fingerprint=excluded.fingerprint, updated_at=excluded.updated_at`,
		sec.TargetID, sec.Nonce, sec.Cipher, sec.Fingerprint, nowStr())
	return err
}

func (s *SQLiteStore) AuditForwardSecret(ctx context.Context, id string) (AuditForwardSecret, bool, error) {
	sec := AuditForwardSecret{TargetID: id}
	err := s.db.QueryRowContext(ctx,
		`SELECT nonce,cipher FROM audit_forward_secrets WHERE target_id=?`, id).Scan(&sec.Nonce, &sec.Cipher)
	if err == sql.ErrNoRows {
		return AuditForwardSecret{}, false, nil
	}
	if err != nil {
		return AuditForwardSecret{}, false, err
	}
	return sec, true, nil
}

// ── 队列 ──

// SetAuditForwardQueueMax 注入每出口的队列上界。
// 调用点只有 main：把入队路径真正消费的那份配置原样传进来，
// 保证外送页显示的"上界"就是丢弃判据在用的那一份（同 SetAuditRetentionDays）。
func (s *SQLiteStore) SetAuditForwardQueueMax(n int) {
	if n <= 0 {
		n = DefaultForwardQueueMax
	}
	s.fwdQueueMax = n
}

// AuditForwardQueueMax 当前生效的队列上界。
func (s *SQLiteStore) AuditForwardQueueMax() int {
	if s.fwdQueueMax <= 0 {
		return DefaultForwardQueueMax
	}
	return s.fwdQueueMax
}

// enqueueAuditForward 在**审计落库的同一个事务里**给每个启用中的出口入队一行。
//
// ★为什么在同一个事务：审计行与它的外送任务必须同生共死。分两步写的话，
// 进程在两步之间退出就会留下一条永远不会被外送的审计——而这条缺失在两端都无痕。
//
// ★为什么入队失败不回滚：审计落库的优先级严格高于外送。这里的错误只可能是
// 存储层故障（队列表被删/磁盘满），此时"少一条外送"远好过"少一条审计"。
// 但它必须留痕：slog.Error 出去，否则就成了本项目最讨厌的静默失效。
func (s *SQLiteStore) enqueueAuditForward(ctx context.Context, tx *sql.Tx, auditID int64, e AuditEntry) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM audit_forward_targets WHERE enabled=1`)
	if err != nil {
		slog.Error("审计外送入队失败：读取出口清单出错，本条审计不会被外送（审计本身已落库）", "err", err.Error())
		return
	}
	var targets []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			slog.Error("审计外送入队失败：出口清单扫描出错", "err", err.Error())
			return
		}
		targets = append(targets, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		slog.Error("审计外送入队失败：出口清单读取出错", "err", err.Error())
		return
	}

	max := s.AuditForwardQueueMax()
	for _, tid := range targets {
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM audit_forward_queue WHERE target_id=?`, tid).Scan(&n); err != nil {
			slog.Error("审计外送入队失败：积压计数出错", "target", tid, "err", err.Error())
			continue
		}
		if n >= max {
			// ★丢新保旧：留下的是**连续的最早一段**，SIEM 侧的 seq 链因此仍然连续，
			// 只是在某个点之后断了口。丢旧保新会在中间挖洞，链校验从此处处报错，
			// 谁也说不清是被篡改了还是只是溢出过。
			if _, err := tx.ExecContext(ctx,
				`UPDATE audit_forward_targets SET dropped=COALESCE(dropped,0)+1 WHERE id=?`, tid); err != nil {
				slog.Error("审计外送丢弃计数写入失败", "target", tid, "err", err.Error())
			}
			slog.Warn("审计外送队列已满，丢弃一条待外送记录（审计本身已落库，只是不会送到 SIEM）",
				"target", tid, "queueMax", max, "seq", e.Seq)
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO audit_forward_queue(target_id,audit_id,ts,category,actor,src_ip,event,verdict,seq,mac,attempts,next_at,last_error,created_at)
			 VALUES(?,?,?,?,?,?,?,?,?,?,0,0,'',?)`,
			tid, auditID, e.Time, e.Category, e.User, e.SrcIP, e.Event, e.Verdict, e.Seq, e.MAC, nowStr()); err != nil {
			slog.Error("审计外送入队失败：写队列出错，本条审计不会被外送（审计本身已落库）",
				"target", tid, "err", err.Error())
		}
	}
}

// ClaimAuditForwardBatch 取一批到期可发的记录（id 升序 = 审计落库序）。
//
// 单进程单 worker，故不做"认领"标记：多标一次状态就多一处会卡在中间态的地方
// （worker 崩在标记之后、发送之前，那批就永远是"发送中"）。
func (s *SQLiteStore) ClaimAuditForwardBatch(ctx context.Context, targetID string, now int64, limit int) ([]AuditForwardItem, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,target_id,COALESCE(ts,''),COALESCE(category,''),COALESCE(actor,''),COALESCE(src_ip,''),
		        COALESCE(event,''),COALESCE(verdict,''),COALESCE(seq,0),COALESCE(mac,''),COALESCE(attempts,0)
		 FROM audit_forward_queue WHERE target_id=? AND COALESCE(next_at,0)<=? ORDER BY id LIMIT ?`,
		targetID, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditForwardItem{}
	for rows.Next() {
		var it AuditForwardItem
		if err := rows.Scan(&it.ID, &it.TargetID, &it.Entry.Time, &it.Entry.Category, &it.Entry.User,
			&it.Entry.SrcIP, &it.Entry.Event, &it.Entry.Verdict, &it.Entry.Seq, &it.Entry.MAC,
			&it.Attempts); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// AckAuditForwardBatch 整批出队。只在真的发送成功之后调用。
func (s *SQLiteStore) AckAuditForwardBatch(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	q := `DELETE FROM audit_forward_queue WHERE id IN (` + placeholders(len(ids)) + `)`
	_, err := s.db.ExecContext(ctx, q, int64sToAny(ids)...)
	return err
}

// RetryAuditForwardBatch 整批留队：计次 +1、推迟到 nextAt、记下失败原因。
// **绝不删行**——外送失败不丢审计这条要求，物理上就落在这个方法只写不删上。
func (s *SQLiteStore) RetryAuditForwardBatch(ctx context.Context, ids []int64, nextAt int64, detail string) error {
	if len(ids) == 0 {
		return nil
	}
	if len([]rune(detail)) > 256 {
		detail = string([]rune(detail)[:256]) + "…"
	}
	args := append([]any{nextAt, detail}, int64sToAny(ids)...)
	_, err := s.db.ExecContext(ctx,
		`UPDATE audit_forward_queue SET attempts=COALESCE(attempts,0)+1, next_at=?, last_error=?
		 WHERE id IN (`+placeholders(len(ids))+`)`, args...)
	return err
}

// RecordAuditForwardResult 记一次已经发生的发送结果。
//
// detail 截断到 512 字符：它来自对端的错误信息，一个返回整页 HTML 的收集器
// 能把这一列撑成几十 KB × 每一轮 pump。
func (s *SQLiteStore) RecordAuditForwardResult(ctx context.Context, id, status, detail string, at int64) error {
	if len([]rune(detail)) > 512 {
		detail = string([]rune(detail)[:512]) + "…"
	}
	if status == AuditForwardOK {
		_, err := s.db.ExecContext(ctx,
			`UPDATE audit_forward_targets SET last_status=?, last_detail=?, last_at=?, last_ok_at=? WHERE id=?`,
			status, detail, at, at, id)
		return err
	}
	// 失败**不碰 last_ok_at**：那一格的意义是"最后一次真的送达是什么时候"，
	// 运维就是靠"上次成功距今多久"判断外送是不是已经断了。
	_, err := s.db.ExecContext(ctx,
		`UPDATE audit_forward_targets SET last_status=?, last_detail=?, last_at=? WHERE id=?`,
		status, detail, at, id)
	return err
}

// ResetAuditForwardBackoff 清零某出口队列的退避（「立即投递」用），返回受影响条数。
// 只动 next_at：attempts 记的是"这批已经失败过几次"，是事实，手动重试抹不掉它。
func (s *SQLiteStore) ResetAuditForwardBackoff(ctx context.Context, targetID string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE audit_forward_queue SET next_at=0 WHERE target_id=? AND COALESCE(next_at,0)>0`, targetID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// placeholders 生成 "?,?,?"。
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func int64sToAny(ids []int64) []any {
	out := make([]any, 0, len(ids))
	for _, v := range ids {
		out = append(out, v)
	}
	return out
}

// auditForwardEnabledCount 启用中的出口数（诊断/测试用）。
func (s *SQLiteStore) auditForwardEnabledCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_forward_targets WHERE enabled=1`).Scan(&n)
	return n, err
}
