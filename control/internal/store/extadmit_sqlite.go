package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// 审批单的种类（approvals.kind）。
//
// ★这一列是**必需的**，不是分类装饰：`DecideApproval` 走的是设备联动路径
// （同事务把 trusted_devices 置 trusted/revoked）。外部准入单要是混在同一张表里
// 而没有 kind，管理员点「批准」时那条路径会查不到设备、按「迁移前遗留的单子」
// 处理——审批单变成 approved，而那个人**仍然进不来**，且两侧都不报错。
const (
	ApprovalKindDevice  = "device"
	ApprovalKindExtUser = "extuser"
)

// ExtAdmission 按 (源, subject) 查准入登记。
func (s *SQLiteStore) ExtAdmission(ctx context.Context, sourceID, subject string) (ExtAdmission, bool, error) {
	a, err := scanExtAdmission(s.db.QueryRowContext(ctx,
		`SELECT `+extAdmitCols+` FROM ext_admissions WHERE source_id=? AND subject=?`, sourceID, subject))
	if errors.Is(err, sql.ErrNoRows) {
		return ExtAdmission{}, false, nil
	}
	return a, err == nil, err
}

const extAdmitCols = `source_id,source_name,subject,username,display_name,email,groups_json,
 status,approval_id,created_at,COALESCE(decided_at,''),COALESCE(decided_by,''),COALESCE(reason,'')`

type rowScanner interface{ Scan(dest ...any) error }

func scanExtAdmission(r rowScanner) (ExtAdmission, error) {
	var a ExtAdmission
	var groups string
	err := r.Scan(&a.SourceID, &a.SourceName, &a.Subject, &a.Username, &a.DisplayName, &a.Email,
		&groups, &a.Status, &a.ApprovalID, &a.CreatedAt, &a.DecidedAt, &a.DecidedBy, &a.Reason)
	if err != nil {
		return ExtAdmission{}, err
	}
	_ = json.Unmarshal([]byte(groups), &a.Groups)
	if a.Groups == nil {
		a.Groups = []string{}
	}
	return a, nil
}

// RequestExtAdmission 登记一条待批准入（幂等）。
//
// ★幂等是必须的，不是优化：登录是可以被无限重试的。每次登录建一条新单子的话，
// 一个被拒的账号反复重试就能把审批页刷满，管理员再也看不见真正的待办——
// 与 auditDeviceObserved 的节流是同一条理由，只是这里用主键天然做到。
//
// 已有登记时**原样返回、不刷新身份快照**：快照是"申请那一刻他是谁"，
// 管理员是照着它做决定的。登录时随手更新等于让申请人自己改申请单内容。
func (s *SQLiteStore) RequestExtAdmission(ctx context.Context, a ExtAdmission) (ExtAdmission, bool, error) {
	if strings.TrimSpace(a.SourceID) == "" || strings.TrimSpace(a.Subject) == "" {
		return ExtAdmission{}, false, fmt.Errorf("准入登记缺少 sourceId/subject")
	}
	// 快查：绝大多数重复登录在这里就返回了，连事务都不开。
	// ★但它**不是**幂等的保证——它跑在事务外，并发首登都能通过它。
	// 真正的保证是下面「先插登记、插成功才配审批单」那一段。
	if cur, ok, err := s.ExtAdmission(ctx, a.SourceID, a.Subject); err != nil {
		return ExtAdmission{}, false, err
	} else if ok {
		return cur, false, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ExtAdmission{}, false, err
	}
	defer tx.Rollback() //nolint:errcheck

	a.Status = AdmitPending
	a.CreatedAt = nowStr()
	a.ApprovalID = "ap-" + uuid.NewString()[:8]
	if a.Groups == nil {
		a.Groups = []string{}
	}
	groups, _ := json.Marshal(a.Groups)

	// ★顺序要紧：**先插准入登记**（OR IGNORE，主键挡住并发的第二个），
	// 真插进去了才配一张审批单。反过来先插审批单的话，每一次重复登录都会往
	// approvals 里塞一条新的 ap-xxx（那是裸 INSERT + 每次新 uuid），而 ext_admissions
	// 被主键挡住不动——审批页上堆满指向同一个人的孤儿待办，管理员批哪一条都不对，
	// 而两侧都不报错。上面那个快查只在单线程下挡得住，并发首登照样漏。
	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO ext_admissions(source_id,source_name,subject,username,display_name,email,
		 groups_json,status,approval_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		a.SourceID, a.SourceName, a.Subject, a.Username, a.DisplayName, a.Email,
		string(groups), a.Status, a.ApprovalID, a.CreatedAt)
	if err != nil {
		return ExtAdmission{}, false, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// 并发下另一方赢了：不配审批单，回读它那条。
		_ = tx.Rollback()
		cur, ok, rerr := s.ExtAdmission(ctx, a.SourceID, a.Subject)
		if rerr != nil {
			return ExtAdmission{}, false, rerr
		}
		if !ok {
			return ExtAdmission{}, false, fmt.Errorf("准入登记写入竞态：既没插入也读不到")
		}
		return cur, false, nil
	}

	// 审批单：与设备绑定单同表，靠 kind 区分（见 ApprovalKindExtUser 的注释）。
	// usr/device/fingerprint 三列在这里的语义由 kind 决定，审批页据此渲染。
	tl, _ := json.Marshal([]ApprovalEvent{{
		Time: a.CreatedAt, Kind: "submit", Title: "外部身份首次登录，申请准入",
		Detail: fmt.Sprintf("认证源「%s」认证通过；该 subject 在白帝尚无账号。批准后其下次登录才会建号。",
			a.SourceName),
	}})
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO approvals(id,kind,usr,device,fingerprint,submitted_at,reason,status,timeline)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		a.ApprovalID, ApprovalKindExtUser, orDash(a.Username), a.SourceName, a.Subject,
		a.CreatedAt, "外部认证源用户首次登录，等待准入批准", AdmitPending, string(tl)); err != nil {
		return ExtAdmission{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return ExtAdmission{}, false, err
	}
	return a, true, nil
}

// DecideExtAdmission 按审批单 id 批准/拒绝一条外部准入。
func (s *SQLiteStore) DecideExtAdmission(ctx context.Context, approvalID, decision, reason, by string) (ExtAdmission, error) {
	if decision != AdmitApproved && decision != AdmitRejected {
		return ExtAdmission{}, errors.New("decision 取值须为 approved|rejected")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ExtAdmission{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	a, err := scanExtAdmission(tx.QueryRowContext(ctx,
		`SELECT `+extAdmitCols+` FROM ext_admissions WHERE approval_id=?`, approvalID))
	if errors.Is(err, sql.ErrNoRows) {
		return ExtAdmission{}, ErrApprovalNotFound
	}
	if err != nil {
		return ExtAdmission{}, err
	}
	if a.Status != AdmitPending {
		// 已处置的单子不接受二次处置：与设备审批同口径，调用方回 409。
		return ExtAdmission{}, ErrApprovalDecided
	}
	now := nowStr()
	if _, err := tx.ExecContext(ctx,
		`UPDATE ext_admissions SET status=?,decided_at=?,decided_by=?,reason=? WHERE approval_id=?`,
		decision, now, by, reason, approvalID); err != nil {
		return ExtAdmission{}, err
	}
	if err := appendApprovalDecisionTx(ctx, tx, approvalID, decision, reason); err != nil {
		return ExtAdmission{}, err
	}
	if err := tx.Commit(); err != nil {
		return ExtAdmission{}, err
	}
	a.Status, a.DecidedAt, a.DecidedBy, a.Reason = decision, now, by, reason
	return a, nil
}

// PendingExtAdmissions 待批准入清单（按申请时间倒序）。
func (s *SQLiteStore) PendingExtAdmissions(ctx context.Context) ([]ExtAdmission, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+extAdmitCols+` FROM ext_admissions WHERE status=? ORDER BY created_at DESC`, AdmitPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExtAdmission{}
	for rows.Next() {
		a, err := scanExtAdmission(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// orDash 空串回破折号（审批单的 usr 列不允许空——页面上会是一行没有主语的待办）。
func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	return v
}

// backfillApprovalKind 给既有审批单补上 kind=device。
//
// ★补列迁移只加列不填值——这是本项目已经踩过的坑（apps.resource_id）。
// 不回填的后果在这里尤其响：DecideApproval 新增了「只处置 kind=device 的单子」这道闸，
// 既有单子 kind 为 NULL 会被一律拒掉，升级那一刻所有待批设备都批不了。
// 无标记（不像语义迁移那样怕重跑）：这条是幂等的 UPDATE，只填空值。
func (s *SQLiteStore) backfillApprovalKind() error {
	_, err := s.db.Exec(`UPDATE approvals SET kind=? WHERE kind IS NULL OR trim(kind)=''`, ApprovalKindDevice)
	return err
}
