package store

import (
	"errors"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ── access_requests 读 ──

const accessReqCols = `id,usr,resource_id,resource_name,reason,ttl_minutes,status,timeline,submitted_at,decided_at,decide_reason,decided_by,grant_id,kind`

func scanAccessRequests(rows *sql.Rows) ([]AccessRequest, error) {
	defer rows.Close()
	out := []AccessRequest{}
	for rows.Next() {
		var r AccessRequest
		var tl string
		// kind 用可空类型扫：回填跑过之后不该有 NULL，但一条 NULL 会让整个列表读不出来，
		// 而"申请列表突然空了"比"某条 kind 显示成 request"糟得多。
		var kind sql.NullString
		if err := rows.Scan(&r.ID, &r.User, &r.ResourceID, &r.ResourceName, &r.Reason, &r.TTLMinutes,
			&r.Status, &tl, &r.SubmittedAt, &r.DecidedAt, &r.DecideReason, &r.DecidedBy, &r.GrantID, &kind); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tl), &r.Timeline)
		if r.Timeline == nil {
			r.Timeline = []ApprovalEvent{}
		}
		r.Kind = kind.String
		if r.Kind == "" {
			r.Kind = AccessKindRequest
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AccessRequests 待审批申请队列（管理台待办，pending，新→旧）。
func (s *SQLiteStore) AccessRequests(ctx context.Context) ([]AccessRequest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+accessReqCols+` FROM access_requests WHERE status='pending' ORDER BY submitted_at DESC`)
	if err != nil {
		return nil, err
	}
	return scanAccessRequests(rows)
}

// AccessRequestsFor 某账号（规范化匹配）的全部申请（门户「我的申请」，新→旧）。
func (s *SQLiteStore) AccessRequestsFor(ctx context.Context, user string) ([]AccessRequest, error) {
	key := strings.ToLower(strings.TrimSpace(user))
	rows, err := s.db.QueryContext(ctx, `SELECT `+accessReqCols+` FROM access_requests WHERE usr=? ORDER BY submitted_at DESC`, key)
	if err != nil {
		return nil, err
	}
	return scanAccessRequests(rows)
}

// ── jit_grants 读 ──

const grantCols = `id,usr,resource_id,resource_name,request_id,reason,granted_by,granted_at,expires_at,status,revoked_at,revoke_reason`

// scanGrants 读授予；displayExpire=true 时把「status=active 但已过 expires_at」的行在展示层显示为 expired
// （惰性模型不翻库状态，读时纠正，避免管理台「访问审查」把已到期授予长期显示为 active）。
func scanGrants(rows *sql.Rows, now int64, displayExpire bool) ([]JitGrant, error) {
	defer rows.Close()
	out := []JitGrant{}
	for rows.Next() {
		var g JitGrant
		if err := rows.Scan(&g.ID, &g.User, &g.ResourceID, &g.ResourceName, &g.RequestID, &g.Reason,
			&g.GrantedBy, &g.GrantedAt, &g.ExpiresAt, &g.Status, &g.RevokedAt, &g.RevokeReason); err != nil {
			return nil, err
		}
		if displayExpire && g.Status == "active" && now >= g.ExpiresAt {
			g.Status = "expired"
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// ListLimit 列表面的读取上限。展示用，**不是**判定用——判定各走各的查询
// （告警读 ActiveGrants/StaleGrants、准入读 PostureUsersByDisposal 的 DISTINCT），
// 所以这道上限截断的只是"看得到多少行"。
const ListLimit = 500

// JitGrants 全部授予（active/revoked/expired，新→旧），供管理台访问审查/倒计时。展示层纠正到期状态。
func (s *SQLiteStore) JitGrants(ctx context.Context) ([]JitGrant, error) {
	l, _, err := s.JitGrantsPage(ctx)
	return l, err
}

// JitGrantsPage 同上，另回**库里的总行数**。
//
// ★为什么要多这一趟 COUNT：`LIMIT 500` 不带总数、页面也不提示，与本项目反复强调的
// 「截断必须可见」相反——第 501 条之后的授予在管理台上**根本不存在**，
// 而访问审查恰恰是要看"有没有我不知道的授予"。多一次 COUNT 的代价远小于
// 让一份审查清单在使用者不知情的情况下少掉一截。
func (s *SQLiteStore) JitGrantsPage(ctx context.Context) ([]JitGrant, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jit_grants`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+grantCols+` FROM jit_grants ORDER BY granted_at DESC LIMIT ?`, ListLimit)
	if err != nil {
		return nil, 0, err
	}
	out, err := scanGrants(rows, time.Now().Unix(), true)
	return out, total, err
}

// ActiveGrants 当前有效授予（status=active 且未到期）——数据面 handleGatewayPolicy 出口 merge 的来源。
// 惰性到期：过了 expires_at 的授予在此被 SQL 过滤掉，网关下次轮询即失去该 allow。
func (s *SQLiteStore) ActiveGrants(ctx context.Context) ([]JitGrant, error) {
	now := time.Now().Unix()
	rows, err := s.db.QueryContext(ctx, `SELECT `+grantCols+` FROM jit_grants WHERE status='active' AND expires_at>?`, now)
	if err != nil {
		return nil, err
	}
	return scanGrants(rows, now, false)
}

// ActiveGrantsFor 某账号（规范化匹配）当前有效授予，供门户把「需申请」磁贴翻回可访问 + 显示剩余时长。
func (s *SQLiteStore) ActiveGrantsFor(ctx context.Context, user string) ([]JitGrant, error) {
	key := strings.ToLower(strings.TrimSpace(user))
	now := time.Now().Unix()
	rows, err := s.db.QueryContext(ctx, `SELECT `+grantCols+` FROM jit_grants WHERE usr=? AND status='active' AND expires_at>?`, key, now)
	if err != nil {
		return nil, err
	}
	return scanGrants(rows, now, false)
}

// ── 写 ──

// CreateAccessRequest 落一条 pending 申请。事务内先去重（同账号+资源已有 pending 或未到期 active 授予则拒），
// 借 _txlock=immediate 起手取写锁，杜绝并发连点堆叠出重复单。User 由 api 层规范化，这里再兜底小写。
func (s *SQLiteStore) CreateAccessRequest(ctx context.Context, req AccessRequest) (AccessRequest, error) {
	user := strings.ToLower(strings.TrimSpace(req.User))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessRequest{}, err
	}
	defer tx.Rollback()

	var pend int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_requests WHERE usr=? AND resource_id=? AND status='pending'`,
		user, req.ResourceID).Scan(&pend); err != nil {
		return AccessRequest{}, err
	}
	// 已有 active 授予时，看它**还剩多久**：
	//   剩余 > RenewWindow → 仍是重复提交（拒），否则「续期」会变成刷时长的工具；
	//   剩余 ≤ RenewWindow → 这是一次**续期**（放行，审批通过后延长现有授予）。
	// ★此前这里只数 COUNT>0 就一律 ErrDuplicateRequest，于是续期结构上不可能：
	//   未到期提交被 409，等到期了访问已经断了——而 PRD FR-AUTH-03/04 要的正是
	//   「在到期前自助续期，不中断访问」。
	now := time.Now().Unix()
	var expiresAt int64
	err = tx.QueryRowContext(ctx, `SELECT expires_at FROM jit_grants WHERE usr=? AND resource_id=? AND status='active' AND expires_at>? ORDER BY expires_at DESC LIMIT 1`,
		user, req.ResourceID, now).Scan(&expiresAt)
	switch {
	case err == nil:
		if expiresAt-now > int64(RenewWindowMinutes)*60 {
			return AccessRequest{}, ErrDuplicateRequest
		}
		req.Kind = AccessKindRenew
	case errors.Is(err, sql.ErrNoRows):
		req.Kind = AccessKindRequest
	default:
		return AccessRequest{}, err
	}
	if pend > 0 {
		return AccessRequest{}, ErrDuplicateRequest
	}

	req.ID = "areq-" + uuid.NewString()[:8]
	req.User = user
	req.Status = "pending"
	req.SubmittedAt = nowStr()
	req.GrantID = ""
	req.Timeline = []ApprovalEvent{
		{Time: req.SubmittedAt, Kind: "submit", Title: "提交访问申请", Detail: req.User + " 申请访问「" + req.ResourceName + "」，理由：" + req.Reason},
		{Time: req.SubmittedAt, Kind: "review", Title: "等待管理员审批", Detail: "进入 JIT 访问审批队列（当前）"},
	}
	tl, _ := json.Marshal(req.Timeline)
	if _, err := tx.ExecContext(ctx, `INSERT INTO access_requests(`+accessReqCols+`)
VALUES(?,?,?,?,?,?,?,?,?,'','','','',?)`,
		req.ID, req.User, req.ResourceID, req.ResourceName, req.Reason, req.TTLMinutes, req.Status, string(tl), req.SubmittedAt, req.Kind); err != nil {
		return AccessRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccessRequest{}, err
	}
	return req, nil
}

// DecideAccessRequest 审批处置（单事务原子）：
//  1. 读申请单（拿申请人/资源/原时长/状态）；非 pending → ErrRequestDecided；
//  2. 通过时职责分离闸：审批人==申请人 → ErrSelfApprove；
//  3. UPDATE ... WHERE id=? AND status='pending'，RowsAffected!=1（被并发抢先决过）→ ErrRequestDecided，回滚；
//  4. 通过时同事务内建 active 授予（expires_at=now+ttl）并回填 request.grant_id。
//
// ttlOverride>0 覆盖申请时长，否则用申请单原值；两路都经 ClampGrantTTL 钳边界。
// 返回 (更新后的申请, 新建授予[驳回时为零值], error)。
func (s *SQLiteStore) DecideAccessRequest(ctx context.Context, id, decision, reason, decidedBy string, ttlOverride int) (AccessRequest, JitGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessRequest{}, JitGrant{}, err
	}
	defer tx.Rollback()

	var req AccessRequest
	var tl string
	var reqKind sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id,usr,resource_id,resource_name,ttl_minutes,status,timeline,kind FROM access_requests WHERE id=?`, id).
		Scan(&req.ID, &req.User, &req.ResourceID, &req.ResourceName, &req.TTLMinutes, &req.Status, &tl, &reqKind)
	if err == sql.ErrNoRows {
		return AccessRequest{}, JitGrant{}, ErrRequestDecided
	}
	if err != nil {
		return AccessRequest{}, JitGrant{}, err
	}
	if req.Status != "pending" {
		return AccessRequest{}, JitGrant{}, ErrRequestDecided
	}
	if decision == "approved" && strings.ToLower(strings.TrimSpace(decidedBy)) == req.User {
		return AccessRequest{}, JitGrant{}, ErrSelfApprove
	}

	var events []ApprovalEvent
	_ = json.Unmarshal([]byte(tl), &events)
	title, kind := "审批通过", "notify"
	if decision == "rejected" {
		title, kind = "审批驳回", "risk"
	}
	events = append(events, ApprovalEvent{Time: nowStr(), Kind: kind, Title: title, Detail: pick(reason, "管理员已处置，已通知申请人")})
	nb, _ := json.Marshal(events)

	res, err := tx.ExecContext(ctx, `UPDATE access_requests SET status=?, decided_at=?, decide_reason=?, decided_by=?, timeline=? WHERE id=? AND status='pending'`,
		decision, nowStr(), reason, decidedBy, string(nb), id)
	if err != nil {
		return AccessRequest{}, JitGrant{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return AccessRequest{}, JitGrant{}, ErrRequestDecided // 并发抢先处置，杜绝 orphan grant
	}

	req.Status = decision
	req.DecidedBy = decidedBy
	req.DecideReason = reason
	req.Timeline = events

	var grant JitGrant
	if decision == "approved" {
		ttl := ttlOverride
		if ttl <= 0 {
			ttl = req.TTLMinutes
		}
		ttl = ClampGrantTTL(ttl)
		now := time.Now().Unix()
		// ★续期单**延长现有授予**，不新建（PRD 验收：「通过后用户授权延续」）。
		//   新建的话同一资源上会同时躺着两条 active 授予：网关侧靠 ActiveGrants 展开，
		//   两条都放行、都到期，审计与授权清单里出现一次根本没发生的"第二次授权"，
		//   而撤销时管理员只会看到并撤掉其中一条。
		req.Kind = reqKind.String
		if req.Kind == "" {
			req.Kind = AccessKindRequest
		}
		var renewed bool
		if req.Kind == AccessKindRenew {
			var gid string
			var oldExp int64
			e := tx.QueryRowContext(ctx, `SELECT id,expires_at FROM jit_grants WHERE usr=? AND resource_id=? AND status='active' AND expires_at>? ORDER BY expires_at DESC LIMIT 1`,
				req.User, req.ResourceID, now).Scan(&gid, &oldExp)
			switch {
			case e == nil:
				// 从**当前时刻**起算而不是从旧到期时间叠加：叠加会让反复续期无限累积，
				// 而每一次续期都该是一次独立的、时长受 TTL 上限约束的授权。
				newExp := now + int64(ttl)*60
				if newExp < oldExp {
					newExp = oldExp // 续期不该缩短已有授权
				}
				if _, err := tx.ExecContext(ctx, `UPDATE jit_grants SET expires_at=?, reason=?, granted_by=? WHERE id=?`,
					newExp, reason, decidedBy, gid); err != nil {
					return AccessRequest{}, JitGrant{}, err
				}
				if err := tx.QueryRowContext(ctx, `SELECT `+grantCols+` FROM jit_grants WHERE id=?`, gid).
					Scan(&grant.ID, &grant.User, &grant.ResourceID, &grant.ResourceName, &grant.RequestID,
						&grant.Reason, &grant.GrantedBy, &grant.GrantedAt, &grant.ExpiresAt, &grant.Status,
						&grant.RevokedAt, &grant.RevokeReason); err != nil {
					return AccessRequest{}, JitGrant{}, err
				}
				renewed = true
			case errors.Is(e, sql.ErrNoRows):
				// 授予在审批期间到期或被撤销了：退化成新建一条（用户仍该拿到访问权，
				// 那正是他申请的东西），但这件事要能从 grant.RequestID 追溯回本单。
			default:
				return AccessRequest{}, JitGrant{}, e
			}
		}
		if !renewed {
			grant = JitGrant{
				ID: "grant-" + uuid.NewString()[:8], User: req.User, ResourceID: req.ResourceID, ResourceName: req.ResourceName,
				RequestID: id, Reason: reason, GrantedBy: decidedBy, GrantedAt: now, ExpiresAt: now + int64(ttl)*60, Status: "active",
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO jit_grants(`+grantCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,0,'')`,
				grant.ID, grant.User, grant.ResourceID, grant.ResourceName, grant.RequestID, grant.Reason,
				grant.GrantedBy, grant.GrantedAt, grant.ExpiresAt, grant.Status); err != nil {
				return AccessRequest{}, JitGrant{}, err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE access_requests SET grant_id=? WHERE id=?`, grant.ID, id); err != nil {
			return AccessRequest{}, JitGrant{}, err
		}
		req.GrantID = grant.ID
	}
	if err := tx.Commit(); err != nil {
		return AccessRequest{}, JitGrant{}, err
	}
	return req, grant, nil
}

// RevokeGrant 管理员提前撤销一条 active 授予（置 revoked + 时间/理由）。非 active → ErrGrantInactive。
// 撤销后下次 handleGatewayPolicy 不再 emit 该授予，网关下轮轮询即失去 allow。
func (s *SQLiteStore) RevokeGrant(ctx context.Context, id, reason string) (JitGrant, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return JitGrant{}, err
	}
	defer tx.Rollback()

	var g JitGrant
	err = tx.QueryRowContext(ctx, `SELECT `+grantCols+` FROM jit_grants WHERE id=?`, id).
		Scan(&g.ID, &g.User, &g.ResourceID, &g.ResourceName, &g.RequestID, &g.Reason,
			&g.GrantedBy, &g.GrantedAt, &g.ExpiresAt, &g.Status, &g.RevokedAt, &g.RevokeReason)
	if err == sql.ErrNoRows {
		return JitGrant{}, ErrGrantInactive
	}
	if err != nil {
		return JitGrant{}, err
	}
	if g.Status != "active" {
		return JitGrant{}, ErrGrantInactive
	}
	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx, `UPDATE jit_grants SET status='revoked', revoked_at=?, revoke_reason=? WHERE id=? AND status='active'`, now, reason, id)
	if err != nil {
		return JitGrant{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return JitGrant{}, ErrGrantInactive
	}
	if err := tx.Commit(); err != nil {
		return JitGrant{}, err
	}
	g.Status = "revoked"
	g.RevokedAt = now
	g.RevokeReason = reason
	return g, nil
}

// backfillAccessRequestKind 给存量申请单补 kind='request'。
// 续期在这道迁移之前结构上不可能提交，所以存量行全都是首次申请。
func (s *SQLiteStore) backfillAccessRequestKind() error {
	_, err := s.db.Exec(`UPDATE access_requests SET kind=? WHERE kind IS NULL OR trim(kind)=''`,
		AccessKindRequest)
	return err
}
