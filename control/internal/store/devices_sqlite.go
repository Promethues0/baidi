package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// deviceTrustSettingKey 准入设置在 settings 表里的键。
const deviceTrustSettingKey = "device_trust"

const deviceCols = `id,account,fingerprint,name,platform,status,first_seen,last_seen,approved_by,approved_at,approval_id,revoke_reason`

// DeviceTrustSetting 读准入设置（未落库 / 解析失败 → 默认值）。
//
// 解析失败不报错而是回默认值：这份配置在敲门热路径上被读，一条坏 JSON 不该让
// 全体终端接不进来。坏值只会让它退回 observe（见 Normalize 的兜底方向说明）。
func (s *SQLiteStore) DeviceTrustSetting(ctx context.Context) (DeviceTrustSetting, error) {
	raw, ok, err := s.Setting(ctx, deviceTrustSettingKey)
	if err != nil {
		return DefaultDeviceTrustSetting(), err
	}
	if !ok {
		return DefaultDeviceTrustSetting(), nil
	}
	var st DeviceTrustSetting
	if json.Unmarshal([]byte(raw), &st) != nil {
		return DefaultDeviceTrustSetting(), nil
	}
	return st.Normalize(), nil
}

// SaveDeviceTrustSetting 落准入设置（先 Normalize，脏值进不了库）。
func (s *SQLiteStore) SaveDeviceTrustSetting(ctx context.Context, st DeviceTrustSetting) (DeviceTrustSetting, error) {
	st = st.Normalize()
	raw, err := json.Marshal(st)
	if err != nil {
		return DeviceTrustSetting{}, err
	}
	return st, s.SetSetting(ctx, deviceTrustSettingKey, string(raw))
}

// Devices 终端管理页数据：准入设置 + 全量设备（含 posture 现况与陈旧标记）+ 待审批队列。
func (s *SQLiteStore) Devices(ctx context.Context) (DeviceBundle, error) {
	st, err := s.DeviceTrustSetting(ctx)
	if err != nil {
		return DeviceBundle{}, err
	}
	devices, err := s.listDevices(ctx, st.StaleDays)
	if err != nil {
		return DeviceBundle{}, err
	}
	aps, err := s.pendingApprovals(ctx)
	if err != nil {
		return DeviceBundle{}, err
	}
	return DeviceBundle{Settings: st, Devices: devices, Approvals: aps}, nil
}

// listDevices 设备清单。posture 现况用 LEFT JOIN 取——设备可能已登记但报告被管理员
// 删过（或首次上报的落库那一步失败），此时 verdict 为空串，页面显示「从未上报」，
// **不是** allow。把缺报渲染成合规是本项目在 posture 三态上早就写死的纪律。
//
// ★不加 LIMIT：行数已被「每账号 ≤MaxDevicesPerAccount 台」硬性钳制，而截断一张
// **准入台账**是危险的——被截掉的那几台在页面上等于不存在，管理员既批不了也吊销不了，
// 却照样参与敲门闸的判定。要么全给，要么给分页，不能悄悄少给。
func (s *SQLiteStore) listDevices(ctx context.Context, staleDays int) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT d.id,d.account,d.fingerprint,d.name,d.platform,d.status,d.first_seen,d.last_seen,
       d.approved_by,d.approved_at,d.approval_id,d.revoke_reason,
       COALESCE(p.os,''),COALESCE(p.client_version,''),COALESCE(p.verdict,''),COALESCE(p.level,''),COALESCE(p.ts,0)
FROM trusted_devices d
LEFT JOIN posture_reports p ON p.user=d.account AND p.device=d.fingerprint
ORDER BY d.last_seen DESC, d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cutoff := staleCutoff(staleDays)
	out := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Account, &d.Fingerprint, &d.Name, &d.Platform, &d.Status,
			&d.FirstSeen, &d.LastSeen, &d.ApprovedBy, &d.ApprovedAt, &d.ApprovalID, &d.RevokeReason,
			&d.OS, &d.ClientVersion, &d.Verdict, &d.Level, &d.PostureTS); err != nil {
			return nil, err
		}
		d.Stale = d.LastSeen < cutoff
		out = append(out, d)
	}
	return out, rows.Err()
}

// staleCutoff 陈旧判定的时间界（last_seen 早于它即陈旧）。
func staleCutoff(staleDays int) int64 {
	if staleDays <= 0 {
		staleDays = DefaultStaleDays
	}
	return time.Now().Add(-time.Duration(staleDays) * 24 * time.Hour).Unix()
}

func (s *SQLiteStore) pendingApprovals(ctx context.Context) ([]TrustApproval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,usr,device,fingerprint,submitted_at,reason,status,timeline
FROM approvals WHERE status='pending' ORDER BY submitted_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	aps := []TrustApproval{}
	for rows.Next() {
		var ap TrustApproval
		var tl string
		if err := rows.Scan(&ap.ID, &ap.User, &ap.Device, &ap.Fingerprint, &ap.SubmittedAt, &ap.Reason, &ap.Status, &tl); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tl), &ap.Timeline)
		if ap.Timeline == nil {
			ap.Timeline = []ApprovalEvent{}
		}
		aps = append(aps, ap)
	}
	return aps, rows.Err()
}

// DeviceByFingerprint 取某账号名下某指纹的设备（敲门设备闸的取数点）。
func (s *SQLiteStore) DeviceByFingerprint(ctx context.Context, account, fingerprint string) (Device, bool, error) {
	key := normAccount(account)
	var d Device
	err := s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM trusted_devices WHERE account=? AND fingerprint=?`,
		key, fingerprint).Scan(&d.ID, &d.Account, &d.Fingerprint, &d.Name, &d.Platform, &d.Status,
		&d.FirstSeen, &d.LastSeen, &d.ApprovedBy, &d.ApprovedAt, &d.ApprovalID, &d.RevokeReason)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, false, nil
	}
	if err != nil {
		return Device{}, false, err
	}
	return d, true, nil
}

// EnrollDevice 终端上报时的设备登记（幂等 upsert 语义）。
//
//   - 已登记 → 只刷新 last_seen / platform / 名称（名称仅在为空时补，管理员改过的名字不覆盖）；
//     **状态一律不动**——尤其 revoked 不因为"它又上报了"自动复活，那等于吊销自带有效期。
//   - 未登记 → 按绑定方式落 pending 或 trusted；approval 模式同事务生成一条绑定审批单。
//
// 上限（MaxDevicesPerAccount）在同一个事务里判定。DSN 带 _txlock=immediate，
// 事务起手即持写锁，故这里的"先查后写"是原子的（与对象删除前的引用复核同一套路）。
//
// 返回 created 表示这次是否新登记（调用方据此决定要不要落一条"新终端首次登记"审计——
// 每 15s 一次的上报若都记一条，审计表会被刷成噪声）。
func (s *SQLiteStore) EnrollDevice(ctx context.Context, account, fingerprint, name, platform string, bind string) (Device, bool, error) {
	key := normAccount(account)
	fingerprint = strings.TrimSpace(fingerprint)
	if key == "" || fingerprint == "" {
		return Device{}, false, errors.New("account/fingerprint 必填")
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, false, err
	}
	defer tx.Rollback() //nolint:errcheck // 成功路径已 Commit

	var d Device
	err = tx.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM trusted_devices WHERE account=? AND fingerprint=?`,
		key, fingerprint).Scan(&d.ID, &d.Account, &d.Fingerprint, &d.Name, &d.Platform, &d.Status,
		&d.FirstSeen, &d.LastSeen, &d.ApprovedBy, &d.ApprovedAt, &d.ApprovalID, &d.RevokeReason)
	switch {
	case err == nil:
		newName := pick(d.Name, name)
		newPlatform := pick(platform, d.Platform)
		if _, uerr := tx.ExecContext(ctx,
			`UPDATE trusted_devices SET last_seen=?, name=?, platform=? WHERE id=?`,
			now, newName, newPlatform, d.ID); uerr != nil {
			return Device{}, false, uerr
		}
		d.LastSeen, d.Name, d.Platform = now, newName, newPlatform
		return d, false, tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return Device{}, false, err
	}

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM trusted_devices WHERE account=?`, key).Scan(&n); err != nil {
		return Device{}, false, err
	}
	if n >= MaxDevicesPerAccount {
		return Device{}, false, ErrDeviceCap
	}

	d = Device{
		ID: "dev-" + uuid.NewString()[:8], Account: key, Fingerprint: fingerprint,
		Name: pick(name, shortFingerprint(fingerprint)), Platform: platform,
		Status: DeviceStatusPending, FirstSeen: now, LastSeen: now,
	}
	if bind == DeviceBindAuto {
		// 自动绑定：首次上报即授信。批准人如实记为 auto（不是某个管理员）——
		// 审计与页面上必须分得清"人批的"和"策略自动放的"。
		d.Status, d.ApprovedBy, d.ApprovedAt = DeviceStatusTrusted, "auto", now
	} else {
		ap := TrustApproval{
			ID: "ap-" + uuid.NewString()[:8], User: key, Device: d.Name, Fingerprint: fingerprint,
			SubmittedAt: nowStr(), Reason: "终端首次上报环境报告，自动进入设备绑定审批队列",
			Status: "pending",
			Timeline: []ApprovalEvent{{
				Time: nowStr(), Kind: "submit", Title: "新终端首次登记",
				// 措辞只写已发生的事实：登记了、进队列了。不写"已完成风险研判"之类没做过的动作。
				Detail: "账号 " + key + " 在指纹 " + shortFingerprint(fingerprint) + "（" + pick(platform, "平台未知") +
					"）上首次上报终端环境，设备状态 pending，等待管理员批准",
			}},
		}
		tl, _ := json.Marshal(ap.Timeline)
		if _, ierr := tx.ExecContext(ctx,
			`INSERT INTO approvals(id,usr,device,fingerprint,submitted_at,reason,status,timeline,decided_at,decide_reason)
VALUES(?,?,?,?,?,?,?,?,'','')`,
			ap.ID, ap.User, ap.Device, ap.Fingerprint, ap.SubmittedAt, ap.Reason, ap.Status, string(tl)); ierr != nil {
			return Device{}, false, ierr
		}
		d.ApprovalID = ap.ID
	}
	if _, ierr := tx.ExecContext(ctx, `INSERT INTO trusted_devices(`+deviceCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		d.ID, d.Account, d.Fingerprint, d.Name, d.Platform, d.Status, d.FirstSeen, d.LastSeen,
		d.ApprovedBy, d.ApprovedAt, d.ApprovalID, d.RevokeReason); ierr != nil {
		return Device{}, false, ierr
	}
	return d, true, tx.Commit()
}

// SetDeviceStatus 管理员改设备状态（批准 / 吊销 / 打回 pending）。
// 返回改动后的设备。状态不变时也照常写（幂等），但调用方拿得到旧状态做审计措辞。
func (s *SQLiteStore) SetDeviceStatus(ctx context.Context, id, status, by, reason string) (Device, Device, error) {
	if !DeviceStatusValid(status) {
		return Device{}, Device{}, errors.New("status 取值须为 pending|trusted|revoked")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, Device{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	before, err := scanDeviceTx(ctx, tx, id)
	if err != nil {
		return Device{}, Device{}, err
	}
	after := before
	after.Status = status
	switch status {
	case DeviceStatusTrusted:
		after.ApprovedBy, after.ApprovedAt, after.RevokeReason = by, time.Now().Unix(), ""
	case DeviceStatusRevoked:
		after.RevokeReason = reason
	default:
		after.ApprovedBy, after.ApprovedAt, after.RevokeReason = "", 0, ""
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE trusted_devices SET status=?, approved_by=?, approved_at=?, revoke_reason=? WHERE id=?`,
		after.Status, after.ApprovedBy, after.ApprovedAt, after.RevokeReason, id); err != nil {
		return Device{}, Device{}, err
	}
	// 设备状态由管理员在设备页直接改时，把它关联的那张审批单一并收口——
	// 否则审批队列里会长期挂着一条"待审批"，而设备其实早就批过/吊销过了。
	if after.ApprovalID != "" {
		dec := map[string]string{DeviceStatusTrusted: "approved", DeviceStatusRevoked: "rejected"}[status]
		if dec != "" {
			if err := appendApprovalDecisionTx(ctx, tx, after.ApprovalID, dec, pick(reason, "管理员在终端管理页直接处置")); err != nil {
				return Device{}, Device{}, err
			}
		}
	}
	return before, after, tx.Commit()
}

// RenameDevice 重命名设备（管理员在终端管理页维护台账）。
func (s *SQLiteStore) RenameDevice(ctx context.Context, id, name string) (Device, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Device{}, errors.New("name 必填")
	}
	if len([]rune(name)) > 64 {
		return Device{}, errors.New("name 过长（≤64 字）")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	d, err := scanDeviceTx(ctx, tx, id)
	if err != nil {
		return Device{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE trusted_devices SET name=? WHERE id=?`, name, id); err != nil {
		return Device{}, err
	}
	d.Name = name
	return d, tx.Commit()
}

// DeleteDevice 删除一台设备登记，**连同它的 posture 报告一并删**。
//
// ★两表同删是「口径统一」的执行处：上限按 trusted_devices 计数，若只删设备行
// 而留下 posture 报告，两表就会在行数上分家——管理员清理完设备发现还是报超限，
// 或者反过来，安全中心「终端合规」页上挂着一台设备页里根本不存在的终端。
func (s *SQLiteStore) DeleteDevice(ctx context.Context, id string) (Device, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	d, err := scanDeviceTx(ctx, tx, id)
	if err != nil {
		return Device{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM trusted_devices WHERE id=?`, id); err != nil {
		return Device{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM posture_reports WHERE user=? AND device=?`, d.Account, d.Fingerprint); err != nil {
		return Device{}, err
	}
	return d, tx.Commit()
}

// PurgeStaleDevices 批量清理陈旧设备（last_seen 早于 staleDays 天前）。
//
// ★**刻意跳过 revoked 设备**：清掉一条吊销记录，该指纹下次上报就会作为新设备重新登记
// （approval 模式下是 pending、auto 模式下直接 trusted）——那等于给"吊销"配了个静默的
// 有效期。被吊销的终端本来就不会再上报，它必然是最陈旧的那批，一刀切清理正好把
// 最该留的记录清得最干净。要彻底删除某台吊销设备，走单台删除（有独立审计与确认）。
func (s *SQLiteStore) PurgeStaleDevices(ctx context.Context, staleDays int) ([]Device, error) {
	cutoff := staleCutoff(staleDays)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	rows, err := tx.QueryContext(ctx, `SELECT `+deviceCols+` FROM trusted_devices WHERE last_seen<? AND status<>? ORDER BY last_seen`,
		cutoff, DeviceStatusRevoked)
	if err != nil {
		return nil, err
	}
	var victims []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Account, &d.Fingerprint, &d.Name, &d.Platform, &d.Status,
			&d.FirstSeen, &d.LastSeen, &d.ApprovedBy, &d.ApprovedAt, &d.ApprovalID, &d.RevokeReason); err != nil {
			rows.Close()
			return nil, err
		}
		d.Stale = true
		victims = append(victims, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, d := range victims {
		if _, err := tx.ExecContext(ctx, `DELETE FROM trusted_devices WHERE id=?`, d.ID); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM posture_reports WHERE user=? AND device=?`, d.Account, d.Fingerprint); err != nil {
			return nil, err
		}
		if d.ApprovalID != "" {
			// 措辞必须与实际动作一致：这里发生的是"设备登记被删除"，不是"审批被驳回"。
			if err := closeApprovalTx(ctx, tx, d.ApprovalID, "rejected", "risk", "关联终端登记已被清理",
				"该终端超过陈旧阈值未上报环境报告，其设备登记与环境报告已被管理员批量清理，本申请随之归档（未对该终端做出授信或吊销判定）"); err != nil {
				return nil, err
			}
		}
	}
	return victims, tx.Commit()
}

// DecideApproval 审批落库（通过/驳回 + 理由 + 决策时间 + 时间线），**同事务**同步设备状态。
//
// 返回被联动的设备（found=false 表示这张审批单没有关联设备——迁移前遗留的单子）。
// 通过 → trusted；驳回 → revoked。审批与设备状态分两步写的话，「批了但设备还是
// pending」会是一个无报错、只在用户连不上时才被发现的状态。
func (s *SQLiteStore) DecideApproval(ctx context.Context, id, decision, reason, by string) (Device, bool, error) {
	if decision != "approved" && decision != "rejected" {
		return Device{}, false, errors.New("decision 取值须为 approved|rejected")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, false, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := appendApprovalDecisionTx(ctx, tx, id, decision, reason); err != nil {
		return Device{}, false, err
	}
	var d Device
	err = tx.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM trusted_devices WHERE approval_id=?`, id).
		Scan(&d.ID, &d.Account, &d.Fingerprint, &d.Name, &d.Platform, &d.Status,
			&d.FirstSeen, &d.LastSeen, &d.ApprovedBy, &d.ApprovedAt, &d.ApprovalID, &d.RevokeReason)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, false, tx.Commit()
	}
	if err != nil {
		return Device{}, false, err
	}
	if decision == "approved" {
		d.Status, d.ApprovedBy, d.ApprovedAt, d.RevokeReason = DeviceStatusTrusted, by, time.Now().Unix(), ""
	} else {
		d.Status, d.RevokeReason = DeviceStatusRevoked, pick(reason, "绑定申请被驳回")
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE trusted_devices SET status=?, approved_by=?, approved_at=?, revoke_reason=? WHERE id=?`,
		d.Status, d.ApprovedBy, d.ApprovedAt, d.RevokeReason, d.ID); err != nil {
		return Device{}, false, err
	}
	return d, true, tx.Commit()
}

// appendApprovalDecisionTx 给一张审批单写决策 + 追加一条时间线事件（事务内）。
func appendApprovalDecisionTx(ctx context.Context, tx *sql.Tx, id, decision, reason string) error {
	title, kind := "审批通过，设备已置为授信", "notify"
	if decision == "rejected" {
		title, kind = "审批驳回，设备已置为吊销", "risk"
	}
	return closeApprovalTx(ctx, tx, id, decision, kind, title, pick(reason, "管理员已处置"))
}

// closeApprovalTx 关闭一张待处置的审批单并追加一条时间线事件（事务内）。
//
// ★title/detail 由调用方给，不由 decision 反推：陈旧清理也要关掉审批单，但它做的是
// **删除设备**而不是"置为吊销"。复用驳回那套措辞会在时间线上留下一句没发生过的话，
// 而时间线正是事后复盘"这台设备当初怎么了"的唯一依据。
func closeApprovalTx(ctx context.Context, tx *sql.Tx, id, decision, kind, title, detail string) error {
	var tl, status string
	if err := tx.QueryRowContext(ctx, `SELECT timeline,status FROM approvals WHERE id=?`, id).Scan(&tl, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // 设备没有关联审批单（auto 绑定 / 迁移回填）时是正常路径
		}
		return err
	}
	if status != "pending" {
		return nil // 已处置过，不重复追加时间线
	}
	var events []ApprovalEvent
	_ = json.Unmarshal([]byte(tl), &events)
	events = append(events, ApprovalEvent{Time: nowStr(), Kind: kind, Title: title, Detail: detail})
	nb, _ := json.Marshal(events)
	_, err := tx.ExecContext(ctx,
		`UPDATE approvals SET status=?, decided_at=?, decide_reason=?, timeline=? WHERE id=?`,
		decision, nowStr(), detail, string(nb), id)
	return err
}

func scanDeviceTx(ctx context.Context, tx *sql.Tx, id string) (Device, error) {
	var d Device
	err := tx.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM trusted_devices WHERE id=?`, id).
		Scan(&d.ID, &d.Account, &d.Fingerprint, &d.Name, &d.Platform, &d.Status,
			&d.FirstSeen, &d.LastSeen, &d.ApprovedBy, &d.ApprovedAt, &d.ApprovalID, &d.RevokeReason)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrDeviceNotFound
	}
	return d, err
}

// shortFingerprint 给设备一个可读的默认名（指纹前 12 位）。
func shortFingerprint(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12]
}

// trustedDevicesBackfillMarker 存量设备一次性回填标记。
const trustedDevicesBackfillMarker = "trusted_devices.backfill.v1"

// backfillTrustedDevices 用既有 posture_reports 回填 trusted_devices。
//
// ★这是**必须有**的回填，不是"新表无需回填"那一类。理由：升级前所有终端都只在
// posture_reports 里留过痕，trusted_devices 一片空白。不回填的话
//   - 终端管理页在升级后是空的（管理员看到的是"一台设备都没有"，而实际有几十台在跑）；
//   - 一旦切到 strict 准入，**全体存量终端立刻被判未登记而拒发敲门令牌**——
//     一次配置变更把所有人锁在门外，且页面上找不到任何可批准的设备。
//
// 回填状态取 trusted 而不是 pending：升级前系统里"授信终端"的事实判据就是
// 「该账号用这个指纹上报过 posture」（认证策略的 TrustedDevice 豁免用的正是这一条），
// 回填成 trusted 才能让升级前后的语义**逐字节一致**（与 backfillAdminRoles 把既有
// admin 回填成 root 是同一条纪律：迁移不得改变既有主体的实际权限）。批准人如实记为
// DeviceApproverBackfill，页面上显示「升级前既有设备」——不冒充成某个管理员批过。
//
// ★放在 migrate() 里是安全的（区别于 backfillOrgUnits 必须排在 seed 之后）：
// posture_reports **从来不播种**，它只被真实上报填充。全新库跑到这里时该表必然是空的，
// 空转就是正确结果——不存在"业务表还没建好导致静默漏填"的情形。
// 一次性标记则堵住另一面：不做成一次性的话，管理员吊销掉的设备会在下次重启时
// 因为 posture 报告还在而被重新回填成 trusted（"重启即复活"）。
func (s *SQLiteStore) backfillTrustedDevices() error {
	ctx := context.Background()
	if _, done, err := s.Setting(ctx, trustedDevicesBackfillMarker); err != nil {
		return err
	} else if done {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT user,device,platform,ts FROM posture_reports`)
	if err != nil {
		return err
	}
	type seed struct {
		user, device, platform string
		ts                     int64
	}
	var seeds []seed
	for rows.Next() {
		var sd seed
		if err := rows.Scan(&sd.user, &sd.device, &sd.platform, &sd.ts); err != nil {
			rows.Close()
			return err
		}
		seeds = append(seeds, sd)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, sd := range seeds {
		// 只补缺失的行；已存在的一律不动（幂等，也避免覆盖管理员改过的名字/状态）。
		if _, err := s.db.ExecContext(ctx, `INSERT INTO trusted_devices(`+deviceCols+`)
SELECT ?,?,?,?,?,?,?,?,?,?,'',''
WHERE NOT EXISTS(SELECT 1 FROM trusted_devices WHERE account=? AND fingerprint=?)`,
			"dev-"+uuid.NewString()[:8], normAccount(sd.user), sd.device, shortFingerprint(sd.device), sd.platform,
			DeviceStatusTrusted, sd.ts, sd.ts, DeviceApproverBackfill, sd.ts,
			normAccount(sd.user), sd.device); err != nil {
			return err
		}
	}
	return s.SetSetting(ctx, trustedDevicesBackfillMarker, nowStr())
}
