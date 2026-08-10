package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// ── 业务告警：SQLite 真实现（表定义见 sqlite.go 的 migrate）──

// alertRuleSeedMarker settings 表里的一次性标记：内置规则只播种一次。
//
// ★为什么要标记而不是"表为空就播种"：管理员把某条内置规则删掉之后，
// 下次重启这条规则会复活——"删了、重启就回来"与既有的组织回填踩过的是同一个坑
// （见 backfillOrgUnits 的注释）。有了标记，删除是真的删除。
const alertRuleSeedMarker = "alert.rules.seed.v1"

// seedAlertRules 首次（且仅一次）为每个规则种类播一条默认规则。
//
// 这同时承担既有库的"回填"职责：新表在旧库上是空的，不播种的话升级后
// 告警页一条规则都没有、什么都不会触发，而页面上看不出缺了什么。
func (s *SQLiteStore) seedAlertRules(ctx context.Context) error {
	if _, done, err := s.Setting(ctx, alertRuleSeedMarker); err != nil || done {
		return err
	}
	for _, spec := range AlertKindSpecs() {
		r := AlertRule{
			ID: "ar-" + strings.ReplaceAll(spec.Kind, "_", "-"), Name: spec.Name, Kind: spec.Kind,
			Threshold: spec.Thresholds, Enabled: true, Channels: []string{},
			CooldownSec: DefaultAlertCooldownSec,
		}
		if _, err := s.SaveAlertRule(ctx, r); err != nil {
			return err
		}
	}
	return s.SetSetting(ctx, alertRuleSeedMarker, nowStr())
}

// AlertRules 全部告警规则（按 kind 固定顺序，保证页面上下不跳）。
func (s *SQLiteStore) AlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,kind,COALESCE(threshold_json,'{}'),enabled,COALESCE(channels_json,'[]'),
		        COALESCE(cooldown_sec,0),COALESCE(created_at,''),COALESCE(updated_at,'') FROM alert_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AlertRule{}
	for rows.Next() {
		var r AlertRule
		var th, ch string
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &th, &enabled, &ch, &r.CooldownSec, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(th), &r.Threshold)
		_ = json.Unmarshal([]byte(ch), &r.Channels)
		if r.Threshold == nil {
			r.Threshold = map[string]float64{}
		}
		if r.Channels == nil {
			r.Channels = []string{}
		}
		r.CooldownSec = ClampAlertCooldown(r.CooldownSec)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 按 kind 在 alertKindSpecs 里的次序排，同 kind 按 id——列表顺序稳定，
	// 免得每次刷新规则行乱跳（管理员会以为内容变了）。
	order := map[string]int{}
	for i, spec := range alertKindSpecs {
		order[spec.Kind] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if oi, oj := order[out[i].Kind], order[out[j].Kind]; oi != oj {
			return oi < oj
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// SaveAlertRule upsert 一条告警规则（阈值已由调用方经 NormalizeThresholds 校验）。
func (s *SQLiteStore) SaveAlertRule(ctx context.Context, r AlertRule) (AlertRule, error) {
	if _, ok := AlertKindSpecOf(r.Kind); !ok {
		return AlertRule{}, ErrUnknownAlertKind
	}
	th, err := NormalizeThresholds(r.Kind, r.Threshold)
	if err != nil {
		return AlertRule{}, err
	}
	r.Threshold = th
	r.CooldownSec = ClampAlertCooldown(r.CooldownSec)
	if r.ID == "" {
		r.ID = "ar-" + uuid.NewString()[:8]
	}
	if r.Channels == nil {
		r.Channels = []string{}
	}
	thb, _ := json.Marshal(r.Threshold)
	chb, _ := json.Marshal(r.Channels)
	r.UpdatedAt = nowStr()
	if r.CreatedAt == "" {
		r.CreatedAt = r.UpdatedAt
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO alert_rules(id,name,kind,threshold_json,enabled,channels_json,cooldown_sec,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, threshold_json=excluded.threshold_json,
  enabled=excluded.enabled, channels_json=excluded.channels_json, cooldown_sec=excluded.cooldown_sec,
  updated_at=excluded.updated_at`,
		r.ID, r.Name, r.Kind, string(thb), b2i(r.Enabled), string(chb), r.CooldownSec, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return AlertRule{}, err
	}
	return r, nil
}

// DeleteAlertRule 删规则。
//
// 已产生的告警**不级联删除**：它们是既成事实（谁在什么时候被告警、谁处理的），
// 删规则不该让历史消失。alerts.rule_id 因此可能指向一条已不存在的规则，
// 读侧不 JOIN 规则表正是为此。
func (s *SQLiteStore) DeleteAlertRule(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alert_rules WHERE id=?`, id)
	return err
}

// defaultAlertLimit 列表默认上限：告警页一屏 + 翻页余量，避免一次拉走全表。
const defaultAlertLimit = 200

// Alerts 按条件查告警（新→旧）。
func (s *SQLiteStore) Alerts(ctx context.Context, q AlertQuery) ([]Alert, error) {
	sb := strings.Builder{}
	sb.WriteString(`SELECT id,rule_id,COALESCE(kind,''),category,severity,title,COALESCE(detail,''),
	  COALESCE(object_key,''),status,triggered_at,COALESCE(handled_at,0),COALESCE(handled_by,'') FROM alerts WHERE 1=1`)
	var args []any
	if q.Status != "" {
		sb.WriteString(` AND status=?`)
		args = append(args, q.Status)
	}
	if q.Category != "" {
		sb.WriteString(` AND category=?`)
		args = append(args, q.Category)
	}
	if q.From > 0 {
		sb.WriteString(` AND triggered_at>=?`)
		args = append(args, q.From)
	}
	if q.To > 0 {
		sb.WriteString(` AND triggered_at<=?`)
		args = append(args, q.To)
	}
	limit := q.Limit
	if limit <= 0 || limit > defaultAlertLimit {
		limit = defaultAlertLimit
	}
	sb.WriteString(` ORDER BY triggered_at DESC, id DESC LIMIT ?`)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.RuleID, &a.Kind, &a.Category, &a.Severity, &a.Title, &a.Detail,
			&a.ObjectKey, &a.Status, &a.TriggeredAt, &a.HandledAt, &a.HandledBy); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AlertCounts 按状态计数（角标 / 页头统计的唯一来源；不受列表 LIMIT 影响）。
func (s *SQLiteStore) AlertCounts(ctx context.Context) (AlertCounts, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM alerts GROUP BY status`)
	if err != nil {
		return AlertCounts{}, err
	}
	defer rows.Close()
	var c AlertCounts
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return AlertCounts{}, err
		}
		switch st {
		case AlertPending:
			c.Pending = n
		case AlertIgnored:
			c.Ignored = n
		case AlertHandled:
			c.Handled = n
		}
	}
	return c, rows.Err()
}

// RaiseAlert 产生一条告警，并按 (rule_id, object_key) 做冷却期去重。
//
// 返回 created=false 表示冷却期内已有同规则同对象的告警，本次不产生新行（不是错误）。
//
// ★去重必须在一条语句里完成（INSERT … SELECT … WHERE NOT EXISTS）：
// 先 SELECT 再 INSERT 的写法在两个评估循环重叠时会双双判"没有"，
// 于是同一秒里插进两条一模一样的告警——冷却在并发下形同虚设。
func (s *SQLiteStore) RaiseAlert(ctx context.Context, a Alert, cooldownSec int) (Alert, bool, error) {
	if a.Status == "" {
		a.Status = AlertPending
	}
	if a.ID == "" {
		a.ID = "al-" + uuid.NewString()[:12]
	}
	since := a.TriggeredAt - int64(ClampAlertCooldown(cooldownSec))
	res, err := s.db.ExecContext(ctx, `INSERT INTO alerts(id,rule_id,kind,category,severity,title,detail,object_key,status,triggered_at,handled_at,handled_by)
SELECT ?,?,?,?,?,?,?,?,?,?,0,''
WHERE NOT EXISTS (
  SELECT 1 FROM alerts WHERE rule_id=? AND object_key=? AND triggered_at>?
)`,
		a.ID, a.RuleID, a.Kind, a.Category, a.Severity, a.Title, a.Detail, a.ObjectKey, a.Status, a.TriggeredAt,
		a.RuleID, a.ObjectKey, since)
	if err != nil {
		return Alert{}, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Alert{}, false, err
	}
	if n == 0 {
		return Alert{}, false, nil
	}
	return a, true, nil
}

// SetAlertStatus 处置一条告警（忽略 / 处理）。
//
// 状态机只允许 pending → ignored|handled：已处置的告警再处置回 ErrAlertDecided（409）。
// 放开"改主意"这条路的代价是审计上说不清——handled_by/handled_at 只有一组，
// 覆盖之后前一个人的处置就消失了。需要重新关注时，条件仍成立自会在冷却期后再报一条。
func (s *SQLiteStore) SetAlertStatus(ctx context.Context, id, status, by string, at int64) (Alert, error) {
	if status != AlertIgnored && status != AlertHandled {
		return Alert{}, ErrAlertDecided
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Alert{}, err
	}
	defer tx.Rollback()
	var cur string
	switch err := tx.QueryRowContext(ctx, `SELECT status FROM alerts WHERE id=?`, id).Scan(&cur); err {
	case nil:
	case sql.ErrNoRows:
		return Alert{}, ErrAlertNotFound
	default:
		return Alert{}, err
	}
	if cur != AlertPending {
		return Alert{}, ErrAlertDecided
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE alerts SET status=?, handled_at=?, handled_by=? WHERE id=? AND status=?`,
		status, at, by, id, AlertPending); err != nil {
		return Alert{}, err
	}
	var a Alert
	if err := tx.QueryRowContext(ctx, `SELECT id,rule_id,COALESCE(kind,''),category,severity,title,COALESCE(detail,''),
	  COALESCE(object_key,''),status,triggered_at,COALESCE(handled_at,0),COALESCE(handled_by,'') FROM alerts WHERE id=?`, id).
		Scan(&a.ID, &a.RuleID, &a.Kind, &a.Category, &a.Severity, &a.Title, &a.Detail,
			&a.ObjectKey, &a.Status, &a.TriggeredAt, &a.HandledAt, &a.HandledBy); err != nil {
		return Alert{}, err
	}
	if err := tx.Commit(); err != nil {
		return Alert{}, err
	}
	return a, nil
}

// StaleGrants 已过期但行仍标 active 的 JIT 授予（before = 判定时刻的 Unix 秒上界）。
//
// 这批行对数据面无害（ActiveGrants 按 expires_at 过滤，网关早已不放行），
// 但它们让「授权清单」显示的是失真状态——JIT 页上一条 active 的授予，实际早就不生效。
func (s *SQLiteStore) StaleGrants(ctx context.Context, before int64) ([]JitGrant, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+grantCols+` FROM jit_grants WHERE status='active' AND expires_at<=? ORDER BY expires_at`, before)
	if err != nil {
		return nil, err
	}
	// displayExpire=false：这里要的就是**库里那一份**状态（active），
	// 展示层纠正会把"该回收没回收"这件事抹平，而它正是本规则要报的事实。
	return scanGrants(rows, before, false)
}

// gatewayMetricsCols 本模块从 gateway_metrics 读的列。
//
// ★该表由「数据面资源指标上报」那条链路建立，本模块只做**运行时探测**：
// 表不存在 / 列对不上 / 表里还没有数据，三种情况都如实回报原因，而不是
// 静默不触发（那会让管理员以为在监控 CPU，其实什么都没在看）。
var gatewayMetricsCols = []string{"gateway_id", "cpu", "mem", "disk", "ts"}

// GatewayMetricsProbe 运行时探测网关资源指标数据源，并取各网关最近一次上报。
func (s *SQLiteStore) GatewayMetricsProbe(ctx context.Context) (MetricsProbe, error) {
	var name string
	switch err := s.db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name='gateway_metrics'`).Scan(&name); err {
	case nil:
	case sql.ErrNoRows:
		return MetricsProbe{Reason: "等待数据面上报：gateway_metrics 表尚未建立（网关资源指标上报未接入）"}, nil
	default:
		return MetricsProbe{}, err
	}
	// 列齐不齐要显式查：缺列时如果直接 SELECT 会每轮报一次 SQL 错误，
	// 而管理员在页面上只会看到"没有告警"。
	have := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(gateway_metrics)`)
	if err != nil {
		return MetricsProbe{}, err
	}
	for rows.Next() {
		var cid int
		var cname, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &cname, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return MetricsProbe{}, err
		}
		have[cname] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return MetricsProbe{}, err
	}
	var missing []string
	for _, c := range gatewayMetricsCols {
		if !have[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return MetricsProbe{Reason: "gateway_metrics 表结构与本规则的读取口径不一致，缺列：" +
			strings.Join(missing, "、") + "（规则不会触发，请对齐列名后再启用）"}, nil
	}
	// 每台网关取 ts 最大的那一行。SQLite 对 bare column + MAX() 聚合有明确保证：
	// 裸列取自 MAX 命中的那一行（这不是可移植写法，但本项目只用 SQLite）。
	mrows, err := s.db.QueryContext(ctx,
		`SELECT gateway_id, cpu, mem, disk, MAX(ts) FROM gateway_metrics GROUP BY gateway_id`)
	if err != nil {
		return MetricsProbe{}, err
	}
	defer mrows.Close()
	var samples []GatewayMetricSample
	for mrows.Next() {
		var m GatewayMetricSample
		if err := mrows.Scan(&m.GatewayID, &m.CPU, &m.Mem, &m.Disk, &m.TS); err != nil {
			return MetricsProbe{}, err
		}
		samples = append(samples, m)
	}
	if err := mrows.Err(); err != nil {
		return MetricsProbe{}, err
	}
	if len(samples) == 0 {
		return MetricsProbe{Reason: "等待数据面上报：gateway_metrics 表已建立但还没有任何一条指标"}, nil
	}
	return MetricsProbe{Ready: true, Samples: samples}, nil
}
