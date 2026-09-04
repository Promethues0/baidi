package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

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
	// ★逐种类判断"这一类有没有规则"，而不是靠一个全局的一次性标记。
	//
	//   原来那个标记（alertRuleSeedMarker）一旦落下，**后来新增的规则种类就再也不会
	//   被播种**：升级到带新规则的版本后，那一类在告警页上根本不存在，也永远不会触发，
	//   而页面上看不出缺了什么——与「补列迁移必须配回填」是同一个坑，只是坑在规则表上。
	//   本波新增 audit_forward_fail 时正好会踩到它。
	//
	//   改成按种类幂等之后，标记只用来区分"首次初始化"（那次要把全部种类播齐），
	//   之后每次启动都会把**缺失的种类**补上。管理员**删掉**的规则不会被复活：
	//   删除时会连同它的种类记进 alertRuleRemovedMarker（见 DeleteAlertRule）。
	existing, err := s.AlertRules(ctx)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, r := range existing {
		have[r.Kind] = true
	}
	removed, err := s.removedAlertKinds(ctx)
	if err != nil {
		return err
	}
	for _, spec := range AlertKindSpecs() {
		if have[spec.Kind] || removed[spec.Kind] {
			continue
		}
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

// alertRuleRemovedMarker 记下管理员**主动删过**的规则种类，避免下次启动把它播回来。
const alertRuleRemovedMarker = "alert.rules.removed.v1"

// removedAlertKinds 读那份"别再播了"的清单。
func (s *SQLiteStore) removedAlertKinds(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	raw, ok, err := s.Setting(ctx, alertRuleRemovedMarker)
	if err != nil || !ok || raw == "" {
		return out, err
	}
	for _, k := range jsonStrings(raw) {
		out[k] = true
	}
	return out, nil
}

// noteRemovedAlertKind 把一个被删掉的种类记进清单（幂等）。
func (s *SQLiteStore) noteRemovedAlertKind(ctx context.Context, kind string) error {
	if kind == "" {
		return nil
	}
	cur, err := s.removedAlertKinds(ctx)
	if err != nil {
		return err
	}
	if cur[kind] {
		return nil
	}
	cur[kind] = true
	keys := make([]string, 0, len(cur))
	for k := range cur {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	raw, _ := json.Marshal(keys)
	return s.SetSetting(ctx, alertRuleRemovedMarker, string(raw))
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
	// 先取种类：播种改成"按种类补齐"之后，删掉的规则会在下次启动被播回来，
	// 而管理员会以为自己没删掉（或者删了又长出来）。记进"别再播"清单。
	var kind string
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(kind,'') FROM alert_rules WHERE id=?`, id).Scan(&kind)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM alert_rules WHERE id=?`, id); err != nil {
		return err
	}
	// 同种类还剩别的规则时不记（管理员只是删了其中一条）。
	var left int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_rules WHERE kind=?`, kind).Scan(&left)
	if left > 0 {
		return nil
	}
	return s.noteRemovedAlertKind(ctx, kind)
}

// AlertListLimit 列表读取上限：告警页一屏 + 余量，避免一次拉走全表。
// 导出给前端是为了让页面能原样说出「本页只显示最近 N 条」，而不是自己猜一个数。
const AlertListLimit = 200

// defaultAlertLimit 保留原名供包内使用。
const defaultAlertLimit = AlertListLimit

// alertWhere 拼过滤条件——**列表与计数必须共用**：各写一份的话，
// 「共 N 条」与列表里的行会按两套条件算，而那个差值看起来就像丢了记录。
func alertWhere(q AlertQuery) (string, []any) {
	sb := strings.Builder{}
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
	return sb.String(), args
}

// CountAlerts 按同一组过滤条件数**库里的总行数**（不受 LIMIT 影响）。
//
// ★截断必须可见（同 store.ListLimit 那条纪律）：列表被 defaultAlertLimit=200 硬截，
// 而页头那三个计数是**全局量**（不随筛选变）。两者并排时，未处理超过 200 条的部署
// 会显示「未处理 350」+ 一张 200 行的表，第 201 条之后的告警在管理台上根本不存在，
// 页面上也没有任何一句话提示被截断过。
func (s *SQLiteStore) CountAlerts(ctx context.Context, q AlertQuery) (int, error) {
	where, args := alertWhere(q)
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE 1=1`+where, args...).Scan(&n)
	return n, err
}

// Alerts 按条件查告警（新→旧）。
func (s *SQLiteStore) Alerts(ctx context.Context, q AlertQuery) ([]Alert, error) {
	sb := strings.Builder{}
	sb.WriteString(`SELECT id,rule_id,COALESCE(kind,''),category,severity,title,COALESCE(detail,''),
	  COALESCE(object_key,''),status,triggered_at,COALESCE(handled_at,0),COALESCE(handled_by,'') FROM alerts WHERE 1=1`)
	where, args := alertWhere(q)
	sb.WriteString(where)
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

// RaiseAlert 产生一条告警，按 (rule_id, object_key) 去重：
//
//	① 该对象上**还挂着一条未处置（pending）的告警** → 不产生新行；
//	② 否则看时间冷却：冷却期内已报过 → 不产生新行。
//
// 返回 created=false 表示本次被去重掉了（不是错误）。
//
// ★①（未处置即压制）是**留存上界**的来源。有一类规则的条件是**永久成立**的——
// 最典型的是 grant_stale：过期的 JIT 授予行在库里永远标着 active（全系统没有回收动作，
// 那正是这条规则要报的事实），于是每条陈旧授予每个冷却周期都能产出一行新告警
// + 一次通知 + 一两条审计，48 行/天/对象、只增不减。没有 ① 的话，"冷却"只降频、
// 不终止。有了 ① 之后待办量收敛成"每个真实对象至多一条"，而管理员点掉之后
// 条件若仍成立，会在冷却期后如常再报一条（不会被永久静默）。
//
// ★② 仍然**只看时间不看状态**：按状态放宽（比如"处置过就立刻能再报"）会让人一点
// 「已处理」就当场冒出同一条。①② 方向相反、各管一段，合起来才既有上界又不失灵。
//
// ★去重必须在一条语句里完成（INSERT … SELECT … WHERE NOT EXISTS）：
// 先 SELECT 再 INSERT 的写法在两个评估循环重叠时会双双判"没有"，
// 于是同一秒里插进两条一模一样的告警——去重在并发下形同虚设。
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
  SELECT 1 FROM alerts WHERE rule_id=? AND object_key=? AND (status=? OR triggered_at>?)
)`,
		a.ID, a.RuleID, a.Kind, a.Category, a.Severity, a.Title, a.Detail, a.ObjectKey, a.Status, a.TriggeredAt,
		a.RuleID, a.ObjectKey, AlertPending, since)
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

// PurgeExpiredAlerts 清理 days 天前**已处置**的告警（days<=0 不清理），返回删除行数。
//
// ★为什么需要留存轮转：告警是只追加的，而多条规则的触发条件是**长期成立**的
// （网关持续离线、应用长期未关联资源、过期授予没有回收动作）。即便有"未处置即压制"
// 这道上界，管理员每处置一条，条件仍成立的对象就会在冷却期后再产生一条——
// 处置过的行按天累积，且此前全仓没有任何 DELETE FROM alerts。
//
// ★为什么**只清已处置的**（pending 一律留着）：pending 是一条待办。按时间删掉待办
// 等于让"没人管的问题"自己消失，而角标与列表会同时变干净——这恰恰是本项目最忌讳的
// 那种"看起来正常"。pending 的行数已由 RaiseAlert 的未处置压制钳住（每对象至多一条），
// 不需要靠留存期去兜底。
func (s *SQLiteStore) PurgeExpiredAlerts(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -days).Unix()
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM alerts WHERE status<>? AND triggered_at<?`, AlertPending, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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

// alertThresholdClampMarker 阈值越界值的一次性清洗标记。
const alertThresholdClampMarker = "alert.rules.threshold.clamp.v1"

// clampAlertThresholds 把库里越界的阈值夹回该键的默认值，一次性。
//
// ★为什么必须有：本波给阈值加了取值区间，但**只校验写入侧**。而库里已经落了 0 的行
// 正是这次要修的那个缺陷（前端输入框清空 → `Number(nv ?? 0)`）留下的产物——
// 「存量库里有 0」不是假设，是这次修复的前提。
//
// 不清洗的后果是**规则在界面上被彻底锁死**：控制台 saveRule 每次都整条 POST
// （`body = {...r, ...patch}`），于是管理员哪怕只想把这条吵闹的规则**关掉**，
// 也会被 400 挡回，理由指向一个他根本没碰的阈值框。gateway_load 有三个阈值键，
// 只要其中两个是 0，逐个改都改不完——每次提交都带着另一个 0。只能上机改库。
//
// ★迁移里做夹取不违反「拒绝而非夹取」那条纪律：那条管的是**入口**——管理员当场提交的
// 越界值必须拒，不能给他 200 OK 而实际生效另一个数；历史脏数据没有"当场"可言，
// 只能夹，且必须留痕（落审计写清哪条规则的哪一项从多少改成了多少），
// 否则管理员会发现自己配的值变了而查不出是谁改的。
func (s *SQLiteStore) clampAlertThresholds(ctx context.Context) error {
	if _, done, err := s.Setting(ctx, alertThresholdClampMarker); err != nil || done {
		return err
	}
	rules, err := s.AlertRules(ctx)
	if err != nil {
		return err
	}
	for _, r := range rules {
		spec, ok := AlertKindSpecOf(r.Kind)
		if !ok {
			continue // 库里有未知 kind：不是本函数该管的事，留给别处报
		}
		var fixed []string
		next := map[string]float64{}
		for k, v := range r.Threshold {
			next[k] = v
			if _, known := spec.Thresholds[k]; !known {
				continue
			}
			if err := checkThresholdRange(k, spec.ThresholdZh[k], v); err != nil {
				def := spec.Thresholds[k]
				next[k] = def
				fixed = append(fixed, fmt.Sprintf("%s %g→%g", spec.ThresholdZh[k], v, def))
			}
		}
		if len(fixed) == 0 {
			continue
		}
		sort.Strings(fixed) // map 遍历无序：审计正文每次运行都该一样
		b, err := json.Marshal(next)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE alert_rules SET threshold_json=? WHERE id=?`, string(b), r.ID); err != nil {
			return err
		}
		if err := s.RecordAudit(ctx, AuditEntry{
			Category: "admin", User: "system", Verdict: "ok",
			Event: fmt.Sprintf("清洗越界的告警阈值（规则「%s」）：%s。"+
				"这些值是旧版本输入框清空时落下的，会让该规则在控制台上改不动也关不掉", r.Name, strings.Join(fixed, "、")),
		}); err != nil {
			return err
		}
	}
	return s.SetSetting(ctx, alertThresholdClampMarker, nowStr())
}
