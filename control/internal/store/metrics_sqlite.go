package store

import (
	"context"
	"errors"
	"time"
)

// gateway_metrics 的落库实现：写入（一条心跳一行）、按桶聚合读出、超期清理。

// AppendGatewayMetric 落一条网关采样点。
//
// ★用 INSERT OR REPLACE 而不是 INSERT：主键是 (gateway_id, ts)，同一秒内的重复上报
// 覆盖而不是报错。这顺带给了一个天然的写入上界——**每网关每秒最多一行**，
// 一台发疯（或被攻陷）的网关拿高频心跳把表撑爆这条路直接堵死了。
// 代价是同一秒的第二次上报会盖掉第一次，而 15s 心跳下这本来就不该发生。
func (s *SQLiteStore) AppendGatewayMetric(ctx context.Context, p GatewayMetricPoint) error {
	if p.GatewayID == "" {
		return errors.New("网关 id 不能为空")
	}
	if p.TS == 0 {
		p.TS = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO gateway_metrics(gateway_id, ts, cpu, mem, disk, load, rx_bps, tx_bps)
		 VALUES(?,?,?,?,?,?,?,?)`,
		p.GatewayID, p.TS, p.CPU, p.Mem, p.Disk, p.Load, p.RxBps, p.TxBps)
	return err
}

// GatewayMetrics 取各网关的最新原始采样 + 查询窗内的降采样时序。
//
// 降采样在 SQL 里做（GROUP BY 桶键 + AVG），不是取回全部原始点再在 Go 里算：
// 72 小时 × 多网关的原始点集本身就是不该出现在进程内存里的量级。
//
// ★AVG 在 SQLite 里**跳过 NULL**：一个桶里若只有部分点采到了 CPU，得到的是
// 那几个点的均值；一个都没采到则整桶为 NULL（不可判定原样穿透到前端）。
// 这正是三态语义能贯穿「采集 → 上报 → 落库 → 聚合 → 渲染」全链路的关键——
// 中间任何一层用 COALESCE(x,0) 兜一下，前端就再也分不出「0%」和「没采到」。
func (s *SQLiteStore) GatewayMetrics(ctx context.Context, q MetricsQuery) ([]GatewayMetricSeries, error) {
	if q.BucketSec <= 0 {
		return nil, errors.New("桶宽必须大于 0")
	}
	// ── 各网关的最新一条原始采样 ──
	// 不受查询窗限制：一台两小时前掉线的网关，它最后报的那组值仍是「它最后的真实状态」，
	// 由 api/前端按 ts 标注陈旧度。窗内没有点就画不出线，但当前值该显示还是要显示。
	latest := map[string]*GatewayMetricPoint{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT m.gateway_id, m.ts, m.cpu, m.mem, m.disk, m.load, m.rx_bps, m.tx_bps
		   FROM gateway_metrics m
		   JOIN (SELECT gateway_id, MAX(ts) AS mts FROM gateway_metrics GROUP BY gateway_id) t
		     ON t.gateway_id = m.gateway_id AND t.mts = m.ts`)
	if err != nil {
		return nil, err
	}
	order := []string{}
	for rows.Next() {
		var p GatewayMetricPoint
		if err := rows.Scan(&p.GatewayID, &p.TS, &p.CPU, &p.Mem, &p.Disk, &p.Load, &p.RxBps, &p.TxBps); err != nil {
			rows.Close()
			return nil, err
		}
		cp := p
		latest[p.GatewayID] = &cp
		order = append(order, p.GatewayID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// ── 窗内降采样 ──
	buckets := map[string][]GatewayMetricBucket{}
	brows, err := s.db.QueryContext(ctx,
		`SELECT gateway_id, (ts / ?) * ? AS b, COUNT(*),
		        AVG(cpu), AVG(mem), AVG(disk), AVG(load), AVG(rx_bps), AVG(tx_bps)
		   FROM gateway_metrics
		  WHERE ts >= ? AND ts < ?
		  GROUP BY gateway_id, b
		  ORDER BY gateway_id, b`,
		q.BucketSec, q.BucketSec, q.Since, q.Until)
	if err != nil {
		return nil, err
	}
	defer brows.Close()
	for brows.Next() {
		var gw string
		var b GatewayMetricBucket
		if err := brows.Scan(&gw, &b.TS, &b.N, &b.CPU, &b.Mem, &b.Disk, &b.Load, &b.RxBps, &b.TxBps); err != nil {
			return nil, err
		}
		if _, seen := latest[gw]; !seen {
			// 理论上不可能（有桶就必有最新点），但真出现时也别把这台网关整个丢掉
			latest[gw] = nil
			order = append(order, gw)
		}
		buckets[gw] = append(buckets[gw], b)
	}
	if err := brows.Err(); err != nil {
		return nil, err
	}

	out := make([]GatewayMetricSeries, 0, len(order))
	for _, gw := range order {
		pts := buckets[gw]
		if pts == nil {
			pts = []GatewayMetricBucket{} // JSON 里是 []，不是 null——前端少一处判空
		}
		out = append(out, GatewayMetricSeries{GatewayID: gw, Latest: latest[gw], Points: pts})
	}
	return out, nil
}

// PurgeExpiredGatewayMetrics 删掉超过留存期的采样点，返回删除行数。
//
// ★retentionHours **不接受 0/负数当作"不清理"**（与审计留存的语义刻意不同）。
// 审计是低频写入且法规上要求长留存，metrics 是 15s 一条的写入热点：给它留一个
// "关掉清理"的开关，等于给运维留一个把库撑爆的按钮，而且撑爆前毫无征兆。
// 传入非正数时按调用方的配置错误处理，直接报错——config 层已保证落到默认 72。
func (s *SQLiteStore) PurgeExpiredGatewayMetrics(ctx context.Context, retentionHours int) (int64, error) {
	if retentionHours <= 0 {
		return 0, errors.New("设备状态留存小时数必须为正（这张表是写入热点，不提供关闭清理的选项）")
	}
	cut := time.Now().Add(-time.Duration(retentionHours) * time.Hour).Unix()
	res, err := s.db.ExecContext(ctx, `DELETE FROM gateway_metrics WHERE ts < ?`, cut)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
