package store

import (
	"context"
	"time"
)

// attackBucketSec 小时桶宽。写入率被网关侧节流钉死（每 (网关,IP,类别) 5 分钟至多
// 两条事件），按小时聚合后单桶单键至多 +12 次 upsert——表增长率有硬上界。
const attackBucketSec = 3600

// RecordAttack 累加一条拒绝事件到小时桶。
func (s *SQLiteStore) RecordAttack(ctx context.Context, gatewayID, ip, cat string, count int, ts int64) error {
	if count <= 0 {
		count = 1
	}
	bucket := ts / attackBucketSec * attackBucketSec
	_, err := s.db.ExecContext(ctx, `
INSERT INTO attack_sources(gateway_id, ip, cat, bucket, count, last_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(gateway_id, ip, cat, bucket) DO UPDATE SET
  count = count + excluded.count, last_at = excluded.last_at`,
		gatewayID, ip, cat, bucket, count, nowStr())
	return err
}

// AttackStats 近 sinceHours 小时的聚合统计（安全概览取数点）。
func (s *SQLiteStore) AttackStats(ctx context.Context, sinceHours int) (AttackStat, error) {
	if sinceHours <= 0 {
		sinceHours = 24
	}
	now := time.Now().Unix()
	curBucket := now / attackBucketSec * attackBucketSec
	since := curBucket - int64(sinceHours-1)*attackBucketSec
	st := AttackStat{Top: []AttackTop{}, Trend: []KV{}}

	// 总量与独立来源数
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ip), COALESCE(SUM(count),0) FROM attack_sources WHERE bucket>=?`,
		since).Scan(&st.Sources, &st.Denies)
	if err != nil {
		return AttackStat{}, err
	}

	// TOP5 来源 + 各自的主要类别（窗口内计数最多的 cat）
	rows, err := s.db.QueryContext(ctx, `
SELECT ip, SUM(count) AS total,
  (SELECT a2.cat FROM attack_sources a2
   WHERE a2.ip = a1.ip AND a2.bucket>=? GROUP BY a2.cat
   ORDER BY SUM(a2.count) DESC LIMIT 1)
FROM attack_sources a1 WHERE bucket>=?
GROUP BY ip ORDER BY total DESC, ip LIMIT 5`, since, since)
	if err != nil {
		return AttackStat{}, err
	}
	for rows.Next() {
		var t AttackTop
		var cat string
		if err := rows.Scan(&t.IP, &t.Count, &cat); err != nil {
			rows.Close()
			return AttackStat{}, err
		}
		t.Cat = attackCatLabel(cat)
		st.Top = append(st.Top, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return AttackStat{}, err
	}

	// 逐小时趋势：空桶补 0（「这一小时没有拒绝」是真实事实，不是不可判定）。
	byBucket := map[int64]int{}
	brows, err := s.db.QueryContext(ctx,
		`SELECT bucket, SUM(count) FROM attack_sources WHERE bucket>=? GROUP BY bucket`, since)
	if err != nil {
		return AttackStat{}, err
	}
	for brows.Next() {
		var b int64
		var n int
		if err := brows.Scan(&b, &n); err != nil {
			brows.Close()
			return AttackStat{}, err
		}
		byBucket[b] = n
	}
	brows.Close()
	if err := brows.Err(); err != nil {
		return AttackStat{}, err
	}
	for b := since; b <= curBucket; b += attackBucketSec {
		st.Trend = append(st.Trend, KV{
			Name:  time.Unix(b, 0).Format("15:04"),
			Value: byBucket[b],
		})
	}
	return st, nil
}

// PurgeAttackSources 删掉 before 之前的小时桶（留存清理循环消费）。
func (s *SQLiteStore) PurgeAttackSources(ctx context.Context, before int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM attack_sources WHERE bucket < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
