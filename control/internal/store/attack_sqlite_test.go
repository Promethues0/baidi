package store

import (
	"context"
	"testing"
	"time"
)

// 计数累加 + 24h 聚合口径（来源数/总量/TOP/趋势补零）。
func TestAttackRecordAndStats(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	// 同 (网关,IP,类别,桶) 累加；不同 IP 分行
	if err := s.RecordAttack(ctx, "gw-1", "203.0.113.9", "knock-replay", 5, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttack(ctx, "gw-1", "203.0.113.9", "knock-replay", 95, now); err != nil {
		t.Fatal(err)
	}
	_ = s.RecordAttack(ctx, "gw-1", "203.0.113.9", "web-ticket", 1, now)
	_ = s.RecordAttack(ctx, "gw-2", "198.51.100.7", "proxy-unauth", 3, now)
	// count<=0 兜底为 1（旧网关不带 count 字段）
	_ = s.RecordAttack(ctx, "gw-1", "198.51.100.8", "knock-token", 0, now)

	st, err := s.AttackStats(ctx, 24)
	if err != nil {
		t.Fatal(err)
	}
	if st.Sources != 3 {
		t.Fatalf("独立来源应 3，实得 %d", st.Sources)
	}
	if st.Denies != 5+95+1+3+1 {
		t.Fatalf("总量应 105，实得 %d", st.Denies)
	}
	if len(st.Top) == 0 || st.Top[0].IP != "203.0.113.9" || st.Top[0].Count != 101 {
		t.Fatalf("TOP1 应为 203.0.113.9×101，实得 %+v", st.Top)
	}
	// 主要类别取该 IP 计数最多的那类，展示中文名
	if st.Top[0].Cat != AttackCatZh["knock-replay"] {
		t.Fatalf("TOP1 主类别应为敲门令牌重放，实得 %q", st.Top[0].Cat)
	}
	// 趋势 24 桶补零：只有当前小时非零
	if len(st.Trend) != 24 {
		t.Fatalf("趋势应 24 个小时桶，实得 %d", len(st.Trend))
	}
	nonzero, sum := 0, 0
	for _, kv := range st.Trend {
		if kv.Value > 0 {
			nonzero++
		}
		sum += kv.Value
	}
	// 写入与查询之间可能跨过小时边界（写入落上一桶），只断言"单桶承载全部计数"。
	if nonzero != 1 || sum != 105 {
		t.Fatalf("应只有一个非零桶且和为总量，实得 %v", st.Trend)
	}
}

// 留存清理只删过期桶；未知类别原样显示不编造。
func TestAttackPurgeAndUnknownCat(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	old := now - 40*24*3600

	_ = s.RecordAttack(ctx, "gw-1", "203.0.113.1", "knock-token", 2, old)
	_ = s.RecordAttack(ctx, "gw-1", "203.0.113.2", "future-cat", 7, now)

	n, err := s.PurgeAttackSources(ctx, now-30*24*3600)
	if err != nil || n != 1 {
		t.Fatalf("应删 1 行过期桶，实得 n=%d err=%v", n, err)
	}
	st, _ := s.AttackStats(ctx, 24)
	if st.Sources != 1 || st.Top[0].Cat != "future-cat" {
		t.Fatalf("未知类别应原样显示，实得 %+v", st)
	}
}
