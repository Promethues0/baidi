package store

// gateway_metrics 落库层的测试：三态穿透、降采样的时间窗与桶边界、留存清理、空态。

import (
	"context"
	"testing"
	"time"
)

func f(v float64) *float64 { return &v }

// mustAppend 落一条采样点。
func mustAppend(t *testing.T, s *SQLiteStore, gw string, ts int64, cpu, mem *float64) {
	t.Helper()
	if err := s.AppendGatewayMetric(context.Background(), GatewayMetricPoint{
		GatewayID: gw, TS: ts, CPU: cpu, Mem: mem,
	}); err != nil {
		t.Fatalf("落 %s@%d 失败：%v", gw, ts, err)
	}
}

// 空库 = 空态：既没有序列也没有错误。这一页的空态必须是真空态，
// 前端据此显示「无数据面上报」，而不是画一条零线。
func TestGatewayMetricsEmptyStore(t *testing.T) {
	s := openTestStore(t)
	got, err := s.GatewayMetrics(context.Background(), MetricsQuery{Since: 0, Until: 1 << 40, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if len(got) != 0 {
		t.Fatalf("空库应返回零条序列，实际 %d 条：%+v", len(got), got)
	}
}

// 不可判定（nil）必须原样穿透：落库为 NULL，聚合时 AVG 跳过，
// 整桶都没采到则整桶为 nil——任何一层补 0 都会让「0%」与「没采到」不可区分。
func TestGatewayMetricsUnknownStaysNull(t *testing.T) {
	s := openTestStore(t)
	const base = 1_700_000_000
	// 同一个 60s 桶里两条：CPU 一条有一条没有，内存两条都没有
	mustAppend(t, s, "gw-1", base+1, f(40), nil)
	mustAppend(t, s, "gw-1", base+2, nil, nil)

	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base, Until: base + 60, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if len(got) != 1 || len(got[0].Points) != 1 {
		t.Fatalf("应有 1 台网关 1 个桶，实际 %+v", got)
	}
	b := got[0].Points[0]
	if b.N != 2 {
		t.Errorf("桶内点数 %d，期望 2", b.N)
	}
	// AVG 只对采到的那一条求平均 → 40，而不是 (40+0)/2=20
	if b.CPU == nil || *b.CPU != 40 {
		t.Errorf("CPU 桶均值应只算采到的那条（40），实际 %v", b.CPU)
	}
	if b.Mem != nil {
		t.Errorf("整桶都没采到内存时应为不可判定（nil），实际 %v——补 0 会让"+
			"「内存 0%%」与「没采到内存」不可区分", *b.Mem)
	}
}

// 当前值取**最新一条原始采样**，不是最后一个桶的均值。
// 桶均值会把一台刚冲到 95% 的机器摊平，而这一页存在的意义就是看现在。
func TestGatewayMetricsLatestIsRawNotBucketAverage(t *testing.T) {
	s := openTestStore(t)
	const base = 1_700_000_000
	mustAppend(t, s, "gw-1", base+1, f(10), nil)
	mustAppend(t, s, "gw-1", base+2, f(20), nil)
	mustAppend(t, s, "gw-1", base+3, f(95), nil) // 最新

	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base, Until: base + 60, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	sr := got[0]
	if sr.Latest == nil || sr.Latest.CPU == nil || *sr.Latest.CPU != 95 {
		t.Fatalf("当前值应是最新那条原始采样 95，实际 %+v", sr.Latest)
	}
	if sr.Latest.TS != base+3 {
		t.Errorf("当前值时刻 %d，期望 %d", sr.Latest.TS, base+3)
	}
	// 桶均值是 (10+20+95)/3 = 41.67，与当前值刻意不同源
	if b := sr.Points[0]; b.CPU == nil || *b.CPU > 42 || *b.CPU < 41 {
		t.Errorf("桶均值应为 ~41.67，实际 %v", b.CPU)
	}
}

// 时间窗是半开区间 [Since, Until)：起点含、终点不含。
// 闭区间会让相邻两个窗口重复计入边界点，翻页时同一条数据出现两次。
func TestGatewayMetricsWindowIsHalfOpen(t *testing.T) {
	s := openTestStore(t)
	const base = 1_700_000_000
	mustAppend(t, s, "gw-1", base-1, f(1), nil) // 窗前，不该进
	mustAppend(t, s, "gw-1", base, f(2), nil)   // 起点，含
	mustAppend(t, s, "gw-1", base+59, f(3), nil)
	mustAppend(t, s, "gw-1", base+60, f(4), nil) // 终点，不含

	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base, Until: base + 60, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	total := 0
	for _, b := range got[0].Points {
		total += b.N
	}
	if total != 2 {
		t.Fatalf("窗内点数 %d，期望 2（起点含、终点不含、窗前不进）：%+v", total, got[0].Points)
	}
}

// 桶键 = floor(ts / bucket) * bucket：跨桶边界的点必须落到各自的桶，
// 且返回顺序按时间升序（前端直接连线，不再排一次）。
func TestGatewayMetricsBucketBoundary(t *testing.T) {
	s := openTestStore(t)
	// 取一个能被 60 整除的基准，好让桶边界一目了然
	const base = 1_700_000_040 // 1700000040 % 60 == 0
	mustAppend(t, s, "gw-1", base+0, f(10), nil)
	mustAppend(t, s, "gw-1", base+59, f(20), nil) // 与上一条同桶
	mustAppend(t, s, "gw-1", base+60, f(80), nil) // 下一个桶的第一个点

	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base, Until: base + 120, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	pts := got[0].Points
	if len(pts) != 2 {
		t.Fatalf("应分成 2 个桶，实际 %d：%+v", len(pts), pts)
	}
	if pts[0].TS != base || pts[1].TS != base+60 {
		t.Fatalf("桶起点应为 %d / %d，实际 %d / %d", base, base+60, pts[0].TS, pts[1].TS)
	}
	if pts[0].N != 2 || pts[1].N != 1 {
		t.Errorf("桶内点数应为 2 / 1，实际 %d / %d", pts[0].N, pts[1].N)
	}
	if *pts[0].CPU != 15 || *pts[1].CPU != 80 {
		t.Errorf("桶均值应为 15 / 80，实际 %v / %v", *pts[0].CPU, *pts[1].CPU)
	}
}

// 降采样真的在降：72 小时的原始点（15s 一条）按小时桶聚合后只剩 72 个点上下，
// 而不是把 17280 个原始点整包端给前端。
func TestGatewayMetricsDownsamples(t *testing.T) {
	s := openTestStore(t)
	const base = 1_699_999_200 // 能被 3600 整除，让 2 小时正好落成 2 个整桶
	// 2 小时 × 每 15s 一条 = 480 条
	for i := 0; i < 480; i++ {
		mustAppend(t, s, "gw-1", base+int64(i)*15, f(float64(i%100)), nil)
	}
	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base, Until: base + 7200, BucketSec: 3600})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if n := len(got[0].Points); n != 2 {
		t.Fatalf("480 个原始点按小时桶应压成 2 个点，实际 %d", n)
	}
	if got[0].Points[0].N != 240 {
		t.Errorf("首桶原始点数 %d，期望 240", got[0].Points[0].N)
	}
}

// 掉线段**不返回空桶**：相邻两桶的 ts 跨度大于桶宽，前端据此断线。
// 补零桶会在图上画出一条完美的平线，看起来像「那段时间很闲」。
func TestGatewayMetricsGapHasNoFilledBucket(t *testing.T) {
	s := openTestStore(t)
	const base = 1_700_000_040
	mustAppend(t, s, "gw-1", base, f(30), nil)
	mustAppend(t, s, "gw-1", base+300, f(35), nil) // 中间空了 4 个桶

	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base, Until: base + 360, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	pts := got[0].Points
	if len(pts) != 2 {
		t.Fatalf("掉线段不该补桶：期望 2 个桶，实际 %d（%+v）", len(pts), pts)
	}
	if pts[1].TS-pts[0].TS != 300 {
		t.Errorf("两桶应相隔 300s（前端据此断线），实际 %d", pts[1].TS-pts[0].TS)
	}
}

// 窗内无数据但库里有旧数据：序列仍返回（带陈旧的当前值），Points 为空数组而非 null。
// 「这台网关最后一次报的是什么」与「这段时间它在不在」是两个问题，都要答。
func TestGatewayMetricsStaleLatestSurvivesEmptyWindow(t *testing.T) {
	s := openTestStore(t)
	const base = 1_700_000_000
	mustAppend(t, s, "gw-1", base, f(50), nil)

	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base + 10000, Until: base + 20000, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if len(got) != 1 {
		t.Fatalf("应返回 1 条序列（当前值仍有意义），实际 %d", len(got))
	}
	if got[0].Latest == nil || *got[0].Latest.CPU != 50 {
		t.Errorf("窗外的最新采样仍应作为当前值返回，实际 %+v", got[0].Latest)
	}
	if got[0].Points == nil || len(got[0].Points) != 0 {
		t.Errorf("窗内无点时 Points 应是空数组（JSON 里的 []），实际 %v", got[0].Points)
	}
}

// 同一秒重复上报覆盖而不是报错：主键 (gateway_id, ts) 顺带把写入速率钉在每秒一行。
func TestAppendGatewayMetricSameSecondReplaces(t *testing.T) {
	s := openTestStore(t)
	const base = 1_700_000_000
	mustAppend(t, s, "gw-1", base, f(10), nil)
	mustAppend(t, s, "gw-1", base, f(90), nil)

	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base, Until: base + 60, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if got[0].Points[0].N != 1 {
		t.Fatalf("同一秒的重复上报应覆盖，桶内点数 %d，期望 1", got[0].Points[0].N)
	}
	if *got[0].Latest.CPU != 90 {
		t.Errorf("应保留后写入的那条（90），实际 %v", *got[0].Latest.CPU)
	}
}

// 空网关 id 拒收：写进去只会得到一批归属不明、永远查不出来的行。
func TestAppendGatewayMetricRejectsEmptyID(t *testing.T) {
	s := openTestStore(t)
	if err := s.AppendGatewayMetric(context.Background(),
		GatewayMetricPoint{TS: 1, CPU: f(1)}); err == nil {
		t.Fatal("空网关 id 应被拒绝")
	}
}

// 留存清理：超期行删掉、期内行留下，且**不提供"关闭清理"这一档**。
func TestPurgeExpiredGatewayMetrics(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	old := now - int64(80*time.Hour/time.Second)  // 80 小时前，超 72 小时留存
	fresh := now - int64(2*time.Hour/time.Second) // 2 小时前，留
	edge := now - int64(71*time.Hour/time.Second) // 71 小时前，留（边界内）
	mustAppend(t, s, "gw-1", old, f(1), nil)
	mustAppend(t, s, "gw-1", edge, f(2), nil)
	mustAppend(t, s, "gw-1", fresh, f(3), nil)

	n, err := s.PurgeExpiredGatewayMetrics(ctx, 72)
	if err != nil {
		t.Fatalf("清理失败：%v", err)
	}
	if n != 1 {
		t.Fatalf("应删掉 1 行超期采样，实际 %d", n)
	}
	got, err := s.GatewayMetrics(ctx, MetricsQuery{Since: 0, Until: now + 1, BucketSec: 3600})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	total := 0
	for _, b := range got[0].Points {
		total += b.N
	}
	if total != 2 {
		t.Fatalf("清理后应剩 2 行，实际 %d", total)
	}
	// 幂等：再清一次不该再删
	if n, err := s.PurgeExpiredGatewayMetrics(ctx, 72); err != nil || n != 0 {
		t.Fatalf("重复清理应为空操作，得到 n=%d err=%v", n, err)
	}
	// 非正数不是"不清理"，是配置错误——这张表是写入热点，不给关闭清理的开关
	if _, err := s.PurgeExpiredGatewayMetrics(ctx, 0); err == nil {
		t.Error("留存 0 应报错而不是静默关闭清理")
	}
}

// 桶宽非法直接报错，而不是悄悄按某个默认值聚合出一张对不上时间轴的图。
func TestGatewayMetricsRejectsZeroBucket(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: 0, Until: 100, BucketSec: 0}); err == nil {
		t.Fatal("桶宽为 0 应报错")
	}
}

// 多网关各自成序列，互不串台。
func TestGatewayMetricsPerGateway(t *testing.T) {
	s := openTestStore(t)
	const base = 1_700_000_040
	mustAppend(t, s, "gw-1", base, f(10), nil)
	mustAppend(t, s, "gw-2", base, f(90), nil)

	got, err := s.GatewayMetrics(context.Background(),
		MetricsQuery{Since: base, Until: base + 60, BucketSec: 60})
	if err != nil {
		t.Fatalf("查询失败：%v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应有 2 条序列，实际 %d", len(got))
	}
	byID := map[string]GatewayMetricSeries{}
	for _, sr := range got {
		byID[sr.GatewayID] = sr
	}
	if *byID["gw-1"].Latest.CPU != 10 || *byID["gw-2"].Latest.CPU != 90 {
		t.Errorf("两台网关的值串台了：%+v", byID)
	}
}
