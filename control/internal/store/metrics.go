package store

// ── 监控中心 · 设备状态时序（PRD ch5 FR-MON-01/02）──
//
// 网关宿主机的 CPU / 内存 / 磁盘 / 负载 / 收发速率由数据面随 mTLS 心跳上报，
// 控制面逐点落 gateway_metrics 表。
//
// ★这是本系统第一个**高频写入**的数据域（每网关 15s 一条 ≈ 每天 5760 行）。
// 因此留存上限与降采样不是事后优化，而是这张表存在的前提之一：不设上限它就会
// 长成第二个「日志只增不删」；不降采样就会把 72 小时的 17280 个原始点整包打给
// 浏览器，页面卡死而后端毫无异常。两件事分别由 PurgeExpiredGatewayMetrics
// 与 MetricsQuery.BucketSec 负责。

// GatewayMetricPoint 一条网关宿主机的原始采样点。
//
// ★每个指标都是**可空**的：nil = 网关如实报告「这一项采不到」（不可判定），
// 不是 0。落库时 nil → SQL NULL，聚合时 AVG 自动跳过它，前端渲染成「—」。
// 塌缩成 0 的后果是「CPU 0%」看起来像一台空闲的机器，而告警规则（CPU>80%）
// 会对一台失明的网关永远保持沉默——与终端 posture 的 unknown 是同一条纪律。
type GatewayMetricPoint struct {
	GatewayID string   `json:"gatewayId"`
	TS        int64    `json:"ts"` // 采样时刻（Unix 秒，控制面收到心跳的时刻，见 api 层说明）
	CPU       *float64 `json:"cpu"`
	Mem       *float64 `json:"mem"`
	Disk      *float64 `json:"disk"`
	Load      *float64 `json:"load"`
	RxBps     *float64 `json:"rxBps"`
	TxBps     *float64 `json:"txBps"`
}

// GatewayMetricBucket 降采样后的一个时间桶（桶内原始点的算术平均）。
//
// ★**空桶不返回**。网关掉线那段时间在结果里表现为「相邻两桶的 ts 差 > BucketSec」，
// 前端据此把折线断开。若给空桶补一行零值，图上就会出现一条完美的零线——
// 那正是「不要画一条假的平线」要挡的东西。N 让前端能区分「这个桶只有一个点」
// 与「这个桶是满的」，也是降采样是否真的生效的自检口。
type GatewayMetricBucket struct {
	TS    int64    `json:"ts"` // 桶起点：floor(原始 ts / BucketSec) * BucketSec
	N     int      `json:"n"`  // 桶内原始采样点数（≥1）
	CPU   *float64 `json:"cpu"`
	Mem   *float64 `json:"mem"`
	Disk  *float64 `json:"disk"`
	Load  *float64 `json:"load"`
	RxBps *float64 `json:"rxBps"`
	TxBps *float64 `json:"txBps"`
}

// GatewayMetricSeries 一台网关的时序结果。
type GatewayMetricSeries struct {
	GatewayID string `json:"gatewayId"`
	// Latest 该网关**最新的一条原始采样**，不是任何桶的平均值。
	// 「当前值」必须来自数据面真正报上来的那一份：拿最后一个桶的均值当现值，
	// 会把一台刚刚冲到 95% 的机器显示成 60%（被同桶内前几个点摊平了）。
	// nil = 该网关在留存期内没有任何采样（旧网关只发心跳不发指标即如此）。
	Latest *GatewayMetricPoint `json:"latest"`
	// Points 降采样后的时间桶，按 TS 升序；查询窗内无数据则为空切片。
	Points []GatewayMetricBucket `json:"points"`
}

// MetricsQuery 时间窗 + 桶宽。
//
// store 层刻意只认「秒」，不认 hour/day/week 这三个词——时间窗档位是展示层的概念，
// 让它渗进 store 就会出现两处各自换算、两处慢慢对不上的老问题。换算在 api 层一处完成。
type MetricsQuery struct {
	Since     int64 // 起点，含（Unix 秒）
	Until     int64 // 终点，**不含**（半开区间 [Since, Until)：相邻两个时间窗才不会重复计入边界点）
	BucketSec int64 // 桶宽（秒），必须 >0
}
