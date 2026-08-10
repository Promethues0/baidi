package api

// 监控中心 · 设备状态（PRD ch5 FR-MON-01/02）。
//
// 写侧：网关随 mTLS 心跳带上来的宿主机指标，逐条落 gateway_metrics（见 handleGatewayRegister）。
// 读侧：GET /api/v1/monitor/device-stat，按 range 档位降采样后返回。
//
// 三条贯穿全链路的纪律：
//
//  1. **不可判定 ≠ 0**。网关采不到的指标在报文里缺席 → 落库 NULL → 聚合 AVG 跳过 →
//     前端渲染「—」。中间任何一层补 0，「CPU 0%」就会伪装成一台空闲的机器。
//  2. **当前值取最新那条原始采样**，不是最后一个桶的均值。桶均值会把一台刚冲到
//     95% 的机器摊平成 60%，而这一页存在的意义就是看现在。
//  3. **不画假的平线**。没有采样的时间段不返回空桶，前端据此把折线断开；
//     一条网关都没上报时回真空态，由页面显示「无数据面上报」。

import (
	"log/slog"
	"net/http"
	"time"

	"baidi.dev/control/internal/config"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// metricRange 一个时间窗档位：窗口长度 + 降采样桶宽。
//
// 桶宽是按「一屏画多少个点」倒推的（60 / 96 / 168 个点）：点太密时 SVG 折线
// 每像素挤好几个点，既看不出趋势又白传数据；点太稀则短促的尖峰被抹平。
type metricRange struct {
	window time.Duration
	bucket int64 // 秒
	label  string
}

// metricRanges 支持的时间窗档位（PRD FR-MON-02 要求按小时/天/周切换）。
var metricRanges = map[string]metricRange{
	"hour": {window: time.Hour, bucket: 60, label: "最近 1 小时"},
	"day":  {window: 24 * time.Hour, bucket: 900, label: "最近 24 小时"},
	"week": {window: 7 * 24 * time.Hour, bucket: 3600, label: "最近 7 天"},
}

// SetMetricsRetentionHours 注入设备状态时序的留存小时数。
//
// 调用点只有 main：把清理循环真正消费的那一份原样传进来。读端点用它把时间窗
// 截断到「库里真有数据的那一段」——「周」档默认覆盖 168 小时，而留存只有 72 小时，
// 不截断的话页面会承诺一段其实早被删掉的历史，用户只会看到左边一大片空白，
// 并合理地怀疑是采集坏了。0 表示未注入（测试栈），此时不截断。
func (s *Server) SetMetricsRetentionHours(h int) { s.metricsRetentionHours = h }

// metricsRetention 返回生效的留存小时数；未注入时按默认值答，绝不答 0
// （答 0 会让下面的截断把窗口压成空，页面上表现为「永远没有数据」）。
func (s *Server) metricsRetention() int {
	if s.metricsRetentionHours <= 0 {
		return config.DefaultMetricsRetentionHours
	}
	return s.metricsRetentionHours
}

// handleDeviceStat GET /api/v1/monitor/device-stat?range=hour|day|week
//
// 权限：requireAdmin（角色现算）。与监控中心的 /online、/userstate 同门槛——
// 这一页是只读观测，内容是网关宿主机的水位，既不含策略也不含审计正文；
// 三权中任一权的管理员在排障时都需要看它，收成 PermSystem 会让安全管理员
// 在处理「用户连不上」时看不到「网关磁盘满了」这条最可能的原因。
// 写侧（谁能往里写数据）另有一道更硬的闸：只有 mTLS 客户端证书能调注册心跳。
func (s *Server) handleDeviceStat(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	key := r.URL.Query().Get("range")
	if key == "" {
		key = "hour"
	}
	rg, ok := metricRanges[key]
	if !ok {
		// 明确拒绝而不是静默回落到 hour：一个拼错的 range 静默换成别的时间窗，
		// 会让人对着「最近 1 小时」的图讨论「上周的那次抖动」。
		httpx.Error(w, http.StatusBadRequest, "range 只能是 hour / day / week，本次为 "+key)
		return
	}
	now := time.Now()
	until := now.Unix() + 1 // 半开区间 [since, until)：+1 才把「此刻这一秒」的点算进来
	since := now.Add(-rg.window).Unix()
	retention := s.metricsRetention()
	truncated := false
	if cut := now.Add(-time.Duration(retention) * time.Hour).Unix(); cut > since {
		since = cut
		truncated = true // 前端据此如实说明「更早的数据已按留存策略清理」
	}

	series, err := s.store.GatewayMetrics(r.Context(), store.MetricsQuery{
		Since: since, Until: until, BucketSec: rg.bucket,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load gateway metrics")
		return
	}

	// 在线但从未上报指标的网关要单列出来：它与「一台网关都没有」是两种不同的处境，
	// 下一步动作也不同（前者去升级网关版本，后者去看数据面为什么没连上）。
	// 空态如实呈现，不给任何一台网关补零点画平线。
	reported := make(map[string]bool, len(series))
	for _, sr := range series {
		reported[sr.GatewayID] = true
	}
	windowSec := int64(gatewayOnlineWindow / time.Second)
	silent := []string{}
	online := 0
	s.mu.Lock()
	for id, gw := range s.gateways {
		if now.Unix()-gw.LastSeen > windowSec {
			continue
		}
		online++
		if !reported[id] {
			silent = append(silent, id)
		}
	}
	s.mu.Unlock()

	httpx.JSON(w, http.StatusOK, map[string]any{
		"range":          key,
		"rangeLabel":     rg.label,
		"since":          since,
		"until":          until,
		"bucketSec":      rg.bucket,
		"retentionHours": retention,
		"truncated":      truncated,
		"onlineGateways": online,
		"silentGateways": silent,
		"gateways":       series,
		"generatedAt":    now.Format(time.RFC3339),
	})
}

// gwMetrics 网关随心跳上报的宿主机指标（与 gateway/internal/sysstat.Sample 同构）。
//
// 全部字段用指针：**缺字段与 0 必须可区分**。旧网关整个 metrics 字段都不发，
// 新网关只发采到的那几项——两种缺席都解成 nil，落库即 NULL。
// 用 float64 的话，「没报 CPU」会被 JSON 解成 0，一路存成「CPU 0%」。
type gwMetrics struct {
	CPU   *float64 `json:"cpu"`
	Mem   *float64 `json:"mem"`
	Disk  *float64 `json:"disk"`
	Load  *float64 `json:"load"`
	RxBps *float64 `json:"rxBps"`
	TxBps *float64 `json:"txBps"`
}

// recordGatewayMetrics 把一次心跳带来的设备状态落库。
//
// 时间戳用**控制面收到的时刻**而不是网关自报的时刻：网关时钟偏几分钟就足以把
// 采样点撒到时间轴的别处（甚至撒到未来），趋势图上表现为莫名的空洞与重叠，
// 而两侧日志都不会说任何话。这与回执审计「以控制面落库时间为准」是同一条口径。
//
// 落库失败只记日志、不让心跳失败：指标是观测通道，把一台正常网关因为一次写库
// 抖动判成离线，代价远大于丢一个采样点（与回执队列「尽力而为」同一取舍）。
func (s *Server) recordGatewayMetrics(r *http.Request, gwID string, m *gwMetrics) {
	if m == nil || gwID == "" {
		return
	}
	p := store.GatewayMetricPoint{
		GatewayID: gwID, TS: time.Now().Unix(),
		CPU:   sanePct(m.CPU),
		Mem:   sanePct(m.Mem),
		Disk:  sanePct(m.Disk),
		Load:  saneNonNeg(m.Load),
		RxBps: saneNonNeg(m.RxBps),
		TxBps: saneNonNeg(m.TxBps),
	}
	if err := s.writer.AppendGatewayMetric(r.Context(), p); err != nil {
		slog.Warn("设备状态采样落库失败（不影响本次心跳）", "gw", gwID, "err", err.Error())
	}
}

// sanePct 校验一个百分比指标：越界或非有限值一律降级为**不可判定**（nil）。
//
// ★降级而不是夹取：0-100 之外的数不是"稍微偏了"，而是这台网关报了一个不可信的值
// （证书失陷的网关可以随便报 1e9 把趋势图整体压平，让真实的尖峰肉眼不可见）。
// 采集器自己已经夹过一次，能到这里的越界值只可能是伪造或协议错位，按不可判定处理最诚实。
func sanePct(v *float64) *float64 {
	if v == nil || *v < 0 || *v > 100 || *v != *v { // v!=v 挡 NaN
		return nil
	}
	return v
}

// saneNonNeg 校验非负指标（负载、吞吐）：负数或 NaN 视为不可判定。
// 上界不设死——负载和吞吐没有自然上限，夹一个拍脑袋的上界反而会把真实的过载抹掉。
func saneNonNeg(v *float64) *float64 {
	if v == nil || *v < 0 || *v != *v {
		return nil
	}
	return v
}
