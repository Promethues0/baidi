package api

// 设备状态接口测试：心跳上报的双向兼容、三态穿透、时间窗档位、留存截断、
// 空态与「在线但不上报」的区分、以及读端点的权限门槛。

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// deviceStatServer 构造走明文口（compat=true）的控制面 + 交出 store（直接断言落库）。
func deviceStatServer(t *testing.T) (http.Handler, *Server, *store.SQLiteStore) {
	t.Helper()
	st := openTestSQLite(t)
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), s, st
}

// deviceStat 拉一次设备状态页数据。
func deviceStat(t *testing.T, h http.Handler, rangeKey, token string) (int, map[string]any) {
	t.Helper()
	path := "/api/v1/monitor/device-stat"
	if rangeKey != "" {
		path += "?range=" + rangeKey
	}
	return doJSON(t, h, "GET", path, token, nil)
}

// ── 双向兼容：旧网关不带 metrics ──
//
// 旧版本网关的心跳里根本没有 metrics 字段。控制面必须照常注册成功、
// 且**不落任何采样点**——补一条全 0 的点会让这台网关在页面上显示成
// 「CPU 0%、内存 0%」的健康机器，而它其实什么都没报。
func TestGatewayRegisterWithoutMetricsIsAccepted(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	body := `{"id":"gw-old","proxy":":18443","spa":":18201","clients":1,"tunnels":0,"uptime":30}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("旧网关注册应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	code, out := deviceStat(t, h, "hour", adminToken())
	if code != http.StatusOK {
		t.Fatalf("设备状态 http %d", code)
	}
	gws, _ := out["gateways"].([]any)
	if len(gws) != 0 {
		t.Errorf("不上报指标的网关不该出现在时序里（补零会让它看起来很健康），实际：%v", gws)
	}
	// 但它在线：必须被单列成「在线却没上报指标」，而不是从页面上消失
	silent, _ := out["silentGateways"].([]any)
	if len(silent) != 1 || silent[0] != "gw-old" {
		t.Errorf("在线但不上报指标的网关应单列出来（提示升级网关），实际 %v", silent)
	}
}

// ── 双向兼容：新网关带 metrics，且部分项不可判定 ──
func TestGatewayRegisterPersistsMetricsAndKeepsUnknown(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	// cpu/mem/disk 有值，load/rxBps/txBps 缺席（网关采不到 → 报文里不出现）
	body := `{"id":"gw-1","proxy":":18443","spa":":18201",
		"metrics":{"cpu":42.5,"mem":63.25,"disk":71}}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}
	code, out := deviceStat(t, h, "hour", adminToken())
	if code != http.StatusOK {
		t.Fatalf("设备状态 http %d：%v", code, out)
	}
	latest := firstLatest(t, out)
	if latest["cpu"] != 42.5 || latest["mem"] != 63.25 || latest["disk"] != float64(71) {
		t.Errorf("已采到的项应原样落库并回显，实际：%v", latest)
	}
	// ★不可判定必须是 null，不是 0
	for _, k := range []string{"load", "rxBps", "txBps"} {
		if v, ok := latest[k]; !ok || v != nil {
			t.Errorf("采不到的 %s 应回 null（不可判定），实际 %v——0 会被读成"+
				"「负载 0 / 无流量」这种看起来完全正常的假象", k, v)
		}
	}
}

// 网关上报了 metrics 但一项都没采到（比如 windows 网关，或首次心跳）：
// 仍要落一条**全 NULL** 的采样点。这条点本身是有信息量的——它证明
// 「这台网关在报，只是采不到」，与「这台网关根本不报」是两码事。
func TestGatewayRegisterEmptyMetricsStillRecordsPoint(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	body := `{"id":"gw-blind","metrics":{}}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d", w.Code)
	}
	_, out := deviceStat(t, h, "hour", adminToken())
	gws, _ := out["gateways"].([]any)
	if len(gws) != 1 {
		t.Fatalf("上报了 metrics 的网关应出现在时序里（哪怕全不可判定），实际 %v", gws)
	}
	latest := firstLatest(t, out)
	for _, k := range []string{"cpu", "mem", "disk", "load", "rxBps", "txBps"} {
		if latest[k] != nil {
			t.Errorf("全不可判定时 %s 应为 null，实际 %v", k, latest[k])
		}
	}
	silent, _ := out["silentGateways"].([]any)
	if len(silent) != 0 {
		t.Errorf("已上报（哪怕全不可判定）的网关不该算「未上报」，实际 %v", silent)
	}
}

// 伪造/越界的指标降级成不可判定，而不是原样入库。
// 一张失陷的网关证书报 cpu=1e9，会把整张趋势图压平，真实尖峰肉眼不可见。
func TestGatewayRegisterRejectsInsaneMetricValues(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	body := `{"id":"gw-bad","metrics":{"cpu":1000000000,"mem":-5,"disk":100.0001,"load":-1,"rxBps":-3}}`
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d", w.Code)
	}
	_, out := deviceStat(t, h, "hour", adminToken())
	latest := firstLatest(t, out)
	for _, k := range []string{"cpu", "mem", "disk", "load", "rxBps"} {
		if latest[k] != nil {
			t.Errorf("越界的 %s 应降级为不可判定，实际 %v", k, latest[k])
		}
	}
}

// 时间窗档位：hour / day / week 各有自己的桶宽与窗口长度（PRD FR-MON-02）。
func TestDeviceStatRanges(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	s2 := map[string][2]int64{ // range → {窗口秒数, 桶宽}
		"hour": {3600, 60},
		"day":  {86400, 900},
		"week": {7 * 86400, 3600},
	}
	for key, want := range s2 {
		code, out := deviceStat(t, h, key, adminToken())
		if code != http.StatusOK {
			t.Fatalf("range=%s http %d", key, code)
		}
		if got := int64(out["bucketSec"].(float64)); got != want[1] {
			t.Errorf("range=%s 桶宽 %d，期望 %d", key, got, want[1])
		}
		span := int64(out["until"].(float64)) - int64(out["since"].(float64))
		// week 档会被 72h 留存截断，只校验未截断的两档的窗口长度
		if key != "week" && (span < want[0] || span > want[0]+5) {
			t.Errorf("range=%s 窗口 %ds，期望 ~%ds", key, span, want[0])
		}
	}
	// 缺省即 hour
	_, out := deviceStat(t, h, "", adminToken())
	if out["range"] != "hour" {
		t.Errorf("缺省 range 应为 hour，实际 %v", out["range"])
	}
}

// 拼错的 range 明确 400，而不是静默换成别的时间窗——
// 静默回落会让人对着「最近 1 小时」的图讨论「上周那次抖动」。
func TestDeviceStatRejectsUnknownRange(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	if code, _ := deviceStat(t, h, "month", adminToken()); code != http.StatusBadRequest {
		t.Fatalf("未知 range 应回 400，实际 %d", code)
	}
}

// 「周」档窗口被留存期截断，并如实标注 truncated——
// 不截断的话页面会承诺一段早被清理掉的历史，左边一片空白，看起来像采集坏了。
func TestDeviceStatTruncatesToRetention(t *testing.T) {
	h, s, _ := deviceStatServer(t)
	s.SetMetricsRetentionHours(6)
	_, out := deviceStat(t, h, "week", adminToken())
	span := int64(out["until"].(float64)) - int64(out["since"].(float64))
	if span > 6*3600+5 {
		t.Errorf("窗口 %ds 应被 6 小时留存截断", span)
	}
	if out["truncated"] != true {
		t.Errorf("被截断时应如实标注 truncated=true，实际 %v", out["truncated"])
	}
	if int(out["retentionHours"].(float64)) != 6 {
		t.Errorf("留存小时数应回显注入的那一份，实际 %v", out["retentionHours"])
	}
	// 未被截断的档位不该谎称截断
	_, out = deviceStat(t, h, "hour", adminToken())
	if out["truncated"] != false {
		t.Errorf("1 小时档在 6 小时留存下不该标 truncated，实际 %v", out["truncated"])
	}
}

// 空态：一台网关都没有 → 空序列 + 零在线 + 空 silent。
// 前端据此显示「无数据面上报」，绝不画平线。
func TestDeviceStatEmptyState(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	code, out := deviceStat(t, h, "hour", adminToken())
	if code != http.StatusOK {
		t.Fatalf("http %d", code)
	}
	if gws, _ := out["gateways"].([]any); len(gws) != 0 {
		t.Errorf("空态不该编造任何序列，实际 %v", gws)
	}
	if n := int(out["onlineGateways"].(float64)); n != 0 {
		t.Errorf("在线网关数应为 0，实际 %d", n)
	}
	if silent, _ := out["silentGateways"].([]any); len(silent) != 0 {
		t.Errorf("空态不该有静默网关，实际 %v", silent)
	}
}

// 趋势点确实经过降采样：一小时档 60s 桶，同一分钟内的多次心跳合成一个点。
func TestDeviceStatDownsamplesWithinBucket(t *testing.T) {
	h, _, st := deviceStatServer(t)
	now := time.Now().Unix()
	for i := 0; i < 4; i++ {
		if err := st.AppendGatewayMetric(t.Context(), store.GatewayMetricPoint{
			GatewayID: "gw-1", TS: now - int64(i), CPU: ptrF(float64(20 + i*10)),
		}); err != nil {
			t.Fatalf("落点失败：%v", err)
		}
	}
	_, out := deviceStat(t, h, "hour", adminToken())
	gws := out["gateways"].([]any)
	pts := gws[0].(map[string]any)["points"].([]any)
	if len(pts) > 2 { // 4 条相邻秒的点最多跨 2 个分钟桶
		t.Fatalf("同一分钟内的多条采样应合成一个桶，实际 %d 个点", len(pts))
	}
	total := 0
	for _, p := range pts {
		total += int(p.(map[string]any)["n"].(float64))
	}
	if total != 4 {
		t.Errorf("桶内原始点数合计 %d，期望 4", total)
	}
}

// 读端点门槛：非管理员一律 403（角色现算，不只看令牌里的 role）。
func TestDeviceStatRequiresAdmin(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	if code, _ := deviceStat(t, h, "hour", userToken("li.ming")); code != http.StatusForbidden {
		t.Errorf("普通用户应 403，实际 %d", code)
	}
	if code, _ := deviceStat(t, h, "hour", gatewayToken()); code != http.StatusForbidden {
		t.Errorf("网关身份应 403（它是写方，不是读方），实际 %d", code)
	}
	if code, _ := deviceStat(t, h, "hour", ""); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Errorf("匿名应被拒，实际 %d", code)
	}
}

// 三权分立下的三种管理员都能读这一页：排障时「网关磁盘满了」是安全管理员
// 处理「用户连不上」的第一嫌疑，把它收成系统权会让他看不到最可能的原因。
func TestDeviceStatVisibleToAllAdminPowers(t *testing.T) {
	h, _, _ := deviceStatServer(t)
	for _, roleKey := range []string{"system", "security", "audit"} {
		tok := makeAdmin(t, h, roleKey+".stat.admin", roleKey)
		if code, out := deviceStat(t, h, "hour", tok); code != http.StatusOK {
			t.Errorf("%s 权管理员应能读设备状态，实际 %d：%v", roleKey, code, out)
		}
	}
}

// firstLatest 取响应里第一台网关的 latest 对象。
func firstLatest(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	gws, _ := out["gateways"].([]any)
	if len(gws) == 0 {
		t.Fatalf("响应里没有任何网关序列：%v", out)
	}
	b, _ := json.Marshal(gws[0])
	var sr struct {
		Latest map[string]any `json:"latest"`
	}
	if err := json.Unmarshal(b, &sr); err != nil {
		t.Fatalf("解析序列失败：%v", err)
	}
	if sr.Latest == nil {
		t.Fatalf("序列缺 latest：%s", b)
	}
	return sr.Latest
}

func ptrF(v float64) *float64 { return &v }
