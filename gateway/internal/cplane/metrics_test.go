package cplane

// 设备状态随心跳上报的 JSON 契约测试（网关侧的一半，控制面侧那一半在
// control/internal/api/metrics_test.go）。三条要钉住的语义：
//
//	① 没装采样源 → 报文里连 metrics 键都没有（旧网关行为逐字节不变）；
//	② 装了采样源但一项都没采到 → metrics 是 {}，与 ① 可区分；
//	③ 采到的单项才出现，采不到的单项**不出现**（而不是 0）。

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"baidi.dev/gateway/internal/sysstat"
)

// registerBody 打一次 Register 并把控制面收到的原始报文解成 map。
func registerBody(t *testing.T, setup func(*Client)) map[string]any {
	t.Helper()
	var raw []byte
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		io.WriteString(w, `{"ok":true}`)
	})
	if setup != nil {
		setup(c)
	}
	if err := c.Register(1, 2, 60, nil); err != nil {
		t.Fatalf("注册失败：%v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("报文不是合法 JSON：%v（%s）", err, raw)
	}
	return out
}

// ① 未装采样源：旧行为——报文里没有 metrics 字段。
// 反过来说，新控制面看到「有心跳但从来没有 metrics」就知道这是台旧网关，
// 可以如实提示「网关版本过旧、未上报设备指标」，而不是画一条零线。
func TestRegisterOmitsMetricsWhenNoSource(t *testing.T) {
	body := registerBody(t, nil)
	if _, ok := body["metrics"]; ok {
		t.Errorf("未装采样源时不该出现 metrics 字段，实际：%v", body["metrics"])
	}
	// 既有字段一个都不能少（本改动对旧契约必须零影响）
	for _, k := range []string{"id", "clients", "tunnels", "uptime", "version", "events"} {
		if _, ok := body[k]; !ok {
			t.Errorf("既有字段 %s 丢失", k)
		}
	}
}

// ② 装了采样源但全不可判定：metrics 出现且为空对象。
// 这与 ① 必须可区分——「不会报」和「报了但采不到」的运维动作完全不同：
// 前者去升级网关，后者去看这台机器为什么读不到 /proc。
func TestRegisterCarriesEmptyMetricsWhenAllUnknown(t *testing.T) {
	body := registerBody(t, func(c *Client) {
		c.SetMetrics(func() sysstat.Sample { return sysstat.Sample{} })
	})
	m, ok := body["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("metrics 应为对象，实际 %T：%v", body["metrics"], body["metrics"])
	}
	if len(m) != 0 {
		t.Errorf("全不可判定时 metrics 应为空对象（各项缺席而非补 0），实际：%v", m)
	}
}

// ③ 部分可采：采到的出现、采不到的缺席。
func TestRegisterCarriesOnlyKnownMetrics(t *testing.T) {
	cpu, disk := 42.5, 71.0
	body := registerBody(t, func(c *Client) {
		c.SetMetrics(func() sysstat.Sample {
			return sysstat.Sample{CPU: &cpu, Disk: &disk} // 内存/负载/吞吐不可判定
		})
	})
	m, ok := body["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("metrics 应为对象，实际：%v", body["metrics"])
	}
	if m["cpu"] != 42.5 || m["disk"] != 71.0 {
		t.Errorf("已采到的项应原样上报，实际：%v", m)
	}
	for _, k := range []string{"mem", "load", "rxBps", "txBps"} {
		if v, ok := m[k]; ok {
			t.Errorf("不可判定的 %s 不该出现在报文里（出现即等于上报 %v，会被读成真实值）", k, v)
		}
	}
}

// 采样源每次心跳恰好被调一次：调 0 次则速率的分母失真，调多次则 CPU 差分被吃掉。
func TestMetricsSourceCalledOncePerHeartbeat(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"ok":true}`)
	})
	c.SetMetrics(func() sysstat.Sample { calls++; return sysstat.Sample{} })
	for i := 0; i < 3; i++ {
		if err := c.Register(0, 0, int64(i), nil); err != nil {
			t.Fatalf("第 %d 次注册失败：%v", i, err)
		}
	}
	if calls != 3 {
		t.Errorf("采样调用 %d 次，期望与心跳次数一致（3）", calls)
	}
}
