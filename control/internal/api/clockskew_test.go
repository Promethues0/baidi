package api

// 控制面与网关时钟一致性：注册心跳里的 now → 偏差三态（上报/未上报）→ 网关页与 /diag。
//
// ★为什么钉三态：敲门令牌是控制面签、网关验的，两侧时钟漂过 knockTTL 时敲门全灭
// 且三处日志都不指向时钟。这里最要防的错法是把「未上报」塌缩成 0——那会让一台
// 从不上报时钟的旧网关永远显示"时钟一致"，恰是它最需要被看见的时候。

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestClockSkewFromHeartbeat(t *testing.T) {
	h, _ := gwReceiptServer(t)

	// 网关自报一个比控制面快 40s 的钟。
	fast := time.Now().Unix() + 40
	body := fmt.Sprintf(`{"id":"gw-skew","proxy":":18443","spa":":18201","now":%d}`, fast)
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(), body); w.Code != http.StatusOK {
		t.Fatalf("注册返回 %d：%s", w.Code, w.Body.String())
	}
	// 旧网关：连 now 字段都不发。
	if w := postJSONWithToken(h, "/api/v1/gateways/register", gwSelfSignedToken(),
		`{"id":"gw-legacy","proxy":":18444","spa":":18202"}`); w.Code != http.StatusOK {
		t.Fatalf("旧网关注册返回 %d：%s", w.Code, w.Body.String())
	}

	code, out := doJSON(t, h, "GET", "/api/v1/gateway", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读网关页 http %d：%v", code, out)
	}
	nodes, _ := out["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("应两台，实得 %v", nodes)
	}
	byID := map[string]map[string]any{}
	for _, raw := range nodes {
		n := mapOf(t, raw)
		byID[n["id"].(string)] = n
	}
	// 上报者：skewSec ≈ +40（注册与读页之间隔了不到 1s，容差 ±2）。
	v, ok := byID["gw-skew"]["skewSec"].(float64)
	if !ok {
		t.Fatalf("上报时钟的网关应有数值 skewSec，实得 %v", byID["gw-skew"]["skewSec"])
	}
	if v < 38 || v > 42 {
		t.Errorf("skewSec 应约为 +40，实得 %v", v)
	}
	// ★旧网关：必须是 null（不可判定），绝不能是 0。
	if got := byID["gw-legacy"]["skewSec"]; got != nil {
		t.Fatalf("未上报时钟的网关 skewSec 必须为 null（不可判定 ≠ 0），实得 %v", got)
	}

	// /diag 的时钟检查：40s 超过 warn 档（>10s）但未达 knockTTL（90s）→ 整项 warn，
	// 且旧网关那行要如实写"未上报"。
	code, diag := doJSON(t, h, "GET", "/api/v1/diag", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("diag http %d", code)
	}
	var clock map[string]any
	for _, raw := range diag["checks"].([]any) {
		c := mapOf(t, raw)
		if c["key"] == "clock" {
			clock = c
			break
		}
	}
	if clock == nil {
		t.Fatal("/diag 里应有 key=clock 的时钟一致性检查")
	}
	if clock["status"] != "warn" {
		t.Errorf("40s 偏差 + 一台未上报应判 warn，实得 %v（%v）", clock["status"], clock["summary"])
	}
	items, _ := clock["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("两台在线网关都该有明细行，实得 %v", items)
	}
}

// 无在线网关时：时钟检查必须 skip（不参与健康分），而不是编一个"pass"。
func TestClockSkewSkipsWithoutGateways(t *testing.T) {
	h := newTestServer(t)
	code, diag := doJSON(t, h, "GET", "/api/v1/diag", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("diag http %d", code)
	}
	for _, raw := range diag["checks"].([]any) {
		c := mapOf(t, raw)
		if c["key"] == "clock" {
			if c["status"] != "skip" {
				t.Fatalf("无网关时时钟检查应 skip，实得 %v", c["status"])
			}
			return
		}
	}
	t.Fatal("缺 clock 检查")
}
