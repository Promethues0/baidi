package api

// 告警阈值越界的 HTTP 出口回归。
//
// 后端拒绝只做对了一半是不够的：错误落进 handleSaveAlertRule 那个 `switch err` 的
// default 分支就会变成 500「failed to save alert rule」，控制台经 failReason 转述出来
// 是一句与真实原因无关的话，管理员照着去查后端连接，而实际原因是他把某个阈值框清空了。
// 这条用例钉住「400 + 后端原话」。

import (
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

func TestSaveAlertRuleRejectsOutOfRangeThreshold(t *testing.T) {
	e := newAlertEnv(t)

	// 「网关离线」的心跳超时被清空 → 前端改造前会提交 0，落库后每台在线网关每轮都判离线。
	code, out := doJSON(t, e.h, "POST", "/api/v1/alerts/rules", adminToken(), map[string]any{
		"id": "ar-gateway-offline", "kind": store.AlertKindGatewayOffline, "name": "网关心跳超时离线",
		"enabled": true, "threshold": map[string]float64{store.ThreshOfflineSec: 0}, "cooldownSec": 600,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("越界阈值应回 400（落进 500 的话控制台会把它转述成「后端连接」类问题），得到 %d：%v", code, out)
	}
	errObj, _ := out["error"].(map[string]any)
	reason, _ := errObj["message"].(string)
	if !strings.Contains(reason, "心跳超时") {
		t.Fatalf("400 正文必须点名是页面上哪一栏、后果是什么，实得 %q", reason)
	}

	// 拒绝必须是**真没落库**：回了 400 却已经写进去，比放行更难查。
	_, list := doJSON(t, e.h, "GET", "/api/v1/alerts/rules", adminToken(), nil)
	for _, raw := range list["rules"].([]any) {
		r := raw.(map[string]any)
		if r["id"] != "ar-gateway-offline" {
			continue
		}
		th, _ := r["threshold"].(map[string]any)
		if v, _ := th[store.ThreshOfflineSec].(float64); v == 0 {
			t.Fatal("被 400 拒掉的阈值不该留在库里")
		}
	}
}
