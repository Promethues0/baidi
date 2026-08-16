package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── 安全基线检测项 key 白名单 ──
//
// 采集器不上报的 key，风险引擎按「缺失即不合规」判该项失败（那是防选择性上报的正确设计），
// 于是这条基线对该平台**全体终端**永远违规——而接入准入基线的默认处置是 block，
// 等于一键给所有人拒发敲门令牌 + 撤窗断隧道，保存那一刻零报错。
// 此前控制台的「添加检测项」按钮 100% 产出这种 key（写死 'c-' + 时间戳）。
//
// 注意这道闸与紧邻的 platforms 校验方向**相反**：platforms 拼错是永不生效（fail-open），
// key 拼错是全员 fail-closed，所以更不能只靠页面自觉。

func baselineBody(checks []map[string]any) map[string]any {
	return map[string]any{
		"id": "bl-t", "name": "测试基线", "type": "onboarding", "scope": "全体",
		"disposal": store.DisposalBlock, "status": "enabled",
		"platforms": []string{"macOS"}, "checks": checks,
	}
}

func TestSaveBaseline_拒收采集器不上报的检测项key(t *testing.T) {
	h := newTestServer(t)
	// 复刻旧版「添加检测项」按钮产出的那种 key
	code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(),
		baselineBody([]map[string]any{
			{"key": "c-1786880000000", "label": "新检测项", "platform": "All", "expect": "待配置", "severity": "medium"},
		}))
	if code != http.StatusBadRequest {
		t.Fatalf("采集器不上报的 key 必须入口拒绝（否则该平台全体终端立刻判违规 + block），实得 http %d: %v", code, out)
	}
	msg := errMsg(out)
	// 错误必须**可执行**：告诉管理员能填什么，否则他只会换个名字再试一次。
	for _, k := range store.CollectableCheckKeys() {
		if !strings.Contains(msg, k) {
			t.Fatalf("400 文案应列出全部合法 key（缺 %q）：%s", k, msg)
		}
	}
}

func TestSaveBaseline_收下采集器真会上报的key(t *testing.T) {
	h := newTestServer(t)
	for _, spec := range store.CollectableChecks() {
		code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(),
			baselineBody([]map[string]any{
				{"key": spec.Key, "label": spec.Label, "platform": "All", "expect": spec.Expect, "severity": "medium"},
			}))
		if code != http.StatusOK {
			t.Fatalf("目录里的 key %q 应被接受，实得 http %d: %v", spec.Key, code, out)
		}
	}
}

func TestSaveBaseline_拒收重复的检测项key(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adminToken(),
		baselineBody([]map[string]any{
			{"key": "disk_encrypted", "label": "磁盘已加密", "platform": "All", "expect": "on", "severity": "high"},
			{"key": "disk_encrypted", "label": "磁盘已加密（重复）", "platform": "All", "expect": "on", "severity": "low"},
		}))
	if code != http.StatusBadRequest {
		t.Fatalf("同一 key 配两遍应拒绝（会重复计分且页面上是两行一样的项），实得 http %d: %v", code, out)
	}
}

// 目录必须随 /security 一起下发——页面下拉与入口校验读同一份，
// 前端自己抄一份的话，加采集项时页面上永远选不到新项。
func TestSecurityBundle_下发采集项目录(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "GET", "/api/v1/security", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /security http %d", code)
	}
	arr, _ := out["checkCatalog"].([]any)
	if len(arr) != len(store.CollectableChecks()) {
		t.Fatalf("checkCatalog 应含 %d 项，实得 %d：%v", len(store.CollectableChecks()), len(arr), out["checkCatalog"])
	}
	got := map[string]bool{}
	for _, it := range arr {
		m, _ := it.(map[string]any)
		if asStr(m["key"]) == "" || asStr(m["label"]) == "" {
			t.Fatalf("目录项缺 key/label：%v", m)
		}
		got[asStr(m["key"])] = true
	}
	for _, k := range store.CollectableCheckKeys() {
		if !got[k] {
			t.Fatalf("目录里缺 %q", k)
		}
	}
	if _, ok := out["baselines"]; !ok {
		t.Fatal("加了 checkCatalog 不能把 baselines 挤掉——那会让整页空白")
	}
}

// ★种子基线里的每一个 key 都必须在目录里。
// 少了这条断言，「改了采集器却忘了改种子」会让全新库首启就带着一条对所有人判违规的基线，
// 而它的处置档是 block——第一个登录的人就被拒发敲门令牌。
func TestSeedBaselines_检测项key全部在采集目录内(t *testing.T) {
	bls, err := (&store.Memory{}).Baselines(context.Background())
	if err != nil {
		t.Fatalf("Baselines: %v", err)
	}
	n := 0
	for _, b := range bls {
		for _, c := range b.Checks {
			n++
			if _, ok := store.CheckSpecOf(c.Key); !ok {
				t.Fatalf("种子基线「%s」用了采集器不上报的 key %q——全新库首启即对全平台终端判违规（该基线处置=%s）",
					b.Name, c.Key, b.Disposal)
			}
		}
	}
	if n == 0 {
		t.Fatal("种子基线一个检测项都没有，本用例失去意义")
	}
}
