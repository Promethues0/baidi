package api

import (
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── client_version 假绿：端到端 ──
//
// risk 包里那组用例证明的是**纯函数判得对**；这一组证明的是**它真的被接进了上报链路**，
// 且判定结果**写回了存下来的报告**。两者缺一不可——wave8 行动 1 的对抗式复核刚教过一次：
// 只测纯函数时，把 handler 里那行接线删掉，纯函数用例照样全绿。
//
// 背景：采集器此前对这一项写死 Pass，于是终端合规页对跑三个版本以前客户端的机器也亮绿，
// 而管理员看那一栏的目的恰恰是找出老客户端。

// postureBody 一份**六项齐全**的终端上报：除 client_version 外全部合规。
//
// ★必须齐全。少报任何一项，风险引擎按「缺失即不合规」把它判成失败（防选择性上报的
// 既有设计），种子接入准入基线就会抬到 block——于是无论 client_version 判成什么，
// 结论都是 block，这一族用例也就什么都证不了了。
// clientVersion 是权威来源；checks 里那一项按新采集器的形态报 unknown（本地判不了目标版本）。
func postureBody(device, clientVersion string) map[string]any {
	checks := []map[string]any{
		{"key": "disk_encrypted", "label": "磁盘已加密", "ok": true, "value": "on"},
		{"key": "sys_integrity", "label": "系统完整性保护开启", "ok": true, "value": "enabled"},
		{"key": "firewall_on", "label": "系统防火墙启用", "ok": true, "value": "on"},
		{"key": "os_version", "label": "系统版本合规", "ok": true, "value": "14.5"},
		{"key": "edr_online", "label": "EDR 终端防护在线", "ok": true, "value": "running"},
		{"key": store.CheckKeyClientVersion, "label": "客户端版本合规", "ok": false, "unknown": true, "value": clientVersion},
	}
	return map[string]any{
		"device": device, "platform": "macOS", "os": "macOS 14.5", "clientVersion": clientVersion,
		"checks": checks,
	}
}

// setStable 经真实端点配一条该平台的稳定版（client_version 的判据来源之一）。
//
// ★必须同时给一个更高的灰度版本。`SaveGrayPlan` 对 `Version==""` 的计划是**整条丢弃**的
// （那是「置空版本即撤销灰度」的语义），只发 stable 的话计划根本不落库，
// 而失败是静默的——接口照回 200。这条注释就是那次踩坑的记号。
func setStable(t *testing.T, h http.Handler, platform, stable, grayVersion string) {
	t.Helper()
	code, out := doJSON(t, h, "PUT", "/api/v1/upgrade/gray", adminToken(),
		map[string]any{"platform": platform, "stable": stable, "version": grayVersion, "percent": 0,
			"accounts": []string{}, "groups": []string{}})
	if code != http.StatusOK {
		t.Fatalf("配置稳定版 http %d: %v", code, out)
	}
	// 真读回来确认它在库里——上面那条 200 只说明请求合法，不说明计划留下了。
	code, out = doJSON(t, h, "GET", "/api/v1/upgrade", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("读升级视图 http %d", code)
	}
	arr, _ := out["gray"].([]any)
	for _, it := range arr {
		if m, _ := it.(map[string]any); asStr(m["platform"]) == platform && asStr(m["stable"]) == stable {
			return
		}
	}
	t.Fatalf("稳定版没落库（SaveGrayPlan 丢弃了这条计划？）：%v", out["gray"])
}

// storedCheck 管理端读回该设备最新报告里的某一项（页面渲染的就是这一份）。
func storedCheck(t *testing.T, h http.Handler, device, key string) map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/posture", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /posture http %d", code)
	}
	rows, _ := out["reports"].([]any)
	for _, it := range rows {
		row, _ := it.(map[string]any)
		if asStr(row["device"]) != device {
			continue
		}
		cs, _ := row["checks"].([]any)
		for _, ci := range cs {
			c, _ := ci.(map[string]any)
			if asStr(c["key"]) == key {
				return c
			}
		}
	}
	t.Fatalf("读不到设备 %s 的 %s 检查项", device, key)
	return nil
}

// ★核心：终端跑着旧版本 → 落库的那一格必须是不合规，页面据此才能找出老客户端。
func TestPostureReport_旧客户端版本判不合规且写回报告(t *testing.T) {
	h := newTestServer(t)
	setStable(t, h, "macos", "0.3.0", "0.4.0")

	code, out := doJSON(t, h, "POST", "/api/v1/posture", userToken("li.fang"), postureBody("MAC-OLD", "0.1.0"))
	if code != http.StatusOK {
		t.Fatalf("上报 http %d: %v", code, out)
	}
	// 种子「终端健康基线」含 client_version（severity=low，处置 degrade）→ 该项失败即抬到 degrade
	if v := asStr(out["verdict"]); v != store.DisposalDegrade {
		t.Fatalf("旧客户端应命中终端健康基线并抬到 degrade，实得 %q（reasons=%v）", v, out["reasons"])
	}
	reasons := strings.Join(strSlice(out["reasons"]), "、")
	if !strings.Contains(reasons, "客户端版本") {
		t.Fatalf("判定理由里应点名客户端版本，实得 %q", reasons)
	}

	// ★写回：页面渲染的是存下来的那份 checks，不写回的话页面仍照客户端那份画——
	// 判定说不合规、页面画着「无法判定」，两边说不同的话。
	c := storedCheck(t, h, "MAC-OLD", store.CheckKeyClientVersion)
	if c["ok"] == true || c["unknown"] == true {
		t.Fatalf("落库的 client_version 应是「确定的不合规」，实得 %v", c)
	}
	if v := asStr(c["value"]); !strings.Contains(v, "0.3.0") {
		t.Fatalf("展示值应点名要求的版本（管理员要知道该升到哪），实得 %q", v)
	}
}

// 终端已达稳定版 → 合规，且不抬处置。
func TestPostureReport_新客户端版本判合规(t *testing.T) {
	h := newTestServer(t)
	setStable(t, h, "macos", "0.3.0", "0.4.0")

	code, out := doJSON(t, h, "POST", "/api/v1/posture", userToken("li.fang"), postureBody("MAC-NEW", "0.3.0"))
	if code != http.StatusOK {
		t.Fatalf("上报 http %d: %v", code, out)
	}
	if v := asStr(out["verdict"]); v != store.DisposalAllow {
		t.Fatalf("已达稳定版不该抬处置，实得 %q（reasons=%v）", v, out["reasons"])
	}
	c := storedCheck(t, h, "MAC-NEW", store.CheckKeyClientVersion)
	if c["ok"] != true {
		t.Fatalf("落库的 client_version 应为合规，实得 %v", c)
	}
}

// ★该平台还没配稳定版时：一律「无法判定」，**绝不回落成合规**。
// 这是本次改造的要害——旧行为正是在这种情况下也亮绿。
func TestPostureReport_没配稳定版则无法判定而非假绿(t *testing.T) {
	h := newTestServer(t)
	// 刻意不配任何灰度计划

	code, out := doJSON(t, h, "POST", "/api/v1/posture", userToken("li.fang"), postureBody("MAC-NOPLAN", "0.1.0"))
	if code != http.StatusOK {
		t.Fatalf("上报 http %d: %v", code, out)
	}
	c := storedCheck(t, h, "MAC-NOPLAN", store.CheckKeyClientVersion)
	if c["ok"] == true {
		t.Fatal("没有目标版本时判成「合规」= 假绿，正是本次要消灭的形态")
	}
	if c["unknown"] != true {
		t.Fatalf("应如实标「无法判定」，实得 %v", c)
	}
	if v := asStr(c["value"]); !strings.Contains(v, "无法判定") {
		t.Fatalf("展示值应说清为什么判不了，实得 %q", v)
	}
	// observe 下不可判定不计分不抬处置，但必须单列出来让人看见
	if v := asStr(out["verdict"]); v != store.DisposalAllow {
		t.Fatalf("observe 下不可判定不该抬处置，实得 %q", v)
	}
	if len(strSlice(out["unknowns"])) == 0 {
		t.Fatal("「无法判定」必须回传给终端——不计分不等于可以不说")
	}
}

// 终端自称合规也压不过控制面判定：判据在控制面，就不能让终端自报的那一格漏出来。
func TestPostureReport_客户端自称合规也压不过控制面(t *testing.T) {
	h := newTestServer(t)
	setStable(t, h, "macos", "0.3.0", "0.4.0")

	body := postureBody("MAC-LIAR", "0.1.0")
	// 模拟旧采集器（或被改过的客户端）：这一项自称通过
	cs, _ := body["checks"].([]map[string]any)
	for i := range cs {
		if cs[i]["key"] == store.CheckKeyClientVersion {
			cs[i]["ok"], cs[i]["unknown"], cs[i]["label"] = true, false, "客户端为最新版本"
		}
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/posture", userToken("li.fang"), body); code != http.StatusOK {
		t.Fatalf("上报 http %d: %v", code, out)
	}
	c := storedCheck(t, h, "MAC-LIAR", store.CheckKeyClientVersion)
	if c["ok"] == true {
		t.Fatal("终端报 ok=true 就被采信 = 判据又回到了客户端手里")
	}
}
