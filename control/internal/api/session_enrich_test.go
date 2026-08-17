package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── 在线用户页脱壳（wave8 行动 5）──
//
// 改造前 monitor_objects.go 对每条**真实**会话逐字段填死：
//   Org: "—", Location: "—", Device: "—", OS: "—", Trust: "trusted", Risk: "none"
// 后两个是**正向断言**，比补 0 更坏：observe 模式下被放行的未授信终端、
// 被 degrade 降权的账号，在监控中心这一页上全部显示成「授信 / 无风险」——
// 而管理员打开这一页的目的恰恰是找出它们。
//
// wave7 删掉的是「无网关时回退 10 条演示会话」那条种子路径，live 路径从未脱壳。

// onlineSessions 让一台网关带着会话心跳上来，然后读回 /online。
func onlineSessions(t *testing.T, f *isoFixture, accounts ...string) []map[string]any {
	t.Helper()
	sess := make([]map[string]any, 0, len(accounts))
	for i, a := range accounts {
		sess = append(sess, map[string]any{"ip": "10.1.0." + string(rune('1'+i)), "user": a, "role": "user", "since": 1786000000})
	}
	code, out := doJSON(t, f.h, "POST", "/api/v1/gateways/register", gatewayToken(),
		map[string]any{"id": "gw-1", "proxy": "10.0.0.1:18443", "spa": "10.0.0.1:18201",
			"version": "v0.5.0", "sessions": sess})
	if code != http.StatusOK {
		t.Fatalf("网关心跳 http %d: %v", code, out)
	}
	code, out = doJSON(t, f.h, "GET", "/api/v1/online", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /online http %d: %v", code, out)
	}
	arr, _ := out["sessions"].([]any)
	rows := make([]map[string]any, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			rows = append(rows, m)
		}
	}
	return rows
}

func sessionOf(t *testing.T, rows []map[string]any, account string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if asStr(r["account"]) == account {
			return r
		}
	}
	t.Fatalf("会话里没有 %s：%v", account, rows)
	return nil
}

// ★核心用例①：账号一台终端都没登记时，必须是 unknown 而不是 trusted。
// 这恰恰是 observe 准入模式下最常见的形态——他照样能敲门进来，而控制面对他的终端一无所知。
func TestOnlineSession_未登记终端判不可判定而非已授信(t *testing.T) {
	f := newIsoFixture(t)
	rows := onlineSessions(t, f, "li.fang")
	s := sessionOf(t, rows, "li.fang")
	if asStr(s["trust"]) != store.SessionTrustUnknown {
		t.Fatalf("一台终端都没登记应判 unknown，实得 %q——把未知说成「已授信」是正向断言，比补 0 更坏", s["trust"])
	}
	if asStr(s["risk"]) != store.SessionRiskUnknown {
		t.Fatalf("从未上报过终端环境应判 unknown，实得 %q", s["risk"])
	}
	// 结论必须带依据：只给一个灰标签，管理员没法判断该不该处置。
	for _, k := range []string{"trustNote", "riskNote"} {
		if asStr(s[k]) == "" {
			t.Fatalf("%s 不能为空——账号级结论必须说清依据", k)
		}
	}
}

// ★核心用例②：名下有被吊销的终端 → untrusted，且依据点名。
func TestOnlineSession_名下有吊销终端判未授信(t *testing.T) {
	f := newIsoFixture(t)
	ctx := context.Background()
	// 两台终端：一台授信、一台吊销
	for _, d := range []struct{ fp, status string }{{"fp-ok", store.DeviceStatusTrusted}, {"fp-bad", store.DeviceStatusRevoked}} {
		if _, _, err := f.st.EnrollDevice(ctx, "li.fang", d.fp, "dev-"+d.fp, "macOS", store.DeviceBindAuto); err != nil {
			t.Fatalf("EnrollDevice: %v", err)
		}
		dev, ok, err := f.st.DeviceByFingerprint(ctx, "li.fang", d.fp)
		if err != nil || !ok {
			t.Fatalf("DeviceByFingerprint: %v ok=%v", err, ok)
		}
		if _, _, err := f.st.SetDeviceStatus(ctx, dev.ID, d.status, "admin", "用例构造"); err != nil {
			t.Fatalf("SetDeviceStatus: %v", err)
		}
	}
	s := sessionOf(t, onlineSessions(t, f, "li.fang"), "li.fang")
	if asStr(s["trust"]) != store.SessionTrustUntrusted {
		t.Fatalf("名下有已吊销终端应判 untrusted，实得 %q", s["trust"])
	}
	if note := asStr(s["trustNote"]); !strings.Contains(note, "吊销") {
		t.Fatalf("依据要点名是什么状态的终端，实得 %q", note)
	}
}

// ★核心用例③：被 degrade 降权的账号必须显示成高风险，且理由与执行同源。
// 此前这一格恒 none——页面说「无风险」，而这个人的高敏资源已经被摘掉了。
func TestOnlineSession_降权账号判高风险且理由同源(t *testing.T) {
	f := newIsoFixture(t)
	f.reportPosture("li.fang", "MAC-1", store.DisposalDegrade, "系统完整性保护未开启")
	s := sessionOf(t, onlineSessions(t, f, "li.fang"), "li.fang")
	if asStr(s["risk"]) != store.SessionRiskHigh {
		t.Fatalf("degrade 账号应判 high，实得 %q（%v）", s["risk"], s["riskNote"])
	}
	note := asStr(s["riskNote"])
	if !strings.Contains(note, "degrade") || !strings.Contains(note, "系统完整性保护未开启") {
		t.Fatalf("理由要与判定同源（档位 + posture 的 reasons），实得 %q", note)
	}
	// 合规之后必须翻回来——否则这一格会永久红着，管理员会学会忽略它
	f.reportPosture("li.fang", "MAC-1", store.DisposalAllow)
	s = sessionOf(t, onlineSessions(t, f, "li.fang"), "li.fang")
	if asStr(s["risk"]) != store.SessionRiskNone {
		t.Fatalf("恢复合规后应判 none，实得 %q", s["risk"])
	}
}

// gray 档是 low 而不是 high：它的执行内容只有一条 observing 审计，访问权一字未改。
// 混成 high 会让管理员把「正在观察」当成「已被拦」。
func TestOnlineSession_灰度观察判低风险(t *testing.T) {
	f := newIsoFixture(t)
	f.reportPosture("li.fang", "MAC-1", store.DisposalGray, "EDR 终端防护在线 未通过")
	s := sessionOf(t, onlineSessions(t, f, "li.fang"), "li.fang")
	if asStr(s["risk"]) != store.SessionRiskLow {
		t.Fatalf("gray 应判 low，实得 %q", s["risk"])
	}
}

// 组织取自 users 目录（SQLiteStore.Users 已按 org_units 回填成组织名）。
func TestOnlineSession_组织取真值(t *testing.T) {
	f := newIsoFixture(t)
	if err := f.st.SetUserOrg(context.Background(), "u2", "dev"); err != nil { // u2 = li.fang
		t.Fatalf("SetUserOrg: %v", err)
	}
	s := sessionOf(t, onlineSessions(t, f, "li.fang"), "li.fang")
	if org := asStr(s["org"]); org == "" || org == "—" {
		t.Fatalf("组织应取到真值，实得 %q", org)
	}
}

// ★没有来源的四个字段（接入地点/设备/OS/当前应用）必须整体消失，
// 而不是继续以 "—" 的形式占着表头——四列永远空着的表头不是「暂无数据」，
// 是在暗示这些维度存在而恰好没取到。「异地·公网接入」那个 KPI 因此结构性恒 0。
func TestOnlineSession_无来源字段已整体删除(t *testing.T) {
	f := newIsoFixture(t)
	rows := onlineSessions(t, f, "li.fang")
	if len(rows) == 0 {
		t.Fatal("没有会话，用例前置失败")
	}
	for _, dead := range []string{"location", "device", "os", "app"} {
		if _, ok := rows[0][dead]; ok {
			t.Fatalf("字段 %q 没有任何数据来源（网关按会话只报 IP/账号/角色/建立时刻），"+
				"应整体删除而不是填 \"—\"：%v", dead, rows[0])
		}
	}
	// 保留的那几格必须真有值
	for _, live := range []string{"ip", "auth", "gateway", "trust", "risk"} {
		if asStr(rows[0][live]) == "" {
			t.Fatalf("字段 %q 应有值：%v", live, rows[0])
		}
	}
}
