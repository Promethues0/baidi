package api

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
)

// 口令复杂度闸（FR-POLICY-08）的四条写口。
//
// ★改造前 auth.PasswordWeakness 在全仓只有**一个**非测试消费方（自助改密），
// 而口令能被写进库的地方有五处；另外四处一律只查 len(pw) < 6。
// 于是判定器算得好好的、中文原因也备好了，弱口令照样落库并回 200。
//
// ★变异检查（实跑过）：把任一处的 requireStrongPassword / weakPasswordReason 去掉，
// 对应的子用例必须变红。

func TestWeakPasswordRejectedAtEveryWriteSite(t *testing.T) {
	weak := []struct{ pw, why string }{
		{"123456", "命中常见弱口令表"},
		{"baidi@123", "命中常见弱口令表"}, // 就是那个曾经的默认值
		{"Short1!", "长度不足 10 位"},
		{"aaaaaaaaaaaa", "字符种类不足"},
	}

	t.Run("建普通用户", func(t *testing.T) {
		h := newTestServer(t)
		for _, w := range weak {
			code, out := doJSON(t, h, "POST", "/api/v1/users", adminToken(),
				map[string]any{"name": "弱口令", "account": "weak.user", "password": w.pw})
			if code != http.StatusBadRequest {
				t.Fatalf("口令 %q 应被拒（%s），实得 %d %v", w.pw, w.why, code, out)
			}
			assertReasonMentions(t, out, w.why)
		}
	})

	t.Run("管理员重置口令", func(t *testing.T) {
		h := newTestServer(t)
		for _, w := range weak {
			code, out := doJSON(t, h, "POST", "/api/v1/users/u2/password", adminToken(),
				map[string]any{"password": w.pw})
			if code != http.StatusBadRequest {
				t.Fatalf("重置成 %q 应被拒（%s），实得 %d %v", w.pw, w.why, code, out)
			}
			assertReasonMentions(t, out, w.why)
		}
	})

	t.Run("建管理员", func(t *testing.T) {
		h := newTestServer(t)
		for _, w := range weak {
			code, out := doJSON(t, h, "POST", "/api/v1/admins", adminToken(),
				map[string]any{"account": "weak.admin", "name": "弱", "roleKey": "audit", "password": w.pw})
			if code != http.StatusBadRequest {
				t.Fatalf("建管理员用 %q 应被拒（%s），实得 %d %v", w.pw, w.why, code, out)
			}
			assertReasonMentions(t, out, w.why)
		}
	})

	t.Run("CSV批量导入", func(t *testing.T) {
		h := newUsersCSVServer(t)
		code, out := importUsers(t, h, adminToken(),
			"账号,姓名,初始口令\nweak.csv,弱口令,123456\n")
		if code != http.StatusOK {
			t.Fatalf("导入本身应回 200（逐行回执），实得 %d %v", code, out)
		}
		failed, _ := out["failed"].([]any)
		if len(failed) != 1 {
			t.Fatalf("弱口令那一行应失败，实得 failed=%v created=%v", failed, out["created"])
		}
		if r, _ := mapOf(t, failed[0])["reason"].(string); !strings.Contains(r, "命中常见弱口令表") {
			t.Fatalf("失败原因应转述判定器的原话，实得 %q", r)
		}
	})
}

// TestOmittedPasswordGeneratesStrongOne 留空不再回落成公开常量，而是逐账号生成随机强口令。
//
// ★为什么不是「留空即拒」：用户目录的 CSV 导出**不含口令**（也不该含），
// 硬拒会让「导出 → 迁库 → 导入」这条路整段走不通，而那正是批量导入存在的理由。
func TestOmittedPasswordGeneratesStrongOne(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "POST", "/api/v1/users", adminToken(),
		map[string]any{"name": "自动口令", "account": "auto.pw"})
	if code != http.StatusCreated {
		t.Fatalf("留空口令应建号成功（服务端生成），实得 %d %v", code, out)
	}
	pw, _ := out["initialPassword"].(string)
	if pw == "" {
		t.Fatal("留空口令时必须在回执里交还生成的初始口令，否则这是个建了却登不进的死账号")
	}
	if pw == "baidi@123" {
		t.Fatal("生成的口令不得是那个已删除的公开常量")
	}
	if weak, why := auth.PasswordWeakness("auto.pw", pw); weak {
		t.Fatalf("系统自己生成的口令被自己的判据判为弱口令（%s）：%q——"+
			"生成器与校验器分家会造成偶发 400 且无人复现得了", why, pw)
	}
	// 真的能登进去，且是一次性的。
	_, lo := doJSON(t, h, "POST", "/api/v1/portal/login", "",
		map[string]string{"username": "auto.pw", "password": pw})
	if lo["ok"] != true {
		t.Fatalf("用交还的初始口令应能登入，实得 %v", lo)
	}
	if lo["mustChangePassword"] != true {
		t.Fatalf("系统生成的初始口令是一次性的，首登必须强制改密，实得 %v", lo)
	}
}

// TestGeneratedInitialPasswordNeverHitsAudit 一次性初始口令绝不入审计。
//
// 审计留存 180 天且可外送 SIEM——把一次性口令写进去等于给它一份长期副本，
// 而审计管理员按设计是**看得到全量审计但管不到用户**的那一权。
func TestGeneratedInitialPasswordNeverHitsAudit(t *testing.T) {
	h := newTestServer(t)
	_, out := doJSON(t, h, "POST", "/api/v1/users", adminToken(),
		map[string]any{"name": "审计探针", "account": "audit.probe"})
	pw, _ := out["initialPassword"].(string)
	if pw == "" {
		t.Fatal("前置条件不成立：没拿到生成的口令，本用例证明不了任何事")
	}
	_, al := doJSON(t, h, "GET", "/api/v1/audit?limit=200", adminToken(), nil)
	raw := strings.Join(auditDetails(t, al), "\n")
	if strings.Contains(raw, pw) {
		t.Fatalf("生成的初始口令出现在了审计正文里：%q", pw)
	}
	if !strings.Contains(raw, "初始口令由系统随机生成") {
		t.Fatalf("审计应记下「这把口令是系统生成的」这个事实（但不记口令本身），实得：%s", raw)
	}
}

func assertReasonMentions(t *testing.T, out map[string]any, want string) {
	t.Helper()
	msg, _ := mapOf(t, out["error"])["message"].(string)
	if !strings.Contains(msg, want) {
		t.Fatalf("拒绝文案应转述判定器的原话（含 %q），实得 %q", want, msg)
	}
}

// auditDetails 取审计列表里的全部正文，供「不得包含某串」这类断言用。
func auditDetails(t *testing.T, out map[string]any) []string {
	t.Helper()
	items, _ := out["logs"].([]any)
	var ds []string
	for _, it := range items {
		m := mapOf(t, it)
		if d, ok := m["event"].(string); ok {
			ds = append(ds, d)
		}
	}
	return ds
}

// TestThrottledAuditDisclosesSuppressedCount 被节流折叠掉的次数必须写进正文。
//
// ★改造前控制面侧的节流是**丢弃式**：水位表只记「上次落审计的时刻」，窗口内被抑制的
// 次数直接扔掉、正文一字不提，而审计导出页逐字写着「导出全量审计日志」。
// 同一功能族的网关侧（gateway/internal/secevent）已经做对了聚合补报，两种记录并排
// 躺在同一张 audit_log 表里，读的人分不出哪条带了聚合、哪条没带。
//
// ★变异：把 auditKnockIssued 正文里的 throttleNote(...) 去掉 → 本用例变红。
func TestThrottledAuditDisclosesSuppressedCount(t *testing.T) {
	tab := map[string]throttleMark{}
	const iv = 5 * time.Minute
	base := int64(1_700_000_000)

	// 第一次：立即落条，此前无折叠。
	due, sup := throttleAdmit(tab, "k", iv, 10, base)
	if !due || sup != 0 {
		t.Fatalf("首次必须落条且无折叠，实得 due=%v suppressed=%d", due, sup)
	}
	// 窗口内又来 7 次：全部折叠，一条都不落。
	for i := 1; i <= 7; i++ {
		if due, _ := throttleAdmit(tab, "k", iv, 10, base+int64(i)); due {
			t.Fatalf("窗口内第 %d 次不该单独落条", i)
		}
	}
	// 窗口到期：落条，并**如实报出**这 7 次。
	due, sup = throttleAdmit(tab, "k", iv, 10, base+int64(iv.Seconds()))
	if !due {
		t.Fatal("窗口到期必须落条")
	}
	if sup != 7 {
		t.Fatalf("到期那一条必须报出窗口内被折叠的 7 次，实得 %d——"+
			"丢弃式节流会让这 7 次在系统里不留任何痕迹，而审计导出页写着「全量」", sup)
	}
	if note := throttleNote(sup, iv); !strings.Contains(note, "7 次") || !strings.Contains(note, "5 分钟") {
		t.Fatalf("正文后缀要同时说清次数与窗口长度（不写窗口就无从判断密集还是稀疏），实得 %q", note)
	}
	// 报过之后清零：下一条不该重复报同一批。
	if _, sup2 := throttleAdmit(tab, "k", iv, 10, base+int64(2*iv.Seconds())); sup2 != 0 {
		t.Fatalf("已报过的折叠数必须清零，否则同一批会被反复计入，实得 %d", sup2)
	}
	// 键数上界：超出即整张清空（键含客户端自报的指纹，攻击者可控）。
	for i := 0; i < 12; i++ {
		throttleAdmit(tab, "flood"+strconv.Itoa(i), iv, 10, base)
	}
	if len(tab) > 11 {
		t.Fatalf("水位表必须有上界（键含客户端自报指纹），实得 %d 键", len(tab))
	}
}
