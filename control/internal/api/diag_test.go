package api

import (
	"net/http"
	"strings"
	"testing"
)

// 运维体检诚实化：检查项只陈述实测事实，不再给种子数据背书。
//
// 历史缺陷：checkCluster/checkStealth/checkAuthSources/checkAuditDisk 读的都是
// Memory 种子——网关一台没起、集群根本不存在，诊断页也能画出"集群健康""隐身生效"。

// diagCheck 从 /diag 响应里按 key 取一项检查。
func diagCheck(t *testing.T, out map[string]any, key string) map[string]any {
	t.Helper()
	checks, ok := out["checks"].([]any)
	if !ok {
		t.Fatalf("diag 响应缺 checks: %v", out)
	}
	for _, it := range checks {
		c, ok := it.(map[string]any)
		if ok && c["key"] == key {
			return c
		}
	}
	t.Fatalf("diag 响应里找不到检查项 %q", key)
	return nil
}

func getDiag(t *testing.T, h http.Handler) map[string]any {
	t.Helper()
	code, out := doJSON(t, h, "GET", "/api/v1/diag", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("diag http %d, want 200", code)
	}
	return out
}

// 无网关注册时：stealth 必须 warn「隐身状态未知」，绝不能凭种子拓扑报 pass。
func TestDiagStealthWarnWithoutGateways(t *testing.T) {
	h := newTestServer(t)
	out := getDiag(t, h)

	spa := diagCheck(t, out, "spa")
	if spa["status"] != "warn" {
		t.Fatalf("无网关注册时 stealth 应 warn, got %v（summary=%v）", spa["status"], spa["summary"])
	}
	if sum := spa["summary"].(string); !strings.Contains(sum, "未知") {
		t.Fatalf("stealth 文案应如实报未知, got %q", sum)
	}
	if items, ok := spa["items"].([]any); ok && len(items) > 0 {
		t.Fatalf("无网关注册时不该有网关明细: %v", items)
	}
}

// 有在线网关、但它**没上报隐身实测态**（旧版网关）时：绝不能报 pass。
//
// ★这条用例此前断言的正是被修掉的假绿：「有在线网关时 stealth 应 pass」。
// 一台在线网关只说明它在跑，说明不了它有没有隐身——参考部署默认不开 -pf，
// 未敲门的 TCP 会先完成三次握手再被用户态断开，nmap 判 open。
// 绿着的测试在替那句断言背书，改对实现反而是它转红，所以它必须跟着改。
func TestDiagStealthUnreportedIsNotPass(t *testing.T) {
	h := newTestServer(t)
	// 测试栈开着 gwPlaintextCompat，register 挂在主 mux 上（生产收口在 mTLS 独立口）。
	code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-test", "proxy": "10.0.0.5:18443", "spa": "10.0.0.5:18201",
	})
	if code != http.StatusOK {
		t.Fatalf("register http %d", code)
	}

	spa := diagCheck(t, getDiag(t, h), "spa")
	if spa["status"] == "pass" {
		t.Fatalf("网关没上报隐身实测态就报 pass = 替一台可能裸奔的网关打包票, got %v", spa)
	}
	if m := spa["metric"].(string); !strings.Contains(m, "内核态隐身生效 0 / 在线 1") {
		t.Fatalf("指标应分开报「生效台数」与「在线台数」, got %q", m)
	}
	items := spa["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("应逐台列出, got %v", items)
	}
	if v := items[0].(map[string]any)["value"].(string); !strings.Contains(v, "未上报") {
		t.Fatalf("旧网关应如实说「未上报」, got %q", v)
	}
}

// 集群检查：没配备机时必须 skip + 如实文案，永远不再出现「主备冗余就绪」；skip 不进健康分分母。
// （配了备机之后的 pass/warn 两态见 api/standby_test.go 的 TestDiagClusterMatchesSystemPage。）
func TestDiagClusterSkipHonest(t *testing.T) {
	h := newTestServer(t)
	out := getDiag(t, h)

	cl := diagCheck(t, out, "cluster")
	if cl["status"] != "skip" {
		t.Fatalf("cluster 应 skip, got %v", cl["status"])
	}
	sum := cl["summary"].(string)
	if !strings.Contains(sum, "未配置备机") || strings.Contains(sum, "主备冗余就绪") {
		t.Fatalf("cluster 文案应承认没有备机, got %q", sum)
	}
	if !strings.Contains(cl["hint"].(string), "promote-standby.sh") {
		t.Errorf("处置建议应给出真实存在的补救路径, got %q", cl["hint"])
	}
	if out["skip"].(float64) < 1 {
		t.Fatalf("bundle 应统计 skip 项: %v", out["skip"])
	}
}

// 认证源检查：清单来自 SQLite auth_sources（种子只有本地目录一条），
// 不再是 Memory 种子的 6 条（含代码层拒绝创建的 radius/短信源）；且绝不假称"在线"。
func TestDiagAuthSourcesFromSQLite(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	// 落一条真实 LDAP 配置（停用态，避免测试真发起连接）
	code, _ := doJSON(t, h, "POST", "/api/v1/authsrc/sources", adm, map[string]any{
		"name": "测试 LDAP", "kind": "ldap", "enabled": false, "priority": 10,
		"config": map[string]any{"url": "ldap://127.0.0.1:1389", "baseDN": "dc=example,dc=org"},
	})
	if code != http.StatusOK {
		t.Fatalf("save authsrc http %d", code)
	}

	c := diagCheck(t, getDiag(t, h), "authsrc")
	items := c["items"].([]any)
	if len(items) != 2 { // local 种子 + 刚建的 ldap
		t.Fatalf("认证源明细应来自 SQLite 真实配置（2 条）, got %d: %v", len(items), items)
	}
	var names []string
	for _, it := range items {
		names = append(names, it.(map[string]any)["label"].(string))
	}
	joined := strings.Join(names, "|")
	if !strings.Contains(joined, "本地用户目录") || !strings.Contains(joined, "测试 LDAP") {
		t.Fatalf("明细应列真实源, got %v", names)
	}
	// Memory 种子里的编造源（含被代码拒绝的类型）不得出现
	for _, ghost := range []string{"总部", "RADIUS", "短信", "商密"} {
		if strings.Contains(joined, ghost) {
			t.Fatalf("认证源明细混入了 Memory 种子 %q: %v", ghost, names)
		}
	}
	// 连通性只有 probe 才知道：结论与指标里不得出现"在线/可达"判定
	sum, metric := c["summary"].(string), c["metric"].(string)
	if strings.Contains(sum, "在线") || strings.Contains(sum, "可达") || strings.Contains(metric, "在线") {
		t.Fatalf("认证源检查不得假称在线/可达: summary=%q metric=%q", sum, metric)
	}
	if !strings.Contains(sum, "测试连接") {
		t.Fatalf("文案应指引以测试连接实测连通性, got %q", sum)
	}
}

// 审计磁盘检查：指标必须是实测（行数/库文件大小/磁盘余量），不再是种子恒 62%。
func TestDiagAuditDiskMeasured(t *testing.T) {
	h := newTestServer(t)
	c := diagCheck(t, getDiag(t, h), "audit-disk")

	m := c["metric"].(string)
	for _, want := range []string{"审计", "行", "库文件", "磁盘余"} {
		if !strings.Contains(m, want) {
			t.Fatalf("audit-disk 指标应含实测口径 %q, got %q", want, m)
		}
	}
	if strings.Contains(m, "占用 62%") {
		t.Fatalf("audit-disk 不得再报种子恒值 62%%: %q", m)
	}
	// 测试栈未注入留存配置（main 才会 SetAuditRetentionDays）→ 应如实报未配置滚动清理
	if c["status"] != "warn" && c["status"] != "fail" && c["status"] != "pass" {
		t.Fatalf("audit-disk 状态非法: %v", c["status"])
	}
	if !strings.Contains(m, "未配置滚动清理") {
		t.Fatalf("未注入留存配置时应如实标注, got %q", m)
	}
}
