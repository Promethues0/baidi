package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── 测试脚手架 ──

type ipsecFixture struct {
	st    *store.SQLiteStore
	srv   *Server
	admin http.Handler // 明文口 + Bearer 中间件
	mtls  http.Handler // mTLS 口（身份靠伪造的客户端证书 CN）
}

func newIpsecFixture(t *testing.T) *ipsecFixture {
	t.Helper()
	// ★必须在第一次触碰 secret.Default() 之前把主密钥路径指到临时目录：
	// 否则会在包目录下生成一个 ipsec-psk.key，污染工作区。
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ipsec.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, false)
	return &ipsecFixture{
		st: st, srv: s,
		admin: auth.Middleware(testKeys, s.IsOpen)(s.Routes()),
		mtls:  s.MTLSHandler(),
	}
}

// callAdmin 发一个带 Bearer 的明文口请求。
func (f *ipsecFixture) callAdmin(t *testing.T, method, path, body, tok string) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	f.admin.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// callMTLS 发一个「已完成 mTLS 握手」的请求。
//
// withCertCN 只读 r.TLS.PeerCertificates[0].Subject.CommonName，
// 因此伪造一个 ConnectionState 即可精确测到 CN 分权那一层，不必真起 TLS 监听
// （真握手要 CA + 证书 + 端口，测的还是同一行判断）。
func (f *ipsecFixture) callMTLS(t *testing.T, method, path, cn, body string) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: cn}},
	}}
	w := httptest.NewRecorder()
	f.mtls.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *ipsecFixture) auditEvents(t *testing.T) []string {
	t.Helper()
	b, err := f.st.Audit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(b.Logs))
	for _, e := range b.Logs {
		out = append(out, e.Event)
	}
	return out
}

// ── 鉴权 ──

// 站点清单 = 对端公网地址 + 两端内网网段，一张完整的内网拓扑图。仅 admin。
func TestIpsecListRequiresAdmin(t *testing.T) {
	f := newIpsecFixture(t)
	userTok := userToken("li.fang")
	if code, _ := f.callAdmin(t, http.MethodGet, "/api/v1/ipsec", "", userTok); code != http.StatusForbidden {
		t.Fatalf("普通用户不该读到组网拓扑，实得 %d", code)
	}
	if code, _ := f.callAdmin(t, http.MethodGet, "/api/v1/ipsec", "", ""); code == http.StatusOK {
		t.Fatal("匿名不该读到组网拓扑")
	}
	if code, _ := f.callAdmin(t, http.MethodGet, "/api/v1/ipsec", "", adminToken()); code != http.StatusOK {
		t.Fatalf("admin 应能读，实得 %d", code)
	}
}

// ── toggle 语义与审计文案 ──

// ★本轮最重要的一条回归：toggle 只下发**意图**，不得声称隧道已建立。
//
// 旧实现把 status 直接写成 'up' 并记审计「建立 IPSec 隧道 site-sh · ok」——
// 没有任何进程被通知、没有任何网络动作，而审计日志断言了一个从未发生的事实。
func TestToggleOnlySetsIntentAndAuditsHonestly(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec/site-sh/toggle", "", tok)
	if code != http.StatusOK {
		t.Fatalf("toggle 失败：%d %v", code, resp)
	}
	if resp["enabled"] != true {
		t.Fatalf("应翻转成已启用：%v", resp)
	}
	// 兼容字段 status 现在只能是 connecting（还没有网关回报过），绝不能是 up
	if resp["status"] == "up" {
		t.Fatal("点一下 toggle 就显示 up——这正是旧实现的谎言，状态必须等网关回报")
	}
	if resp["status"] != "connecting" {
		t.Fatalf("启用但无回报时应为 connecting，实得 %v", resp["status"])
	}

	events := f.auditEvents(t)
	found := false
	for _, e := range events {
		if strings.Contains(e, "建立 IPSec 隧道") {
			t.Fatalf("审计仍在谎报隧道已建立：%q", e)
		}
		if strings.Contains(e, "site-sh") && strings.Contains(e, "意图") {
			found = true
		}
	}
	if !found {
		t.Fatalf("审计应记录「下发启用意图」，实得 %v", events)
	}

	// 再点一次回到停用
	_, resp = f.callAdmin(t, http.MethodPost, "/api/v1/ipsec/site-sh/toggle", "", tok)
	if resp["enabled"] != false || resp["status"] != "down" {
		t.Fatalf("再次 toggle 应回到未启用：%v", resp)
	}

	if code, _ := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec/site-无/toggle", "", tok); code != http.StatusNotFound {
		t.Fatalf("不存在的站点应 404，实得 %d", code)
	}
}

// toggle 必须按请求体里的**目标值**执行，而不是按当前值盲翻转。
//
// ★盲翻转下，两次并发点击、或基于一份陈旧列表的一次点击，会把「我要启用」
// 执行成「停用」，而返回体看起来完全正常。前端一直提交的就是 {enabled: 目标值}。
func TestToggleHonorsRequestedTargetState(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	// 站点当前是停用。连发两次「启用」：幂等，两次都应得到 enabled=true。
	for i := 0; i < 2; i++ {
		code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec/site-sh/toggle", `{"enabled":true}`, tok)
		if code != http.StatusOK {
			t.Fatalf("第 %d 次启用失败：%d %v", i+1, code, resp)
		}
		if resp["enabled"] != true {
			t.Fatalf("第 %d 次提交 enabled=true 却得到 %v——盲翻转把「启用」执行成了「停用」", i+1, resp["enabled"])
		}
	}
	// 同理，连发两次「停用」也必须幂等
	for i := 0; i < 2; i++ {
		_, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec/site-sh/toggle", `{"enabled":false}`, tok)
		if resp["enabled"] != false {
			t.Fatalf("第 %d 次提交 enabled=false 却得到 %v", i+1, resp["enabled"])
		}
	}
	// 不带请求体（旧控制台 / curl）仍走翻转，保持既有调用方可用
	_, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec/site-sh/toggle", "", tok)
	if resp["enabled"] != true {
		t.Fatalf("空请求体应回退到翻转语义，实得 %v", resp["enabled"])
	}
}

// gatewayId 不以 ipsec- 开头 = 协议上不可能被任何网关承载（控制面按证书 CN 精确过滤），
// 而症状是「站点安静地永远 down、日志里一条协商记录都没有」。保存时就要拦。
func TestSaveIpsecRejectsGatewayIDWithoutIpsecPrefix(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	body := `{"name":"错前缀","peer":"203.0.113.9","localSubnet":"10.20.0.0/16",` +
		`"remoteSubnet":"10.80.0.0/16","auth":"psk","suite":"standard","gatewayId":"gw-1","enabled":true}`
	code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok)
	if code != http.StatusBadRequest {
		t.Fatalf("gatewayId=gw-1 应被拒（它取不到任何站点），实得 %d %v", code, resp)
	}
	errObj, _ := resp["error"].(map[string]any)
	if msg, _ := errObj["message"].(string); !strings.Contains(msg, "ipsec-gw-1") {
		t.Fatalf("错误信息应直接给出改法 ipsec-gw-1，实得 %q", msg)
	}

	// 正确前缀照常保存
	ok := strings.Replace(body, `"gatewayId":"gw-1"`, `"gatewayId":"ipsec-gw-1"`, 1)
	if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", ok, tok); code != http.StatusOK {
		t.Fatalf("合法 gatewayId 应保存成功：%d %v", code, resp)
	}
}

// 启用但未指派承载网关 = 静默失效（没有任何网关会去建这条隧道），必须显式报出来。
func TestConfigWarningSurfacesSilentFailures(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	body := `{"name":"孤儿站点","peer":"203.0.113.7","localSubnet":"10.20.0.0/16",` +
		`"remoteSubnet":"10.80.0.0/16","auth":"psk","suite":"standard","enabled":true}`
	code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok)
	if code != http.StatusOK {
		t.Fatalf("保存失败：%d %v", code, resp)
	}
	site, _ := resp["site"].(map[string]any)
	warn, _ := site["configWarning"].(string)
	if !strings.Contains(warn, "未指派承载网关") {
		t.Fatalf("未指派网关必须报出来，否则站点永远停在 connecting 且零报错：%q", warn)
	}
	if !strings.Contains(warn, "PSK") {
		t.Fatalf("未配 PSK 也必须报出来：%q", warn)
	}
}

// 配置校验的错误信息必须带上实际值，能直接指导排障。
func TestSaveIpsecValidatesWithActualValues(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	// 主机位不为零是最常见的手误，且 netip 会拒绝
	body := `{"name":"X","peer":"203.0.113.7","localSubnet":"10.20.0.1/16","remoteSubnet":"10.80.0.0/16"}`
	code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok)
	msg := errMsg(resp)
	if code != http.StatusBadRequest || !strings.Contains(msg, "10.20.0.1/16") || !strings.Contains(msg, "10.20.0.0/16") {
		t.Fatalf("应拒绝并给出应该写成什么：%d %q", code, msg)
	}
	body = `{"name":"X","peer":"不是地址","localSubnet":"10.20.0.0/16","remoteSubnet":"10.80.0.0/16"}`
	code, resp = f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok)
	if code != http.StatusBadRequest || !strings.Contains(errMsg(resp), "不是地址") {
		t.Fatalf("应拒绝非法 peer 并回显实际值：%d %v", code, resp)
	}
	// 合法形态：裸 IP / IP:port（含 IPv6）
	for _, peer := range []string{"203.0.113.7", "203.0.113.7:500", "[2001:db8::1]:500"} {
		body = `{"name":"X","peer":"` + peer + `","localSubnet":"10.20.0.0/16","remoteSubnet":"10.80.0.0/16"}`
		if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok); code != http.StatusOK {
			t.Fatalf("peer=%q 应被接受：%d %v", peer, code, resp)
		}
	}
	// ★FQDN 必须**拒收**（wave8 行动 17）。这条断言此前是反的——它把
	// 「sh.example.com 应被接受」钉成了正确行为，而组网网关的 parsePeer 是**刻意**
	// 不解析域名的（sync_test.go 正把「拒收 FQDN」钉住）。于是入口放行、
	// 400 文案还主动推荐这种写法，管理员照着填拿到 200 OK，站点安静地永远 down：
	// 要等到「已指派网关 + 网关在线 + 下一轮同步」之后才能从 LastError 里看到那句拒绝。
	// 又一个「绿着的测试在替坏行为背书」（同 wave8 行动 2 的 Rust 用例、行动 7 的 diag 用例）。
	for _, peer := range []string{"sh.example.com", "sh.example.com:500"} {
		body = `{"name":"X","peer":"` + peer + `","localSubnet":"10.20.0.0/16","remoteSubnet":"10.80.0.0/16"}`
		code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok)
		if code != http.StatusBadRequest {
			t.Fatalf("peer=%q 是域名，数据面不解析 DNS，入口必须当场拒收：%d %v", peer, code, resp)
		}
		m := errMsg(resp)
		if !strings.Contains(m, "DNS") || !strings.Contains(m, peer) {
			t.Fatalf("拒绝要说得出原因并回显实际值（否则管理员会反复换写法去试）：%q", m)
		}
	}
	// 400 文案不得再把域名列为推荐写法。
	body = `{"name":"X","peer":"???","localSubnet":"10.20.0.0/16","remoteSubnet":"10.80.0.0/16"}`
	if _, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok); strings.Contains(errMsg(resp), "example.com") {
		t.Fatalf("错误文案不该把 FQDN 列为可用写法：%q", errMsg(resp))
	}
}

func errMsg(resp map[string]any) string {
	e, _ := resp["error"].(map[string]any)
	m, _ := e["message"].(string)
	return m
}

// ── PSK：只写不读 ──

// ★写进去之后，任何管理侧响应都不得再出现 PSK 原文，只回 hasPsk + 8 位指纹。
func TestSetPSKIsWriteOnly(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()
	const psk = "a-sufficiently-long-preshared-key"

	code, resp := f.callAdmin(t, http.MethodPut, "/api/v1/ipsec/site-sh/psk", `{"psk":"`+psk+`"}`, tok)
	if code != http.StatusOK {
		t.Fatalf("写 PSK 失败：%d %v", code, resp)
	}
	if resp["pskVersion"] != float64(1) {
		t.Fatalf("首次写入版本应为 1：%v", resp)
	}
	if _, leaked := resp["psk"]; leaked {
		t.Fatal("手工设置的 PSK 不该被回显")
	}
	fp, _ := resp["pskFingerprint"].(string)
	if len(fp) != 8 {
		t.Fatalf("指纹应回前 8 位十六进制，实得 %q", fp)
	}

	// 清单里同样不得出现原文；hasPsk 与指纹要在
	_, list := f.callAdmin(t, http.MethodGet, "/api/v1/ipsec", "", tok)
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), psk) {
		t.Fatal("站点清单里出现了 PSK 原文")
	}
	sites, _ := list["sites"].([]any)
	seen := false
	for _, s := range sites {
		m, _ := s.(map[string]any)
		if m["id"] != "site-sh" {
			continue
		}
		seen = true
		if m["hasPsk"] != true {
			t.Fatalf("hasPsk 应为 true：%v", m)
		}
		if m["pskFingerprint"] != fp {
			t.Fatalf("指纹回显不一致：%v vs %v", m["pskFingerprint"], fp)
		}
	}
	if !seen {
		t.Fatal("清单里找不到 site-sh")
	}

	// 审计只记站点与版本，绝不出现密钥的任何形态
	for _, e := range f.auditEvents(t) {
		if strings.Contains(e, psk) {
			t.Fatalf("审计日志泄漏了 PSK：%q", e)
		}
	}
}

// 弱 PSK 必须被拒，且错误信息要说清「差多少」与「为什么」。
// IKEv2 的 AUTH 载荷是 PSK 的 PRF 输出，抓一次握手就能离线爆破——弱口令等于没有认证。
func TestShortPSKRejectedWithActionableMessage(t *testing.T) {
	f := newIpsecFixture(t)
	code, resp := f.callAdmin(t, http.MethodPut, "/api/v1/ipsec/site-sh/psk", `{"psk":"123456"}`, adminToken())
	msg := errMsg(resp)
	if code != http.StatusBadRequest {
		t.Fatalf("弱 PSK 应被拒，实得 %d", code)
	}
	if !strings.Contains(msg, "20") || !strings.Contains(msg, "6") || !strings.Contains(msg, "generate") {
		t.Fatalf("错误信息应含期望长度/实际长度/替代方案：%q", msg)
	}
}

// generate 路径：控制面生成，**只在本次响应里出现一次**，之后无任何回读路径。
func TestGeneratePSKReturnedExactlyOnce(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()
	code, resp := f.callAdmin(t, http.MethodPut, "/api/v1/ipsec/site-cd/psk", `{"generate":true}`, tok)
	if code != http.StatusOK {
		t.Fatalf("生成失败：%d %v", code, resp)
	}
	psk, _ := resp["psk"].(string)
	if len(psk) < minPSKLen {
		t.Fatalf("生成的 PSK 太短：%q", psk)
	}
	if resp["notice"] == nil {
		t.Fatal("必须明确告知「只出现一次、不提供回读」")
	}
	// 之后清单里再也拿不到
	_, list := f.callAdmin(t, http.MethodGet, "/api/v1/ipsec", "", tok)
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), psk) {
		t.Fatal("生成的 PSK 在后续读取中再次出现——「只写不读」没有兑现")
	}
}

func TestSetPSKOnMissingSite404(t *testing.T) {
	f := newIpsecFixture(t)
	code, _ := f.callAdmin(t, http.MethodPut, "/api/v1/ipsec/site-无/psk",
		`{"psk":"a-sufficiently-long-preshared-key"}`, adminToken())
	if code != http.StatusNotFound {
		t.Fatalf("不存在的站点应 404（静默成功会让管理员以为密钥已生效），实得 %d", code)
	}
}

// ── mTLS：CN 前缀分权 ──

// ★核心断言：一张只负责站点组网的证书**读不到全量资源授权策略**。
// policy 里是「谁能访问哪个后端」的完整清单，等于一张授权地图。
func TestIpsecCertCannotReadResourcePolicy(t *testing.T) {
	f := newIpsecFixture(t)
	for _, p := range []string{"/api/v1/gateways/policy"} {
		code, resp := f.callMTLS(t, http.MethodGet, p, "ipsec-1", "")
		if code != http.StatusForbidden {
			t.Fatalf("ipsec-* 证书不该能调 %s，实得 %d %v", p, code, resp)
		}
	}
	code, _ := f.callMTLS(t, http.MethodPost, "/api/v1/gateways/register", "ipsec-1", `{"id":"ipsec-1"}`)
	if code != http.StatusForbidden {
		t.Fatalf("ipsec-* 证书不该能注册成接入网关，实得 %d", code)
	}
	// 反向：接入网关证书调不到 ipsec 端点（PSK 的出口要尽可能窄）
	for _, p := range []string{"/api/v1/gateways/ipsec", "/api/v1/gateways/ipsec/site-sh/psk"} {
		code, resp := f.callMTLS(t, http.MethodGet, p, "gw-1", "")
		if code != http.StatusForbidden {
			t.Fatalf("接入网关证书不该能调 %s，实得 %d %v", p, code, resp)
		}
		if !strings.Contains(errMsg(resp), "ipsec-") {
			t.Fatalf("错误信息应写明期望的 CN 前缀与实际 CN：%q", errMsg(resp))
		}
	}
	// 存量接入网关的 CN 由部署时的 GW_ID 决定（可能不是 gw- 开头），必须继续可用
	if code, _ := f.callMTLS(t, http.MethodGet, "/api/v1/gateways/policy", "beijing-idc-1", ""); code != http.StatusOK {
		t.Fatalf("非 gw- 前缀的存量接入网关必须继续可用（收成白名单会在升级瞬间踢掉现网），实得 %d", code)
	}
}

// 下发只给归属本网关的站点，且不含 PSK 的任何形态。
func TestGatewayIpsecSitesMinimalDisclosure(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()
	// 种子三条都归 ipsec-1；另建一条归 ipsec-2
	body := `{"name":"别人家的站点","gatewayId":"ipsec-2","peer":"203.0.113.99",` +
		`"localSubnet":"10.20.0.0/16","remoteSubnet":"10.90.0.0/16","auth":"psk"}`
	if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok); code != http.StatusOK {
		t.Fatalf("保存失败：%d %v", code, resp)
	}
	_, _ = f.callAdmin(t, http.MethodPut, "/api/v1/ipsec/site-sh/psk",
		`{"psk":"a-sufficiently-long-preshared-key"}`, tok)

	code, resp := f.callMTLS(t, http.MethodGet, "/api/v1/gateways/ipsec", "ipsec-1", "")
	if code != http.StatusOK {
		t.Fatalf("下发失败：%d %v", code, resp)
	}
	raw, _ := json.Marshal(resp)
	if strings.Contains(string(raw), "10.90.0.0/16") || strings.Contains(string(raw), "203.0.113.99") {
		t.Fatal("下发了别的网关的站点：对端地址 + 内网网段是一张现成的横向移动地图")
	}
	for _, leak := range []string{"psk\":\"", "pskFingerprint", "hasPsk"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("站点下发里出现了密钥相关字段 %q：PSK 只走单独端点", leak)
		}
	}
	if !strings.Contains(string(raw), "pskVersion") {
		t.Fatal("必须带 pskVersion，否则网关无从判断本地密钥是否过期")
	}
}

// ★取 PSK 必须校验「这条站点归你」。前两道闸只证明「你是一台我们签过的 IPSec 网关」。
func TestGatewayPSKRequiresOwnership(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()
	const psk = "a-sufficiently-long-preshared-key"
	if code, resp := f.callAdmin(t, http.MethodPut, "/api/v1/ipsec/site-sh/psk", `{"psk":"`+psk+`"}`, tok); code != http.StatusOK {
		t.Fatalf("写 PSK 失败：%d %v", code, resp)
	}

	// 归属网关：拿得到，且原文与写入一致（base64 口径）
	code, resp := f.callMTLS(t, http.MethodGet, "/api/v1/gateways/ipsec/site-sh/psk", "ipsec-1", "")
	if code != http.StatusOK {
		t.Fatalf("归属网关应能取到 PSK：%d %v", code, resp)
	}
	if resp["version"] != float64(1) {
		t.Fatalf("版本应为 1：%v", resp)
	}
	b64, _ := resp["psk"].(string)
	if decoded := mustB64(t, b64); decoded != psk {
		t.Fatalf("PSK 往返口径不一致：%q != %q（两端编码不一致的症状是一句无头无尾的「认证失败」）", decoded, psk)
	}

	// 非归属网关：404（不告诉它「存在但不归你」——站点 id 本身也是拓扑情报）
	if code, _ := f.callMTLS(t, http.MethodGet, "/api/v1/gateways/ipsec/site-sh/psk", "ipsec-9", ""); code != http.StatusNotFound {
		t.Fatalf("非归属网关不该拿到 PSK，实得 %d", code)
	}
	// 未配 PSK 的站点
	if code, _ := f.callMTLS(t, http.MethodGet, "/api/v1/gateways/ipsec/site-cd/psk", "ipsec-1", ""); code != http.StatusNotFound {
		t.Fatalf("未配 PSK 应 404，实得 %d", code)
	}

	// 下发有审计（密钥流动可追溯），且不含原文
	hit := false
	for _, e := range f.auditEvents(t) {
		if strings.Contains(e, psk) {
			t.Fatalf("审计泄漏 PSK：%q", e)
		}
		if strings.Contains(e, "下发") && strings.Contains(e, "site-sh") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("PSK 下发必须留审计：%v", f.auditEvents(t))
	}
}

func mustB64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("PSK 不是合法 base64：%v", err)
	}
	return string(b)
}

// ── 运行态回报 ──

// 网关回报的运行态必须真的落库并出现在管理侧清单里（状态回路闭合），
// 且不属于本网关的站点被丢弃并在响应里明确计数——静默忽略会让网关一直白报。
func TestGatewayStatusReportClosesTheLoop(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()
	_, _ = f.callAdmin(t, http.MethodPost, "/api/v1/ipsec/site-sh/toggle", "", tok)

	body := `{"states":[
	  {"siteId":"site-sh","gatewayId":"ipsec-伪造","state":"up","ikeSpiI":"1122334455667788",
	   "ikeSpiR":"8877665544332211","childSpiIn":3232235777,"childSpiOut":1067188226,
	   "rxBytes":4096,"txBytes":2048,"negotiatedProposal":"AES256-GCM16/PRF-HMAC-SHA256/ECP256",
	   "establishedAt":1700000000},
	  {"siteId":"site-别人的","state":"up"},
	  {"siteId":"site-cd","state":"我不认识这个状态"}
	]}`
	code, resp := f.callMTLS(t, http.MethodPost, "/api/v1/gateways/ipsec/status", "ipsec-1", body)
	if code != http.StatusOK {
		t.Fatalf("回报失败：%d %v", code, resp)
	}
	if resp["accepted"] != float64(2) {
		t.Fatalf("应接受 2 条（site-sh + site-cd），实得 %v", resp["accepted"])
	}
	rejected, _ := resp["rejected"].([]any)
	if len(rejected) != 1 || rejected[0] != "site-别人的" {
		t.Fatalf("不归本网关的站点应被丢弃并计数：%v", resp["rejected"])
	}

	_, list := f.callAdmin(t, http.MethodGet, "/api/v1/ipsec", "", tok)
	sites, _ := list["sites"].([]any)
	for _, s := range sites {
		m, _ := s.(map[string]any)
		sa, _ := m["sa"].(map[string]any)
		switch m["id"] {
		case "site-sh":
			if sa == nil || sa["state"] != "up" {
				t.Fatalf("回报的运行态没进管理侧清单：%v", m)
			}
			if sa["gatewayId"] != "ipsec-1" {
				t.Fatalf("body 里自报的 gatewayId 不该被采信：%v", sa["gatewayId"])
			}
			// 兼容字段现在来自实测值而不是种子常量
			if m["status"] != "up" || m["rxBytes"] != float64(4096) {
				t.Fatalf("兼容字段应由实测运行态现算：%v", m)
			}
			if sa["reportedAt"] == float64(0) {
				t.Fatal("reportedAt 应由控制面盖章（界面上的「最近更新 N 秒前」不该依赖网关时钟）")
			}
		case "site-cd":
			// 未知状态折成 failed：原样落库会让前端状态灯静默不渲染，看起来像「这行没状态」
			if sa == nil || sa["state"] != "failed" {
				t.Fatalf("未知状态应折成 failed，实得 %v", sa)
			}
		}
	}
}
