package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── 消息通道（PRD ch15.2）端到端 ──

type notifyFixture struct {
	srv *Server
	h   http.Handler
	st  *store.SQLiteStore
}

func newNotifyFixture(t *testing.T) *notifyFixture {
	t.Helper()
	// 必须在第一次触碰 secret.Default() 之前指走主密钥路径，否则会在包目录下生成密钥文件。
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "notify.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	return &notifyFixture{srv: s, h: auth.Middleware(testKeys, s.IsOpen)(s.Routes()), st: st}
}

// hookServer 起一个记录收到载荷的 webhook 服务端。status 为它的应答码。
func hookServer(t *testing.T, status int) (url string, got func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var payloads []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		m := map[string]any{}
		_ = json.Unmarshal(raw, &m)
		m["_authHeader"] = r.Header.Get("Authorization")
		mu.Lock()
		payloads = append(payloads, m)
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any{}, payloads...)
	}
}

// createHookChannel 建一条指向 url 的 webhook 通道，返回 id。
func createHookChannel(t *testing.T, f *notifyFixture, tok, name, url string, enabled bool) string {
	t.Helper()
	code, out := doJSON(t, f.h, "POST", "/api/v1/notify/channels", tok, map[string]any{
		"name": name, "kind": "webhook", "enabled": enabled,
		"config": map[string]any{"url": url, "secretHeader": "Authorization", "timeoutSec": 5},
	})
	if code != http.StatusOK {
		t.Fatalf("建通道 http %d: %v", code, out)
	}
	id := out["channel"].(map[string]any)["id"].(string)
	// 凭据只写不读：这里设一次，后面断言它进了请求头但从不回显。
	if code, out := doJSON(t, f.h, "PUT", "/api/v1/notify/channels/"+id+"/secret", tok,
		map[string]any{"secret": "Bearer tok-abc"}); code != http.StatusOK {
		t.Fatalf("设凭据 http %d: %v", code, out)
	}
	return id
}

// 权限矩阵：system 权可管，security/audit/普通用户一律 403。
func TestNotifyChannels_权限归系统权(t *testing.T) {
	f := newNotifyFixture(t)
	sysTok := makeAdmin(t, f.h, "sys.admin", "system")
	secTok := makeAdmin(t, f.h, "sec.admin", "security")
	audTok := makeAdmin(t, f.h, "aud.admin", "audit")

	if code, out := doJSON(t, f.h, "GET", "/api/v1/notify/channels", sysTok, nil); code != http.StatusOK {
		t.Fatalf("系统管理员应能读通道: %d %v", code, out)
	}
	for name, tok := range map[string]string{"安全管理员": secTok, "审计管理员": audTok, "普通用户": userToken("zhang.san")} {
		if code, _ := doJSON(t, f.h, "GET", "/api/v1/notify/channels", tok, nil); code != http.StatusForbidden {
			t.Errorf("%s 读通道应 403，实得 %d", name, code)
		}
		if code, _ := doJSON(t, f.h, "POST", "/api/v1/notify/channels", tok,
			map[string]any{"name": "x", "kind": "webhook"}); code != http.StatusForbidden {
			t.Errorf("%s 建通道应 403，实得 %d", name, code)
		}
	}
	// ★读端点也必须现算角色：撤掉系统管理员身份后，旧令牌立刻读不到（不等 8h 会话过期）。
	if code, out := doJSON(t, f.h, "DELETE", "/api/v1/admins/sys.admin", adminToken(), nil); code != http.StatusOK {
		t.Fatalf("撤销管理员 http %d: %v", code, out)
	}
	if code, _ := doJSON(t, f.h, "GET", "/api/v1/notify/channels", sysTok, nil); code != http.StatusForbidden {
		t.Fatalf("撤销后旧令牌仍能读通道（读面停在令牌快照上），实得 %d", code)
	}
}

// 未实现的类型在保存时明确拒绝，而不是存下来在告警发生时静默失败。
func TestNotifyChannels_未知类型拒绝(t *testing.T) {
	f := newNotifyFixture(t)
	tok := makeAdmin(t, f.h, "sys.admin", "system")
	code, out := doJSON(t, f.h, "POST", "/api/v1/notify/channels", tok,
		map[string]any{"name": "钉钉机器人", "kind": "dingtalk"})
	if code != http.StatusBadRequest {
		t.Fatalf("未实现类型应 400，实得 %d %v", code, out)
	}
}

// CRUD + 凭据只写不读 + 保存即校验。
func TestNotifyChannels_增改删与凭据只写不读(t *testing.T) {
	f := newNotifyFixture(t)
	tok := makeAdmin(t, f.h, "sys.admin", "system")
	url, _ := hookServer(t, http.StatusOK)
	id := createHookChannel(t, f, tok, "SOC webhook", url, true)

	code, out := doJSON(t, f.h, "GET", "/api/v1/notify/channels", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("列表 http %d", code)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "tok-abc") {
		t.Fatalf("★列表响应里出现了凭据原文：%s", raw)
	}
	chans := out["channels"].([]any)
	if len(chans) != 1 {
		t.Fatalf("应有 1 条通道: %v", chans)
	}
	c := chans[0].(map[string]any)
	if c["hasSecret"] != true || c["secretFingerprint"] == "" {
		t.Errorf("应回显 hasSecret + 指纹: %v", c)
	}
	// 短信通道的诚实标注要下发给控制台
	if !strings.Contains(out["smsNote"].(string), "webhook") {
		t.Errorf("smsNote 必须如实说明短信就是 webhook: %v", out["smsNote"])
	}

	// 配置写错时保存不拒绝，但把原因带回去（管理员可能分几步填）
	code, out = doJSON(t, f.h, "POST", "/api/v1/notify/channels", tok, map[string]any{
		"id": id, "name": "SOC webhook", "kind": "webhook", "enabled": true,
		"config": map[string]any{"url": "ftp://nope/x"},
	})
	if code != http.StatusOK || out["warning"] == "" {
		t.Fatalf("配置非法应保存成功但带 warning: %d %v", code, out)
	}

	if code, _ := doJSON(t, f.h, "DELETE", "/api/v1/notify/channels/"+id, tok, nil); code != http.StatusOK {
		t.Fatalf("删除应 200")
	}
	if code, _ := doJSON(t, f.h, "DELETE", "/api/v1/notify/channels/"+id, tok, nil); code != http.StatusNotFound {
		t.Fatalf("重复删除应 404")
	}
}

// 改目的地即清凭据；不改目的地则一律不动。
//
// ★攻击面：SaveNotifyChannel 刻意不碰凭据表（改个显示名不该让告警发不出去），
// 于是持 PermSystem 的管理员带上**已有通道的 id** 把 SMTP 主机换成自己的机器，
// 再点一次「测试」，buildNotifyChannel 就会把解密后的企业邮箱口令以 AUTH PLAIN 送过去。
// AAD 绑 channel id 挡的是"密文跨记录剪贴"，挡不住"记录还在原地、目的地被换掉"。
func TestNotifyChannels_改目的地即清凭据(t *testing.T) {
	f := newNotifyFixture(t)
	tok := makeAdmin(t, f.h, "sys.admin", "system")
	url, _ := hookServer(t, http.StatusOK)
	id := createHookChannel(t, f, tok, "SOC webhook", url, true)

	// ① 只改显示名：凭据必须还在。
	code, out := doJSON(t, f.h, "POST", "/api/v1/notify/channels", tok, map[string]any{
		"id": id, "name": "SOC webhook（主）", "kind": "webhook", "enabled": true,
		"config": map[string]any{"url": url, "secretHeader": "Authorization", "timeoutSec": 5},
	})
	if code != http.StatusOK {
		t.Fatalf("改名 http %d: %v", code, out)
	}
	if out["secretCleared"] == true || out["channel"].(map[string]any)["hasSecret"] != true {
		t.Fatalf("只改显示名不该清凭据：%v", out)
	}

	// ② 把 URL 换成攻击者的地址：凭据必须当场清掉，且请求头里再也拿不到它。
	evilURL, evilGot := hookServer(t, http.StatusOK)
	code, out = doJSON(t, f.h, "POST", "/api/v1/notify/channels", tok, map[string]any{
		"id": id, "name": "SOC webhook（主）", "kind": "webhook", "enabled": true,
		"config": map[string]any{"url": evilURL, "secretHeader": "Authorization", "timeoutSec": 5},
	})
	if code != http.StatusOK {
		t.Fatalf("改 URL http %d: %v", code, out)
	}
	if out["secretCleared"] != true || out["channel"].(map[string]any)["hasSecret"] != false {
		t.Fatalf("改了目的地必须清凭据：%v", out)
	}
	// 现在去「测试」：应当因为"配了凭据头却没有凭据"而失败，且新地址收不到任何请求。
	code, out = doJSON(t, f.h, "POST", "/api/v1/notify/channels/"+id+"/test", tok, nil)
	if code != http.StatusOK || out["ok"] != false {
		t.Fatalf("凭据被清后测试应如实失败：%d %v", code, out)
	}
	for _, p := range evilGot() {
		if h, _ := p["_authHeader"].(string); h != "" {
			t.Fatalf("★换了目的地之后凭据仍被送了出去：%q", h)
		}
	}
	if !auditHasEvent(t, f.h, "原有凭据已一并清除") {
		t.Fatal("凭据被清这件事必须落审计")
	}
}

// ★「测试连接」必须真发，成功与失败都如实回报，并落进 last_* 四列。
func TestNotifyChannels_测试按钮真发不假成功(t *testing.T) {
	f := newNotifyFixture(t)
	tok := makeAdmin(t, f.h, "sys.admin", "system")

	okURL, okGot := hookServer(t, http.StatusOK)
	okID := createHookChannel(t, f, tok, "可用通道", okURL, true)
	badURL, _ := hookServer(t, http.StatusInternalServerError)
	badID := createHookChannel(t, f, tok, "对端报错的通道", badURL, true)

	code, out := doJSON(t, f.h, "POST", "/api/v1/notify/channels/"+okID+"/test", tok, nil)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("可用通道测试应成功: %d %v", code, out)
	}
	got := okGot()
	if len(got) != 1 {
		t.Fatalf("测试按钮应真的发出一次请求，实得 %d 次", len(got))
	}
	if got[0]["_authHeader"] != "Bearer tok-abc" {
		t.Errorf("凭据没被注入到配置的头上: %v", got[0]["_authHeader"])
	}
	if !strings.Contains(got[0]["subject"].(string), "测试") {
		t.Errorf("载荷主题 = %v", got[0]["subject"])
	}

	code, out = doJSON(t, f.h, "POST", "/api/v1/notify/channels/"+badID+"/test", tok, nil)
	if code != http.StatusOK || out["ok"] != false {
		t.Fatalf("★对端 500 却报成功：%d %v", code, out)
	}
	if !strings.Contains(out["detail"].(string), "500") {
		t.Errorf("失败详情应含对端状态码: %v", out["detail"])
	}

	// 两次结果都进 last_*，且是**真发那一次**的结果
	_, list := doJSON(t, f.h, "GET", "/api/v1/notify/channels", tok, nil)
	byID := map[string]map[string]any{}
	for _, it := range list["channels"].([]any) {
		m := it.(map[string]any)
		byID[m["id"].(string)] = m
	}
	if byID[okID]["lastStatus"] != "ok" || byID[okID]["lastEvent"] != "test" {
		t.Errorf("成功通道的 last_* = %v", byID[okID])
	}
	if byID[badID]["lastStatus"] != "fail" || !strings.Contains(byID[badID]["lastDetail"].(string), "500") {
		t.Errorf("失败通道的 last_* = %v", byID[badID])
	}
}

// ★真实消费方之一：账号被爆破锁定 → 通知真的发到了通道上。
func TestNotify_爆破锁定触发真实通知(t *testing.T) {
	f := newNotifyFixture(t)
	tok := makeAdmin(t, f.h, "sys.admin", "system")
	url, got := hookServer(t, http.StatusOK)
	createHookChannel(t, f, tok, "SOC webhook", url, true)
	// 关掉的那条不该收到任何东西——enabled 是有真实消费方的开关，不是摆设。
	offURL, offGot := hookServer(t, http.StatusOK)
	createHookChannel(t, f, tok, "已停用通道", offURL, false)

	// 关 IP 维度，只留账号锁（httptest 全部同源 IP）
	cfg := map[string]any{"threshold": 3, "windowSec": 600, "durationSec": 900,
		"ipEnabled": false, "accountEnabled": true}
	if code, out := doJSON(t, f.h, "PUT", "/api/v1/security/lockout-config", adminToken(), cfg); code != http.StatusOK {
		t.Fatalf("保存防爆破配置 http %d: %v", code, out)
	}
	wrong := map[string]string{"username": "li.fang", "password": "wrong-pw"}
	for i := 0; i < 3; i++ {
		doJSON(t, f.h, "POST", "/api/v1/portal/login", "", wrong)
	}
	f.srv.notices.Wait()

	sent := got()
	if len(sent) != 1 {
		t.Fatalf("锁定应触发 1 条通知，实得 %d 条", len(sent))
	}
	subj := sent[0]["subject"].(string)
	body := sent[0]["body"].(string)
	if !strings.Contains(subj, "登录防爆破锁定") || !strings.Contains(subj, "li.fang") {
		t.Errorf("通知主题 = %q", subj)
	}
	// 措辞只记已发生的事实：说"已建立临时锁定"，不说"已封禁账号"之类没发生的动作。
	if !strings.Contains(body, "已建立临时锁定") || !strings.Contains(body, "锁定至") {
		t.Errorf("通知正文 = %q", body)
	}
	if len(offGot()) != 0 {
		t.Errorf("★已停用的通道也收到了通知：enabled 开关没有消费方")
	}

	// 发送成功要留痕（审计 + last_*）
	_, ab := doJSON(t, f.h, "GET", "/api/v1/audit", adminToken(), nil)
	foundOK := false
	for _, it := range ab["logs"].([]any) {
		m := it.(map[string]any)
		if strings.Contains(m["event"].(string), "安全事件通知已发出") && m["verdict"] == "ok" {
			foundOK = true
			if m["user"] != "system" {
				t.Errorf("后台通知的行为人应记 system，实得 %v", m["user"])
			}
		}
	}
	if !foundOK {
		t.Error("发送成功应落审计")
	}
}

// ★通知发送失败不阻塞主流程，且失败要落审计。
//
// 通道指向一个装死的对端：登录接口必须**照常**在毫秒级返回、锁定必须照常生效，
// 只有通知这一路慢——它是观测通道，不是执行通道。
func TestNotify_发送失败不阻塞主流程且落审计(t *testing.T) {
	f := newNotifyFixture(t)
	tok := makeAdmin(t, f.h, "sys.admin", "system")

	block := make(chan struct{})
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// 清理是 LIFO：先放行 handler，再关服务端。
	t.Cleanup(dead.Close)
	t.Cleanup(func() { close(block) })

	code, out := doJSON(t, f.h, "POST", "/api/v1/notify/channels", tok, map[string]any{
		"name": "装死的通道", "kind": "webhook", "enabled": true,
		"config": map[string]any{"url": dead.URL, "timeoutSec": 1},
	})
	if code != http.StatusOK {
		t.Fatalf("建通道 http %d: %v", code, out)
	}

	cfg := map[string]any{"threshold": 2, "windowSec": 600, "durationSec": 900,
		"ipEnabled": false, "accountEnabled": true}
	doJSON(t, f.h, "PUT", "/api/v1/security/lockout-config", adminToken(), cfg)

	wrong := map[string]string{"username": "li.fang", "password": "wrong-pw"}
	doJSON(t, f.h, "POST", "/api/v1/portal/login", "", wrong)
	start := time.Now()
	doJSON(t, f.h, "POST", "/api/v1/portal/login", "", wrong) // 这一次触发锁定 + 通知
	if el := time.Since(start); el > 900*time.Millisecond {
		t.Fatalf("★登录接口被通知发送拖住了 %v——一台连不上的通道会变成拒绝服务面", el)
	}
	// 锁定本身照常生效（通知发不出去不改变任何安全结论）
	if code, _ := doJSON(t, f.h, "POST", "/api/v1/portal/login", "", wrong); code != http.StatusForbidden {
		t.Fatalf("锁定应照常生效，实得 %d", code)
	}

	f.srv.notices.Wait()
	_, ab := doJSON(t, f.h, "GET", "/api/v1/audit", adminToken(), nil)
	foundFail := false
	for _, it := range ab["logs"].([]any) {
		m := it.(map[string]any)
		if strings.Contains(m["event"].(string), "安全事件通知发送失败") && m["verdict"] == "fail" {
			foundFail = true
		}
	}
	if !foundFail {
		t.Fatal("★发送失败没有落审计：'你以为已经通知到了、其实没有'就再无痕迹")
	}
	// 失败结果也进 last_*
	_, list := doJSON(t, f.h, "GET", "/api/v1/notify/channels", tok, nil)
	c := list["channels"].([]any)[0].(map[string]any)
	if c["lastStatus"] != "fail" {
		t.Errorf("失败没落进 last_*: %v", c)
	}
}

// ★真实消费方之二：终端判定转入 block 时发通知，且**只在转入那一次**发。
func TestNotify_终端判block只在转入时通知一次(t *testing.T) {
	f := newNotifyFixture(t)
	tok := makeAdmin(t, f.h, "sys.admin", "system")
	url, got := hookServer(t, http.StatusOK)
	createHookChannel(t, f, tok, "SOC webhook", url, true)

	utok := userToken("zhang.san")
	bad := map[string]any{
		"device": "MBP-01", "platform": "macOS", "os": "macOS 15", "clientVersion": "1.0.0",
		"checks": []map[string]any{{"key": "disk_encrypted", "ok": false}},
	}
	if code, out := doJSON(t, f.h, "POST", "/api/v1/posture", utok, bad); code != http.StatusOK {
		t.Fatalf("posture 上报 http %d: %v", code, out)
	}
	f.srv.notices.Wait()
	// ★不写成 t.Skip：一条"条件不满足就悄悄跳过"的用例，等同于没有这条用例。
	// 种子基线把 disk_encrypted（severity=high）判成 block，这是本用例的前提。
	first := got()
	if len(first) != 1 {
		t.Fatalf("转入 block 应发 1 条，实得 %d", len(first))
	}
	if !strings.Contains(first[0]["subject"].(string), "终端不合规") {
		t.Errorf("通知主题 = %v", first[0]["subject"])
	}

	// 同一台设备再报一次同样的不合规：状态没变，不该再发。
	doJSON(t, f.h, "POST", "/api/v1/posture", utok, bad)
	f.srv.notices.Wait()
	if n := len(got()); n != 1 {
		t.Fatalf("★状态未变化却又发了通知（%d 条）：按上报频率会把管理员邮箱刷爆", n)
	}
}
