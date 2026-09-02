package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// webGWHost 测试网关显式 bind 的对外可达地址（TEST-NET-2）。
//
// ★不能再用 127.0.0.1：入口推导对回环/通配地址现在如实报「无法确定」而不是签票
// （见 webHostUnroutable），而参考部署里网关正是 `-spa :18201 -web 127.0.0.1:18444`。
// 这里给网关一个显式可达的 bind 地址，等价于「少数部署直接 bind 公网 IP」那条路。
const webGWHost = "198.51.100.7"

// registerWebGateway 让一台带七层落点的网关上线（走真实的注册端点，
// 而不是直接改 s.gateways——注册报文的字段名对不上是这类改动最常见的失败形态）。
func registerWebGateway(t *testing.T, h http.Handler, web string, tlsOn bool) {
	t.Helper()
	body := map[string]any{"id": "gw-1", "proxy": webGWHost + ":18443", "spa": webGWHost + ":18201"}
	if web != "" {
		body["web"] = web
		body["webTls"] = tlsOn
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), body); code != http.StatusOK {
		t.Fatalf("网关注册 http %d", code)
	}
}

// ticketClaims 把签出来的入口 URL 拆回 Claims（用 control 自己的密钥验——
// 这同时证明票确实是 control 签的，而不是拼了个字符串）。
func ticketClaims(t *testing.T, entryURL string) auth.Claims {
	t.Helper()
	u, err := url.Parse(entryURL)
	if err != nil {
		t.Fatalf("入口 URL 非法: %v", err)
	}
	if u.Path != webEntryPath {
		t.Fatalf("入口路径必须与网关侧逐字一致，得 %q", u.Path)
	}
	c, err := testKeys.Verify(u.Query().Get("t"))
	if err != nil {
		t.Fatalf("票据应可被 control 公钥验证: %v", err)
	}
	return c
}

// 正路：门户用户点开一个 Web 应用 → 拿到 60s 一次性、绑定到该资源的票据。
func TestWebTicketHappyPath(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)

	code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
		map[string]string{"appId": "a1"})
	if code != http.StatusOK {
		t.Fatalf("有权限的 Web 应用应签出票据，得 %d %v", code, out)
	}
	entry, _ := out["url"].(string)
	if !strings.HasPrefix(entry, "http://"+webGWHost+":18444"+webEntryPath+"?t=") {
		t.Fatalf("入口 URL 应指向网关自报的七层落点（host 取自显式 bind 的 SPA 地址），得 %q", entry)
	}
	c := ticketClaims(t, entry)
	if c.Use != auth.UseWeb {
		t.Fatalf("票据用途必须是 web（否则会被网关的用途闸拒），得 %q", c.Use)
	}
	if c.Res != "oa" {
		t.Fatalf("票据必须绑定到具体资源，得 %q", c.Res)
	}
	if c.Jti == "" {
		t.Fatal("票据必须带 jti（一次性去重的依据）")
	}
	if ttl := c.Exp - c.Iat; ttl != int64(webTicketTTL.Seconds()) {
		t.Fatalf("票据寿命应为 %s，得 %ds", webTicketTTL, ttl)
	}
	if c.Name != "li.fang" {
		t.Fatalf("票据主体必须是规范化账号（网关按它逐请求鉴权），得 %q", c.Name)
	}
}

// ★网关没开七层就如实说没开——绝不拼一个连不上的地址发出去。
// 那种"地址给了、就是打不开"的形态会让人去查浏览器、查网络、查证书，
// 而真正要做的只是给网关加一个 -web。
func TestWebTicketWithoutGatewayWebListener(t *testing.T) {
	h := newTestServer(t)
	for name, setup := range map[string]func(){
		"无网关在线":     func() {},
		"网关在线但没开七层": func() { registerWebGateway(t, h, "", false) },
	} {
		t.Run(name, func(t *testing.T) {
			setup()
			code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
				map[string]string{"appId": "a1"})
			if code != http.StatusServiceUnavailable {
				t.Fatalf("应回 503 并说明原因，得 %d %v", code, out)
			}
		})
	}
	// 门户磁贴同批拿到同一个结论，前端据此把「访问」按钮置灰而不是让人点了才知道。
	code, out := doJSON(t, h, "GET", "/api/v1/portal/apps", userToken("li.fang"), nil)
	if code != http.StatusOK {
		t.Fatalf("门户应用清单 http %d", code)
	}
	wp, _ := out["webProxy"].(map[string]any)
	if wp == nil || wp["ready"] != false || wp["note"] == "" {
		t.Fatalf("门户应如实下发七层入口状态与原因，得 %v", out["webProxy"])
	}
}

// 授权闸：无权访问的资源不签票。判定与剖面同一入口（accessibleFor），
// 下面 TestWebTicketMatchesProfileAccessibility 钉住两者同真同假。
func TestWebTicketDeniedWithoutAuthorization(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)
	// a2 = 财务核算系统（资源 finance，allowRoles=[admin]，高敏）
	code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
		map[string]string{"appId": "a2"})
	if code != http.StatusForbidden {
		t.Fatalf("无授权应 403，得 %d %v", code, out)
	}
}

// 非 Web 应用、未关联资源、已停用、不存在——四种都当面报清楚，
// 而不是签一张网关必然拒收的票（那的症状是"点了没反应"）。
func TestWebTicketRejectsNonWebApps(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)
	// 造一个「Web 模式但没关联受控资源」的应用——种子里的 a4 是 tunnel 模式，
	// 模式闸会先命中，测不到"未桥接资源"这一条（而它恰恰是本项目栽过的那个洞）。
	if code, out := doJSON(t, h, "POST", "/api/v1/apps", adminToken(), map[string]any{
		"name": "未桥接的 Web 应用", "addr": "10.20.7.7:80", "mode": "web",
		"category": "office", "status": "running",
	}); code != http.StatusCreated {
		t.Fatalf("建应用 http %d %v", code, out)
	}
	unlinked := ""
	{
		_, out := doJSON(t, h, "GET", "/api/v1/apps", adminToken(), nil)
		apps, _ := out["apps"].([]any)
		for _, a := range apps {
			m, _ := a.(map[string]any)
			if m["name"] == "未桥接的 Web 应用" {
				unlinked, _ = m["id"].(string)
			}
		}
		if unlinked == "" {
			t.Fatal("没找到刚建的应用")
		}
	}
	cases := map[string]struct {
		appID string
		want  int
	}{
		"隧道模式应用":  {"a3", http.StatusBadRequest},
		"未关联受控资源": {unlinked, http.StatusConflict},
		"已停用":     {"a5", http.StatusConflict},
		"全局加速":    {"a6", http.StatusBadRequest},
		"不存在":     {"nope", http.StatusNotFound},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
				map[string]string{"appId": c.appID})
			if code != c.want {
				t.Fatalf("应回 %d，得 %d %v", c.want, code, out)
			}
		})
	}
}

// 三道账号闸对 B/S 与 C/S 是**同一段代码**：禁用的账号两条路都进不来。
// 少了这条，"已禁用的人换浏览器还能进"会是一个无报错的洞。
func TestWebTicketSharesEntryGatesWithKnock(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)
	disabled := userToken("ext.zhou") // 种子里 u5 状态为 disabled
	for path, body := range map[string]any{
		"/api/v1/portal/web-ticket": map[string]string{"appId": "a1"},
		"/api/v1/knock-token":       map[string]string{},
	} {
		code, out := doJSON(t, h, "POST", path, disabled, body)
		if code != http.StatusForbidden {
			t.Fatalf("%s：禁用账号必须被拒，得 %d %v", path, code, out)
		}
	}
}

// ★跨出口同构：同一个用户、同一个资源，「剖面里排不排得出这个应用」与
// 「签不签得出票据」必须同真同假。分叉的两个方向都很难查——
// 门户点得开而网关照拒，或者门户不给点其实有权限。
func TestWebTicketMatchesProfileAccessibility(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)
	admin := adminToken()
	tok := userToken("li.fang")

	inProfile := func() bool {
		code, out := doJSON(t, h, "GET", "/api/v1/client/profile", tok, nil)
		if code != http.StatusOK {
			t.Fatalf("剖面 http %d", code)
		}
		apps, _ := out["apps"].([]any)
		for _, a := range apps {
			m, _ := a.(map[string]any)
			if m["id"] == "a1" {
				acc, _ := m["accessible"].(bool)
				return acc
			}
		}
		return false
	}
	ticketOK := func() bool {
		code, _ := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", tok, map[string]string{"appId": "a1"})
		return code == http.StatusOK
	}

	if !inProfile() || !ticketOK() {
		t.Fatal("初始状态：剖面与票据都应可访问")
	}
	// 把 oa 的 ACL 收紧到别人身上
	if code, out := doJSON(t, h, "POST", "/api/v1/resources", admin, map[string]any{
		"id": "oa", "name": "OA 协同办公", "backend": "10.20.1.10:8080",
		"allowUsers": []string{"someone-else"},
	}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("改资源 http %d %v", code, out)
	}
	if inProfile() || ticketOK() {
		t.Fatal("★收回授权后：剖面与票据必须同时翻假")
	}
}

// 对外入口覆盖：管理员给某个应用配了专属域名时，票据跳到那个域名。
// 同时钉住非法取值当面被拒——带路径的入口会让浏览器跳到一个 404，两侧日志都正常。
func TestWebEntryOverrideAndValidation(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)
	admin := adminToken()
	base := map[string]any{"id": "oa", "name": "OA 协同办公", "backend": "10.20.1.10:8080",
		"allowRoles": []string{"admin", "user"}}

	save := func(extra map[string]any) int {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		for k, v := range extra {
			body[k] = v
		}
		code, _ := doJSON(t, h, "POST", "/api/v1/resources", admin, body)
		return code
	}
	for name, bad := range map[string]map[string]any{
		"入口带路径":        {"webEntry": "https://oa.corp.example/base"},
		"入口协议不对":       {"webEntry": "ftp://oa.corp.example"},
		"入口缺主机":        {"webEntry": "https://"},
		"webScheme 拼错": {"webScheme": "tls"},
	} {
		t.Run(name, func(t *testing.T) {
			if code := save(bad); code != http.StatusBadRequest {
				t.Fatalf("非法取值应 400，得 %d", code)
			}
		})
	}
	if code := save(map[string]any{"webEntry": "https://oa.corp.example", "webScheme": "https"}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("合法取值应保存成功，得 %d", code)
	}
	code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
		map[string]string{"appId": "a1"})
	if code != http.StatusOK {
		t.Fatalf("应签出票据，得 %d %v", code, out)
	}
	if entry, _ := out["url"].(string); !strings.HasPrefix(entry, "https://oa.corp.example"+webEntryPath) {
		t.Fatalf("应跳到管理员配置的专属入口，得 %q", entry)
	}
}

// 后端协议是**拨号参数**，必须真的下发到网关——不下发的话网关只能按端口猜，
// 而 8443 上的 HTTPS 应用会被当成 http 去撞，症状是一个空白页。
func TestGatewayPolicyCarriesWebScheme(t *testing.T) {
	h := newTestServer(t)
	admin := adminToken()
	if code, out := doJSON(t, h, "POST", "/api/v1/resources", admin, map[string]any{
		"id": "sec-app", "name": "内网 HTTPS 应用", "backend": "10.20.9.9:8443",
		"allowRoles": []string{"user"},
	}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("建资源 http %d %v", code, out)
	}
	code, out := doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("拉策略 http %d", code)
	}
	rs, _ := out["resources"].([]any)
	var got string
	for _, r := range rs {
		m, _ := r.(map[string]any)
		if m["id"] == "sec-app" {
			got, _ = m["webScheme"].(string)
		}
	}
	if got != store.WebSchemeHTTPS {
		t.Fatalf("8443 后端应按 https 下发（回填/归一只有一处定义），得 %q", got)
	}
}

// ★L7 访问票据不得当控制面会话令牌用。
//
// 退回旧实现（中间件只拦 pwreset）这条用例立刻红：Keys.Verify 按 kid 同时认
// sess/knock/web 三把公钥，于是一张本该"只开一扇门 60s"的资源级票据等价于该账号
// 60s 的全量 API 会话——admin 的票就是 60s 全权管理台，还能拿它再调一次
// /portal/web-ticket 自我续签，把"短时效"结构性抵消掉。
func TestDataplaneTicketsRejectedOnControlPlane(t *testing.T) {
	h := newTestServer(t)
	for name, c := range map[string]auth.Claims{
		"Web 访问票据": {Sub: "admin", Role: "admin", Name: "admin", Jti: "j1", Use: auth.UseWeb, Res: "oa"},
		"敲门令牌":     {Sub: "admin", Role: "admin", Name: "admin", Jti: "j2", Use: auth.UseKnock},
	} {
		t.Run(name, func(t *testing.T) {
			tok := testKeys.Sign(c, time.Minute)
			for _, ep := range []struct{ method, path string }{
				{"GET", "/api/v1/users"},
				{"GET", "/api/v1/auth/me"},
				{"GET", "/api/v1/client/profile"},
				{"POST", "/api/v1/portal/web-ticket"}, // 自我续签这条路要一并堵死
				{"POST", "/api/v1/knock-token"},
			} {
				code, body := doRaw(t, h, ep.method, ep.path, tok)
				if code != http.StatusForbidden {
					t.Fatalf("★%s 调 %s %s 必须 403，得 %d %s", name, ep.method, ep.path, code, body)
				}
			}
		})
	}
	// 对照：正常会话令牌照常可用（否则上面的 403 可能只是把所有人都挡住了）
	if code, _ := doJSON(t, h, "GET", "/api/v1/auth/me", userToken("li.fang"), nil); code != http.StatusOK {
		t.Fatalf("正常会话令牌应可用，得 %d", code)
	}
}

// 票据要绑定到算出入口的那台网关：数据面的一次性去重是每台网关自己的内存，
// 不带网关维度的话，同一张票在每台装了 web 公钥的网关上都能各换一次会话。
func TestWebTicketBoundToChosenGateway(t *testing.T) {
	h := newTestServer(t)
	registerWebGateway(t, h, "0.0.0.0:18444", false)
	code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
		map[string]string{"appId": "a1"})
	if code != http.StatusOK {
		t.Fatalf("取票 http %d %v", code, out)
	}
	c := ticketClaims(t, out["url"].(string))
	if c.Gw != "gw-1" {
		t.Fatalf("★票据必须绑定算出入口的那台网关，得 %q", c.Gw)
	}
}

// 混合版本集群：只有开了七层的那台才是候选。
//
// 退回旧实现（按 LastSeen 取最大再判有没有开七层）这条会**随机**失败——
// 那正是现网症状：同一份配置下 Web 磁贴时能点时不能点。
func TestWebEntryPicksOnlyGatewaysWithWebListener(t *testing.T) {
	h := newTestServer(t)
	// gw-old 没开七层（旧版网关连 web 键都不发），gw-web 开了
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		map[string]any{"id": "gw-old", "proxy": webGWHost + ":18443", "spa": webGWHost + ":18201"}); code != http.StatusOK {
		t.Fatal("注册 gw-old 失败")
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		map[string]any{"id": "gw-web", "proxy": webGWHost + ":18453", "spa": webGWHost + ":18211",
			"web": "0.0.0.0:18444"}); code != http.StatusOK {
		t.Fatal("注册 gw-web 失败")
	}
	// 两台心跳落在同一秒是常态（Unix 秒 + 15s 周期），跑多次不允许有一次落到没开七层的那台
	for i := 0; i < 20; i++ {
		code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
			map[string]string{"appId": "a1"})
		if code != http.StatusOK {
			t.Fatalf("★第 %d 次取票被拒（候选没按七层能力过滤）：%d %v", i+1, code, out)
		}
		if c := ticketClaims(t, out["url"].(string)); c.Gw != "gw-web" {
			t.Fatalf("★第 %d 次选中了没开七层的网关 %q", i+1, c.Gw)
		}
	}
}

// ── 七层入口主机名改读管理员登记的对外接入地址（wave9，web-entry-base）──
//
// 缺陷原样：webEntryBase 的优先级是 资源 WebEntry → BAIDI_WEB_ENTRY_BASE → 网关自报监听
// 地址的 host（空/通配时退 SPA host，再退 BAIDI_CLIENT_GW_HOST 默认 127.0.0.1），
// **不读** wave8 行动 4 给剖面补的管理员登记接入地址。参考部署 `-spa :18201` +
// `BAIDI_GW_WEB=127.0.0.1:18444` 下票据 URL 是 http://127.0.0.1:18444/__baidi/enter，
// 而 webProxyStatus 照报 ready=true——浏览器被指向自己、零报错。

// registerLoopbackWebGateway 复刻参考部署形态：七层**显式绑回环**、SPA 通配监听（不带 host）。
// 这种形态下登记地址 + 自报端口组合不出一个有人监听的地址，只有前置入口能救。
func registerLoopbackWebGateway(t *testing.T, h http.Handler, id string) {
	t.Helper()
	registerWebGatewayListening(t, h, id, "127.0.0.1:18444")
}

// registerWildcardWebGateway 七层**通配监听**（不带 host）：这才是「登记地址 + 自报端口」成立的形态。
func registerWildcardWebGateway(t *testing.T, h http.Handler, id string) {
	t.Helper()
	registerWebGatewayListening(t, h, id, ":18444")
}

func registerWebGatewayListening(t *testing.T, h http.Handler, id, web string) {
	t.Helper()
	if code, out := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		map[string]any{"id": id, "proxy": ":18443", "spa": ":18201", "web": web}); code != http.StatusOK {
		t.Fatalf("网关 %s 注册 http %d: %v", id, code, out)
	}
}

func webTicketURL(t *testing.T, h http.Handler) (int, string, map[string]any) {
	t.Helper()
	code, out := doJSON(t, h, "POST", "/api/v1/portal/web-ticket", userToken("li.fang"),
		map[string]string{"appId": "a1"})
	u, _ := out["url"].(string)
	return code, u, out
}

// 用例①：网关七层通配监听 + 管理员登记了对外接入地址 → 票据 URL 用登记地址（端口仍取自报监听）。
// 撤掉 webEntryBase 里「登记地址」那一档，这条会红（回落到空 host → SPA host 也空 → 兜底
// 127.0.0.1 被回环判据拒成 503）。
// ★夹具必须是通配监听（`:18444`）而不是回环：回环绑定 + 登记地址是另一条用例里的**反例**。
func TestWebEntryUsesRegisteredGatewayAccess(t *testing.T) {
	h := newTestServer(t)
	registerWildcardWebGateway(t, h, "gw-1")
	if code, out := doJSON(t, h, "PUT", "/api/v1/gateway/gw-1/access", adminToken(),
		map[string]any{"lanHost": "", "wanHost": "gw.example.com"}); code != http.StatusOK {
		t.Fatalf("登记接入地址 http %d: %v", code, out)
	}
	code, entry, out := webTicketURL(t, h)
	if code != http.StatusOK {
		t.Fatalf("★登记了接入地址就该签出票据，得 %d %v", code, out)
	}
	if !strings.HasPrefix(entry, "http://gw.example.com:18444"+webEntryPath+"?t=") {
		t.Fatalf("★入口 URL 应用管理员登记的接入地址 + 自报七层端口，得 %q", entry)
	}
	// 走登记地址时控制面确切知道票会落到哪台网关，票据照样钉网关（一次性去重是每台各自做的）。
	if c := ticketClaims(t, entry); c.Gw != "gw-1" {
		t.Fatalf("经登记地址下发的票据仍应绑定该网关，得 %q", c.Gw)
	}
	// 门户状态同源：登记之后就绪。
	_, apps := doJSON(t, h, "GET", "/api/v1/portal/apps", userToken("li.fang"), nil)
	if wp, _ := apps["webProxy"].(map[string]any); wp == nil || wp["ready"] != true {
		t.Fatalf("登记接入地址后门户应报七层入口就绪，得 %v", apps["webProxy"])
	}

	// 两栏都登记：内网栏优先，与剖面「内网在前」同序（顺序不确定会让入口主机名在两栏之间乱跳）。
	if code, out := doJSON(t, h, "PUT", "/api/v1/gateway/gw-1/access", adminToken(),
		map[string]any{"lanHost": "gw.corp.internal", "wanHost": "gw.example.com"}); code != http.StatusOK {
		t.Fatalf("登记两栏 http %d: %v", code, out)
	}
	if _, entry, _ := webTicketURL(t, h); !strings.HasPrefix(entry, "http://gw.corp.internal:18444"+webEntryPath) {
		t.Fatalf("两栏都登记时应取内网栏（与剖面同序），得 %q", entry)
	}
}

// 用例②：无登记 + 监听回环 → 门户状态非 ready、取票 503，且两处原因是同一句话。
// 撤掉 webHostUnroutable 那道判据，这条会红（签出一张指向 127.0.0.1 的票、状态照报 ready）。
func TestWebEntryLoopbackIsNotReady(t *testing.T) {
	for name, web := range map[string]string{
		"七层监听回环":     "127.0.0.1:18444",
		"七层监听通配":     "0.0.0.0:18444",
		"七层监听不带host": ":18444",
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestServer(t)
			if code, out := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
				map[string]any{"id": "gw-1", "proxy": ":18443", "spa": ":18201", "web": web}); code != http.StatusOK {
				t.Fatalf("网关注册 http %d: %v", code, out)
			}
			code, entry, out := webTicketURL(t, h)
			if code != http.StatusServiceUnavailable {
				t.Fatalf("★入口 host 推导成回环/通配时不得签票（拿到的是 %q），得 %d %v", entry, code, out)
			}
			errObj, _ := out["error"].(map[string]any)
			msg, _ := errObj["message"].(string)
			if !strings.HasPrefix(msg, webEntryUnresolvedPrefix) {
				t.Fatalf("★取票被拒必须带出补救路径，得 %q", msg)
			}
			if !strings.Contains(msg, "127.0.0.1") && !strings.Contains(msg, "0.0.0.0") && !strings.Contains(msg, `""`) {
				t.Fatalf("拒绝原因应写出此刻推导出的地址，得 %q", msg)
			}
			// 补救路径按形态给：显式绑回环时「登记接入地址」救不了它，文案不能照抄那一句；
			// 通配/不带 host 时两条路都真能救。
			if web == "127.0.0.1:18444" {
				if strings.Contains(msg, "请在网关页登记对外接入地址") || !strings.Contains(msg, "BAIDI_WEB_ENTRY_BASE") {
					t.Fatalf("★七层显式绑回环时补救路径只有前置入口，不得建议登记接入地址，得 %q", msg)
				}
			} else if !strings.HasPrefix(msg, webEntryUnresolvedMsg) {
				t.Fatalf("通配监听时两条补救路径都成立，文案应是整句 webEntryUnresolvedMsg，得 %q", msg)
			}
			_, apps := doJSON(t, h, "GET", "/api/v1/portal/apps", userToken("li.fang"), nil)
			wp, _ := apps["webProxy"].(map[string]any)
			if wp == nil || wp["ready"] != false {
				t.Fatalf("★入口地址无法确定时门户不得报 ready，得 %v", apps["webProxy"])
			}
			if note, _ := wp["note"].(string); note != msg {
				t.Fatalf("门户 note 与取票 503 必须是同一句话（同一判据），得\n  note=%q\n  503 =%q", note, msg)
			}
		})
	}
}

// 反例（复核补）：七层**显式绑回环** + 管理员登记了接入地址 → 仍不就绪、仍拒签，且原因点名回环监听。
//
// 第一版第 3 档只看「登记地址是否存在」：参考部署 `BAIDI_GW_WEB=127.0.0.1:18444` 的管理员为了让
// C/S 客户端连得上去网关页登记了 gw.example.com 之后，webEntryBase 算出 http://gw.example.com:18444、
// 门户报就绪、审计记「签发 Web 访问票据」——而网关的 L7 只 bind 在 127.0.0.1，那个地址上什么都
// 没在听。撤掉 webEntryBase 里 webListenLoopback 那道闸，这条会红（签出票、状态报 ready）。
func TestWebEntryLoopbackListenerRejectsRegisteredAccess(t *testing.T) {
	h := newTestServer(t)
	registerLoopbackWebGateway(t, h, "gw-1")
	if code, out := doJSON(t, h, "PUT", "/api/v1/gateway/gw-1/access", adminToken(),
		map[string]any{"lanHost": "", "wanHost": "gw.example.com"}); code != http.StatusOK {
		t.Fatalf("登记接入地址 http %d: %v", code, out)
	}
	code, entry, out := webTicketURL(t, h)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("★七层只监听回环时登记地址上没有服务，不得签票（拿到的是 %q），得 %d %v", entry, code, out)
	}
	errObj, _ := out["error"].(map[string]any)
	msg, _ := errObj["message"].(string)
	if !strings.HasPrefix(msg, webEntryUnresolvedPrefix) {
		t.Fatalf("拒绝文案应以固定开头起，得 %q", msg)
	}
	for _, want := range []string{"gw-1", "127.0.0.1:18444", "gw.example.com", "BAIDI_WEB_ENTRY_BASE"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("★拒绝原因必须点名网关、回环监听地址、登记地址与真正的补救路径（缺 %q），得 %q", want, msg)
		}
	}
	if strings.Contains(msg, "请在网关页登记对外接入地址") {
		t.Fatalf("★管理员已经登记了，再让他去登记是把人指去一条走不通的路，得 %q", msg)
	}
	_, apps := doJSON(t, h, "GET", "/api/v1/portal/apps", userToken("li.fang"), nil)
	wp, _ := apps["webProxy"].(map[string]any)
	if wp == nil || wp["ready"] != false {
		t.Fatalf("★七层显式绑回环时门户不得报 ready，得 %v", apps["webProxy"])
	}
	if note, _ := wp["note"].(string); note != msg {
		t.Fatalf("门户 note 与取票 503 必须是同一句话，得\n  note=%q\n  503 =%q", note, msg)
	}
	// 同一台网关改成通配监听（重新注册覆盖），登记地址立刻成立——两种形态分得开、且只差这一处。
	registerWildcardWebGateway(t, h, "gw-1")
	if code, entry, out := webTicketURL(t, h); code != http.StatusOK || !strings.HasPrefix(entry, "http://gw.example.com:18444"+webEntryPath) {
		t.Fatalf("改成通配监听后登记地址 + 自报端口应成立，得 %d %q %v", code, entry, out)
	}
}

// 用例③：显式 BAIDI_WEB_ENTRY_BASE 仍优先于登记地址（顺序不变），且统一入口下票不绑网关。
// 资源级 WebEntry 又优先于环境变量——三档顺序一并钉住。
// 夹具刻意用**回环绑定**的网关：显式统一入口是回环绑定的唯一正确出路，它不受回环闸约束。
func TestWebEntryExplicitBaseBeatsRegisteredAccess(t *testing.T) {
	h := newTestServer(t)
	registerLoopbackWebGateway(t, h, "gw-1")
	if code, out := doJSON(t, h, "PUT", "/api/v1/gateway/gw-1/access", adminToken(),
		map[string]any{"wanHost": "gw.example.com"}); code != http.StatusOK {
		t.Fatalf("登记接入地址 http %d: %v", code, out)
	}
	t.Setenv("BAIDI_WEB_ENTRY_BASE", "https://portal.example.com/")
	code, entry, out := webTicketURL(t, h)
	if code != http.StatusOK {
		t.Fatalf("取票 http %d %v", code, out)
	}
	if !strings.HasPrefix(entry, "https://portal.example.com"+webEntryPath+"?t=") {
		t.Fatalf("★显式 BAIDI_WEB_ENTRY_BASE 应优先于登记地址，得 %q", entry)
	}
	if c := ticketClaims(t, entry); c.Gw != "" {
		t.Fatalf("统一入口下控制面不知道票会落到哪台网关，不该绑 gw，得 %q", c.Gw)
	}
	// 资源级覆盖压过环境变量
	if code, _ := doJSON(t, h, "POST", "/api/v1/resources", adminToken(), map[string]any{
		"id": "oa", "name": "OA 协同办公", "backend": "10.20.1.10:8080",
		"allowRoles": []string{"admin", "user"}, "webEntry": "https://oa.corp.example"}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("保存资源 http %d", code)
	}
	if _, entry, _ := webTicketURL(t, h); !strings.HasPrefix(entry, "https://oa.corp.example"+webEntryPath) {
		t.Fatalf("资源级 WebEntry 应优先于 BAIDI_WEB_ENTRY_BASE，得 %q", entry)
	}
}

// 监听形态判据：只认「显式绑回环」；空/通配是「所有接口都听」，与回环走相反的分支。
func TestWebListenLoopback(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.8.8.8": true, "::1": true, "localhost": true, "LOCALHOST": true,
		"": false, "  ": false, "0.0.0.0": false, "::": false,
		"10.0.0.5": false, "gw.example.com": false,
	} {
		if got := webListenLoopback(host); got != want {
			t.Errorf("webListenLoopback(%q)=%v, want %v", host, got, want)
		}
	}
}

// 判据本身：只拦「必然不通」的形态；内网 IP / 域名放行（控制面无从知道浏览器在哪一侧）。
func TestWebHostUnroutable(t *testing.T) {
	for host, want := range map[string]bool{
		"": true, "  ": true, "0.0.0.0": true, "::": true, "127.0.0.1": true, "127.8.8.8": true,
		"::1": true, "localhost": true, "LOCALHOST": true,
		"10.0.0.5": false, "198.51.100.7": false, "gw.example.com": false, "fd00::1": false,
	} {
		if got := webHostUnroutable(host); got != want {
			t.Errorf("webHostUnroutable(%q)=%v, want %v", host, got, want)
		}
	}
}
