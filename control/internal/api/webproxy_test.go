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

// registerWebGateway 让一台带七层落点的网关上线（走真实的注册端点，
// 而不是直接改 s.gateways——注册报文的字段名对不上是这类改动最常见的失败形态）。
func registerWebGateway(t *testing.T, h http.Handler, web string, tlsOn bool) {
	t.Helper()
	body := map[string]any{"id": "gw-1", "proxy": "127.0.0.1:18443", "spa": "127.0.0.1:18201"}
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
	if !strings.HasPrefix(entry, "http://127.0.0.1:18444"+webEntryPath+"?t=") {
		t.Fatalf("入口 URL 应指向网关自报的七层落点，得 %q", entry)
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
		map[string]any{"id": "gw-old", "proxy": "127.0.0.1:18443", "spa": "127.0.0.1:18201"}); code != http.StatusOK {
		t.Fatal("注册 gw-old 失败")
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(),
		map[string]any{"id": "gw-web", "proxy": "127.0.0.1:18453", "spa": "127.0.0.1:18211",
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
