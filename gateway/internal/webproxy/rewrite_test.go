package webproxy

import (
	"net/http"
	"testing"
)

// 进站的来源声明类头必须**一条不剩**地被剥掉。信任它们等于让任何人伪造来源 IP，
// 而伪造成功后后端日志与风控看起来完全正常。
func TestStripInboundHops(t *testing.T) {
	h := http.Header{}
	h.Add("X-Forwarded-For", "1.2.3.4")
	h.Add("X-Forwarded-For", "5.6.7.8") // 多值也要清干净
	h.Set("x-real-ip", "1.2.3.4")       // 大小写不敏感
	h.Set("Forwarded", "for=1.2.3.4")
	h.Set("X-Forwarded-Host", "evil.example")
	h.Set("X-Forwarded-Proto", "https")
	h.Set("X-Baidi-User", "admin") // 自称"我是网关转发来的"同样要剥
	h.Set("Cookie", "keep=me")

	StripInboundHops(h)
	for _, k := range inboundHopHeaders {
		if v := h.Values(k); len(v) != 0 {
			t.Fatalf("%s 未被剥净: %v", k, v)
		}
	}
	if h.Get("Cookie") != "keep=me" {
		t.Fatal("不该误伤其它头")
	}

	SetForwarded(h, Peer{IP: "10.0.0.9", Proto: "https"}, "zhangsan", "oa")
	if h.Get("X-Forwarded-For") != "10.0.0.9" || h.Get("X-Real-Ip") != "10.0.0.9" {
		t.Fatalf("应按真实对端重写: %v", h)
	}
	if h.Get("X-Baidi-User") != "zhangsan" || h.Get("X-Baidi-Resource") != "oa" {
		t.Fatalf("身份头应来自网关验过的会话: %v", h)
	}
	// ★没有可信来源时**一个字节都不下发** X-Forwarded-Host：此前这里写的是客户端
	// 完全可控的 r.Host，后端据它拼出的找回密码链接会指向攻击者的域名。
	if v := h.Get("X-Forwarded-Host"); v != "" {
		t.Fatalf("无可信来源时不得下发 X-Forwarded-Host，得 %q", v)
	}
	SetForwarded(h, Peer{IP: "10.0.0.9", Proto: "https", Host: "oa.example.com"}, "zhangsan", "oa")
	if h.Get("X-Forwarded-Host") != "oa.example.com" {
		t.Fatalf("显式配置的对外主机名应下发: %v", h)
	}
}

func TestRewriteLocation(t *testing.T) {
	const be, pre = "10.20.1.10:8080", "/app/oa/"
	cases := map[string]string{
		// 指向后端自己的绝对跳转 → 收进前缀（不改就把用户甩到内网地址上）
		"http://10.20.1.10:8080/login":   "/app/oa/login",
		"http://10.20.1.10:8080/l?a=1#f": "/app/oa/l?a=1#f",
		"https://10.20.1.10:8080/x":      "/app/oa/x",
		"http://10.20.1.10:8080":         "/app/oa/",
		"/login":                         "/app/oa/login",
		"/":                              "/app/oa/",
		// 指向别处（SSO/外部站点）→ 原样保留：那是后端有意要用户离开
		"https://idp.example.com/authorize": "https://idp.example.com/authorize",
		"//cdn.example.com/x.js":            "//cdn.example.com/x.js",
		// 相对路径浏览器自己解析就对，不动
		"./next": "./next",
		"":       "",
	}
	for in, want := range cases {
		if got := RewriteLocation(in, be, pre); got != want {
			t.Fatalf("RewriteLocation(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// 后端普遍下发 Path=/，不收窄就等于把 A 应用的会话 Cookie 送给 B 应用的后端。
func TestRewriteSetCookiePath(t *testing.T) {
	const pre = "/app/oa/"
	cases := map[string]string{
		"sid=1; Path=/; HttpOnly":             "sid=1; Path=/app/oa/; HttpOnly",
		"sid=1; HttpOnly":                     "sid=1; HttpOnly; Path=/app/oa/",
		"sid=1; Domain=corp.internal; Path=/": "sid=1; Path=/app/oa/",
		"sid=1; path=/x; Secure":              "sid=1; Path=/app/oa/; Secure",
	}
	for in, want := range cases {
		if got := RewriteSetCookiePath(in, pre); got != want {
			t.Fatalf("RewriteSetCookiePath(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestTargetFromReferer(t *testing.T) {
	if got, ok := TargetFromReferer("https://gw/app/oa/index.html", "/static/a.css", "v=1"); !ok ||
		got != "/app/oa/static/a.css?v=1" {
		t.Fatalf("应把根相对资源送进来源应用的前缀，得 %q/%v", got, ok)
	}
	// 已经在前缀内、入口端点、无 Referer、Referer 不是应用路径 —— 都不参与
	for _, c := range []struct{ ref, path string }{
		{"https://gw/app/oa/i.html", "/app/oa/x"},
		{"https://gw/app/oa/i.html", entryPath},
		{"", "/static/a.css"},
		{"https://gw/other", "/static/a.css"},
	} {
		if _, ok := TargetFromReferer(c.ref, c.path, ""); ok {
			t.Fatalf("(%q,%q) 不该产生兜底重定向", c.ref, c.path)
		}
	}
}
