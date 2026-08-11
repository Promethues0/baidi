package api

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// profileFixture 构造一组覆盖各分支的应用/资源：
// 普通可访问、高敏需授予、越权、未桥接资源、已停用、全网资源。
func profileFixture() (store.AppBundle, []store.Resource) {
	apps := store.AppBundle{Apps: []store.App{
		{ID: "a1", Name: "OA", Addr: "10.20.1.10:8080", Mode: "web", Category: "office", Status: "running", ResourceID: "oa"},
		{ID: "a2", Name: "财务", Addr: "10.20.3.21:443", Mode: "web", Category: "finance", Status: "running", ResourceID: "finance"},
		{ID: "a3", Name: "Git", Addr: "10.30.5.8:22", Mode: "tunnel", Category: "dev", Status: "running", ResourceID: "git"},
		{ID: "a4", Name: "无资源应用", Addr: "10.30.9.4:22", Mode: "tunnel", Category: "dev", Status: "running"},
		{ID: "a5", Name: "已停用", Addr: "10.40.2.7:8000", Mode: "web", Category: "office", Status: "stopped", ResourceID: "oa"},
		{ID: "a6", Name: "知网", Addr: "*.cnki.net", Mode: "global", Category: "global", Status: "running"},
	}}
	res := []store.Resource{
		{ID: "oa", Name: "OA", Backend: "10.20.1.10:8080", AllowRoles: []string{"admin", "user"}},
		{ID: "finance", Name: "财务", Backend: "10.20.3.21:443", AllowRoles: []string{"admin"}},
		{ID: "git", Name: "Git", Backend: "10.30.5.8:22", AllowRoles: []string{"admin", "user"}},
	}
	return apps, res
}

// newProfileServer 构造只做剖面推导的 Server。buildProfile 只用到 store 的
// ActiveGrantsFor（JIT 授予），其余数据经参数注入，故直接挂真 SQLite 临时库即可。
func newProfileServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "profile.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
}

func findApp(p ClientProfile, id string) (ProfileApp, bool) {
	for _, a := range p.Apps {
		if a.ID == id {
			return a, true
		}
	}
	return ProfileApp{}, false
}

// 剖面的核心契约：有权资源同时进 resmap（VIP + 真实后端两条键）与 routes；
// 无权资源作为磁贴可见但**不进**路由——可见性与可达性分离。
func TestBuildProfile_RoutesAndResmap(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileFixture()
	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	if got := p.Resmap["10.20.1.10:8080"]; got != "oa" {
		t.Fatalf("真实后端未登记到 oa，实得 %q", got)
	}
	oa, ok := findApp(p, "a1")
	if !ok {
		t.Fatal("OA 应缺席剖面")
	}
	if got := p.Resmap[oa.VIP+":8080"]; got != "oa" {
		t.Fatalf("VIP %s:8080 未登记到 oa，实得 %q", oa.VIP, got)
	}
	// 真实后端 /32 必须在 routes 里，否则用户访问业务真实地址时流量根本不进隧道——
	// 这正是修复前「隧道建起来了却什么都访问不了」的根因，须有回归防线。
	if !hasRoute(p.Routes, "10.20.1.10/32") {
		t.Fatalf("真实后端 /32 未进 routes: %v", p.Routes)
	}
	if !hasRoute(p.Routes, p.VIPCidr) {
		t.Fatalf("VIP 网段未进 routes: %v", p.Routes)
	}

	// finance 的 AllowRoles 只有 admin，user 无静态权限也无授予 → 磁贴在、路由不在
	fin, ok := findApp(p, "a2")
	if !ok {
		t.Fatal("高敏应用应作为磁贴可见（供申请入口），不应整条隐藏")
	}
	if fin.Accessible {
		t.Fatal("无授予的高敏资源不应标记为可访问")
	}
	if _, in := p.Resmap["10.20.3.21:443"]; in {
		t.Fatal("无权资源不得进 resmap（终端不该接管其流量）")
	}
	if hasRoute(p.Routes, "10.20.3.21/32") {
		t.Fatal("无权资源不得进 routes")
	}
}

// 未桥接受控资源的应用必须产生显式告警，而不是静默消失——
// 静默是此前最难排查的失败形态：管理台里应用好端端的，客户端就是连不上。
func TestBuildProfile_UnbridgedAppWarns(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileFixture()
	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	if _, ok := findApp(p, "a4"); ok {
		t.Fatal("未关联资源的应用不该出现在剖面里（无从路由）")
	}
	var hit bool
	for _, w := range p.Warnings {
		if strings.Contains(w, "无资源应用") {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("未关联资源的应用须显式告警，实得 %v", p.Warnings)
	}
	if _, ok := findApp(p, "a5"); ok {
		t.Fatal("已停用应用不该进剖面")
	}
	// 全网资源没有内网落点，进磁贴但不参与隧道路由。
	g, ok := findApp(p, "a6")
	if !ok || g.VIP != "" {
		t.Fatalf("全网资源应作为磁贴出现且无 VIP，实得 %+v", g)
	}
}

// VIP 分配必须确定性：同一资源在任意次调用中得到同一 VIP。
// 否则用户每次重连 VIP 都变，收藏夹/SSH 配置全部失效。
func TestBuildProfile_VIPIsStable(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileFixture()
	a := s.buildProfile(context.Background(), "li.fang", "user", apps, res)
	b := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	for _, x := range a.Apps {
		y, ok := findApp(b, x.ID)
		if !ok || x.VIP != y.VIP {
			t.Fatalf("应用 %s 的 VIP 不稳定：%q vs %q", x.ID, x.VIP, y.VIP)
		}
	}
	// 不同资源不得撞 VIP（撞了会让两个业务在同一地址上互相覆盖）。
	seen := map[string]string{}
	for _, x := range a.Apps {
		if x.VIP == "" {
			continue
		}
		if prev, dup := seen[x.VIP]; dup {
			t.Fatalf("VIP %s 被 %s 与 %s 重复分配", x.VIP, prev, x.ResourceID)
		}
		seen[x.VIP] = x.ResourceID
	}
}

// VIP 必须在**资源集合变化**时也稳定——这是同一份稳定性承诺里更常见、也更难发现的一半。
//
// ★按排序下标分配时，新增一个字典序靠前的资源就会让其后所有资源的 VIP 集体位移一格：
// 用户存进 SSH 配置的 10.99.0.11 要么连不通（resmap 里那个键没了），要么被相邻资源
// 接住——端口恰好相同时会静默连到**另一个业务系统**上。
func TestBuildProfile_VIPStableAcrossResourceChanges(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileFixture()
	before := s.buildProfile(context.Background(), "admin", "admin", apps, res)

	// 新增一个字典序最小的资源（下标法下它会把所有既有资源顶后一位）
	apps.Apps = append(apps.Apps, store.App{
		ID: "app-aaa", Name: "新应用", Addr: "10.20.9.9:8080", Mode: "web",
		Category: "office", Status: "running", ResourceID: "aaa-first",
	})
	res = append(res, store.Resource{ID: "aaa-first", Name: "新资源", Backend: "10.20.9.9:8080"})
	after := s.buildProfile(context.Background(), "admin", "admin", apps, res)

	for _, x := range before.Apps {
		if x.VIP == "" {
			continue
		}
		y, ok := findApp(after, x.ID)
		if !ok {
			t.Fatalf("应用 %s 在新增资源后消失了", x.ID)
		}
		if x.VIP != y.VIP {
			t.Fatalf("新增一个资源后，应用 %s（资源 %s）的 VIP 从 %s 变成了 %s——"+
				"用户存的书签/SSH 配置会指向另一个资源", x.ID, x.ResourceID, x.VIP, y.VIP)
		}
	}

	// 删除同一个资源后必须回到原样（增删对称）
	apps.Apps = apps.Apps[:len(apps.Apps)-1]
	res = res[:len(res)-1]
	back := s.buildProfile(context.Background(), "admin", "admin", apps, res)
	for _, x := range before.Apps {
		y, ok := findApp(back, x.ID)
		if !ok || x.VIP != y.VIP {
			t.Fatalf("删除资源后应用 %s 的 VIP 未回到原值：%q vs %q", x.ID, x.VIP, y.VIP)
		}
	}
}

// 角色授权与网关侧 resource.Authorize 必须同构：admin 能拿到 finance 的路由。
func TestBuildProfile_AdminGetsRestrictedResource(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileFixture()
	p := s.buildProfile(context.Background(), "admin", "admin", apps, res)

	fin, ok := findApp(p, "a2")
	if !ok || !fin.Accessible {
		t.Fatalf("admin 应可访问 finance，实得 %+v", fin)
	}
	if p.Resmap["10.20.3.21:443"] != "finance" {
		t.Fatal("admin 的 finance 后端应进 resmap")
	}
}

// JIT 授予必须把高敏资源翻回可访问，并真正下发 VIP / 路由 / resmap。
//
// ★这是最容易做成"假闭环"的一环：审批流程走完、管理台显示已授予，但客户端剖面仍按
// 静态 ACL 过滤，于是拿到审批的用户依旧连不上——审批白批。控制面在下发网关策略时
// 会把有效授予并入 AllowUsers（handleGatewayPolicy），剖面必须与之同构。
func TestBuildProfile_ActiveGrantUnlocksRouting(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileFixture()
	ctx := context.Background()

	req, err := s.writer.CreateAccessRequest(ctx, store.AccessRequest{
		ID: "req-1", User: "li.fang", ResourceID: "finance", ResourceName: "财务",
		Reason: "月结对账", TTLMinutes: 60,
	})
	if err != nil {
		t.Fatalf("建申请失败: %v", err)
	}
	if _, _, err := s.writer.DecideAccessRequest(ctx, req.ID, "approved", "已核实", "admin", 0); err != nil {
		t.Fatalf("审批失败: %v", err)
	}

	p := s.buildProfile(ctx, "li.fang", "user", apps, res)
	fin, ok := findApp(p, "a2")
	if !ok || !fin.Accessible {
		t.Fatalf("持有效 JIT 授予后 finance 应可访问，实得 %+v", fin)
	}
	if p.Resmap["10.20.3.21:443"] != "finance" {
		t.Fatalf("授予后 finance 后端须进 resmap，实得 %v", p.Resmap)
	}
	if !hasRoute(p.Routes, "10.20.3.21/32") {
		t.Fatalf("授予后 finance 后端 /32 须进 routes，实得 %v", p.Routes)
	}
}

// 一台网关都没注册时给出回退落点 + 明确告警，而不是返回空清单让客户端瞎试。
func TestProfileGateways_NoRegistrationFallsBackWithWarning(t *testing.T) {
	s := newProfileServer(t)
	gws, warns := s.profileGateways()
	if len(gws) != 1 {
		t.Fatalf("回退落点须恰好一条，实得 %d 条", len(gws))
	}
	if gws[0].Online {
		t.Fatal("无注册网关时不应标记在线")
	}
	if gws[0].SPAPort == "" || gws[0].ProxyPort == "" || gws[0].Host == "" {
		t.Fatalf("回退落点须完整，实得 %+v", gws[0])
	}
	if len(warns) == 0 {
		t.Fatal("网关离线须带出告警")
	}
}

// containsStr 与 hasRoute 同构，只是用在分流域清单上——同一个函数名叫 hasRoute
// 读起来像在查路由表，容易误导后来者。
func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func hasRoute(routes []string, want string) bool {
	for _, r := range routes {
		if r == want {
			return true
		}
	}
	return false
}

// ────────────────────────────── 域名后端 / 分离式 DNS ──────────────────────────────

// profileDomainFixture 覆盖域名后端的各种形态：需规范化的写法、同名不同端口、
// 公共后缀域、无权访问、通配符（非法域名）、以及一个 IP 后端做对照组。
// 刻意与 profileFixture 分开，免得给既有用例引入新的资源、扰动它们的 VIP 断言。
func profileDomainFixture() (store.AppBundle, []store.Resource) {
	apps := store.AppBundle{Apps: []store.App{
		{ID: "d1", Name: "OA 域名版", Addr: "OA.Corp.Internal.:8080", Mode: "web", Category: "office", Status: "running", ResourceID: "d-oa"},
		{ID: "d2", Name: "Git SSH", Addr: "git.corp.internal:22", Mode: "tunnel", Category: "dev", Status: "running", ResourceID: "d-git"},
		{ID: "d3", Name: "Git Web", Addr: "git.corp.internal:8443", Mode: "web", Category: "dev", Status: "running", ResourceID: "d-gitweb"},
		{ID: "d4", Name: "商城", Addr: "shop.example.com:443", Mode: "web", Category: "office", Status: "running", ResourceID: "d-shop"},
		{ID: "d5", Name: "财务域名版", Addr: "fin.corp.internal:443", Mode: "web", Category: "finance", Status: "running", ResourceID: "d-fin"},
		{ID: "d6", Name: "知网直连", Addr: "*.cnki.net:443", Mode: "web", Category: "office", Status: "running", ResourceID: "d-wild"},
		{ID: "d7", Name: "机房跳板", Addr: "10.20.9.9:22", Mode: "tunnel", Category: "dev", Status: "running", ResourceID: "d-ip"},
	}}
	res := []store.Resource{
		{ID: "d-oa", Name: "OA 域名版", Backend: "OA.Corp.Internal.:8080", AllowRoles: []string{"admin", "user"}},
		{ID: "d-git", Name: "Git SSH", Backend: "git.corp.internal:22", AllowRoles: []string{"admin", "user"}},
		{ID: "d-gitweb", Name: "Git Web", Backend: "git.corp.internal:8443", AllowRoles: []string{"admin", "user"}},
		{ID: "d-shop", Name: "商城", Backend: "shop.example.com:443", AllowRoles: []string{"admin", "user"}},
		{ID: "d-fin", Name: "财务域名版", Backend: "fin.corp.internal:443", AllowRoles: []string{"admin"}},
		{ID: "d-wild", Name: "知网直连", Backend: "*.cnki.net:443", AllowRoles: []string{"admin", "user"}},
		{ID: "d-ip", Name: "机房跳板", Backend: "10.20.9.9:22", AllowRoles: []string{"admin", "user"}},
	}
	return apps, res
}

// 域名后端的完整契约：拿 VIP、进 DNS 记录、父域进分流域、resmap **只**登记 VIP 一侧。
//
// ★这是本轮补的洞：此前域名后端拿到了 VIP，却既没有 DNS 记录也没有 /32 路由，
// 名字仍由系统解析器解到内网真实 IP、按默认出口直连——隧道显示"已接入"，
// 流量却完全没进隧道，且全程无任何报错。
func TestBuildProfile_DomainBackendRoutedViaDNS(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileDomainFixture()
	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	oa, ok := findApp(p, "d1")
	if !ok || oa.VIP == "" {
		t.Fatalf("域名后端的应用必须拿到 VIP，实得 %+v", oa)
	}
	// 记录键须已规范化：控制台里填的是 "OA.Corp.Internal."，客户端查的是 "oa.corp.internal"。
	if got := p.DNS.Records["oa.corp.internal"]; got != oa.VIP {
		t.Fatalf("DNS 记录应把 oa.corp.internal 指向 %s，实得 %q（records=%v）", oa.VIP, got, p.DNS.Records)
	}
	if _, bad := p.DNS.Records["OA.Corp.Internal."]; bad {
		t.Fatal("DNS 记录键未规范化（大小写/尾点），客户端按小写无尾点查表将全部落空")
	}
	// VIP 一侧登记 + /32 路由：域名解析到 VIP 后，流量才真正被 utun 接管。
	if got := p.Resmap[oa.VIP+":8080"]; got != "d-oa" {
		t.Fatalf("VIP 侧 resmap 未登记到 d-oa，实得 %q", got)
	}
	if !hasRoute(p.Routes, oa.VIP+"/32") {
		t.Fatalf("域名后端的 VIP 未进 routes: %v", p.Routes)
	}
	// ★真实后端一侧对域名**刻意不登记**：resmap 是按「连接目的地址」反查的，
	// 目的地址永远是 IP，域名键永远命中不了，登记只会掩盖真正的接管路径。
	for _, k := range []string{"oa.corp.internal:8080", "OA.Corp.Internal.:8080"} {
		if _, in := p.Resmap[k]; in {
			t.Fatalf("域名形式的 resmap 键 %q 不应登记（永远命中不了）", k)
		}
	}
	// 父域进分流域，且不是把整个 internal 顶级域劫进来。
	if !containsStr(p.DNS.Domains, "corp.internal") {
		t.Fatalf("父域 corp.internal 未进分流域: %v", p.DNS.Domains)
	}

	// 解析器 VIP 必须存在、必须在 routes 里，且不与任何资源 VIP 冲突。
	if p.DNS.Server == "" {
		t.Fatal("有域名后端时必须下发解析器 VIP")
	}
	if !hasRoute(p.Routes, p.DNS.Server+"/32") {
		t.Fatalf("解析器 VIP %s 未进 routes——查询会按默认路由送出隧道，症状是全部超时: %v", p.DNS.Server, p.Routes)
	}
	for _, a := range p.Apps {
		if a.VIP != "" && a.VIP == p.DNS.Server {
			t.Fatalf("资源 %s 的 VIP 与解析器 VIP 撞了（%s）", a.ResourceID, a.VIP)
		}
	}

	// 无权资源不进 DNS：解析到一个没有 resmap/路由的 VIP 只会得到一条死路。
	if _, in := p.DNS.Records["fin.corp.internal"]; in {
		t.Fatal("无权访问的域名资源不得进 DNS 记录")
	}
	// 通配符后端不是合法域名，必须显式告警而不是塞一条永远答不出来的死记录。
	if _, in := p.DNS.Records["*.cnki.net"]; in {
		t.Fatal("通配符后端不得进 DNS 记录")
	}
	if containsStr(p.DNS.Domains, "cnki.net") {
		t.Fatalf("通配符后端不得推导出分流域: %v", p.DNS.Domains)
	}
	var wildWarned bool
	for _, w := range p.Warnings {
		if strings.Contains(w, "*.cnki.net") {
			wildWarned = true
		}
	}
	if !wildWarned {
		t.Fatalf("通配符后端须显式告警，实得 %v", p.Warnings)
	}

	// IP 后端行为一字不变（双向登记 + 真实后端 /32）。
	if p.Resmap["10.20.9.9:22"] != "d-ip" {
		t.Fatalf("IP 后端的透明模式登记不应受影响，实得 %v", p.Resmap)
	}
	if !hasRoute(p.Routes, "10.20.9.9/32") {
		t.Fatalf("IP 后端 /32 路由不应受影响: %v", p.Routes)
	}
}

// 同一域名被多个资源以不同端口引用时，A 记录只能指向一个 VIP——
// ★那么另一个资源的端口必须挂到**承载 VIP** 上，否则经域名访问它时目的地址是
// 承载 VIP、端口却查不到资源 id，连接会落到默认资源或直接失败。
func TestBuildProfile_SharedHostnameKeepsBothPortsReachable(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileDomainFixture()
	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	owner := p.DNS.Records["git.corp.internal"]
	if owner == "" {
		t.Fatalf("git.corp.internal 应有 A 记录，实得 %v", p.DNS.Records)
	}
	if got := p.Resmap[owner+":22"]; got != "d-git" {
		t.Fatalf("承载 VIP %s:22 应命中 d-git，实得 %q", owner, got)
	}
	if got := p.Resmap[owner+":8443"]; got != "d-gitweb" {
		t.Fatalf("承载 VIP %s:8443 应命中 d-gitweb，实得 %q（同名多端口的资源被漏登记）", owner, got)
	}
	// 各资源自身的 VIP 一侧仍然可用（两种访问姿态并存）。
	gitweb, _ := findApp(p, "d3")
	if got := p.Resmap[gitweb.VIP+":8443"]; got != "d-gitweb" {
		t.Fatalf("资源自身 VIP 侧也应可达，实得 %q", got)
	}
	// 承载权按资源 id 字典序裁决：d-git < d-gitweb。
	gitssh, _ := findApp(p, "d2")
	if owner != gitssh.VIP {
		t.Fatalf("承载 VIP 应为字典序最小的资源 d-git（%s），实得 %s", gitssh.VIP, owner)
	}
}

// ★公共后缀绝不能成为分流域：把 com 交给隧道内解析器意味着用户整个互联网的 DNS
// 都被劫进隧道，而解析器对未知名字一律 REFUSED（刻意不做递归转发）——
// 结果是接入隧道后全网域名解析崩掉，断开前无法自愈。
func TestBuildProfile_PublicSuffixNeverBecomesSearchDomain(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileDomainFixture()
	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	if p.DNS.Records["shop.example.com"] == "" {
		t.Fatalf("shop.example.com 应有 A 记录，实得 %v", p.DNS.Records)
	}
	for _, d := range p.DNS.Domains {
		if d == "com" || d == "net" || d == "cn" || d == "org" {
			t.Fatalf("公共后缀 %q 混进了分流域：会把整个互联网 DNS 劫进隧道（domains=%v）", d, p.DNS.Domains)
		}
	}
	if !containsStr(p.DNS.Domains, "example.com") {
		t.Fatalf("shop.example.com 的父域 example.com 应作为分流域，实得 %v", p.DNS.Domains)
	}
}

// 两级公共注册后缀（com.cn / co.uk）看着"有两级"，却同样是全网共享的后缀，
// 用它分流等于劫持整个 .com.cn；此时应退回只分流这一个 FQDN 本身。
func TestSearchDomainFor(t *testing.T) {
	cases := map[string]string{
		"oa.corp.internal":     "corp.internal",
		"a.b.corp.internal":    "b.corp.internal",
		"shop.example.com":     "example.com",
		"oa.internal":          "oa.internal", // 父域只有一级 → 退回自身
		"oa":                   "oa",
		"pay.com.cn":           "pay.com.cn", // 父域是公共注册后缀 → 退回自身
		"wiki.co.uk":           "wiki.co.uk",
		"deep.sub.example.com": "sub.example.com",
		"":                     "",
	}
	for in, want := range cases {
		if got := searchDomainFor(in); got != want {
			t.Errorf("searchDomainFor(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// 分流域去冗余：corp.internal 已覆盖 x.corp.internal，多下发一条只会多写一个
// /etc/resolver 文件——也就多一个退出时要清理、漏清就永久污染系统解析的对象。
func TestPruneSubDomains(t *testing.T) {
	got := pruneSubDomains([]string{"corp.internal", "example.com", "x.corp.internal"})
	if len(got) != 2 || got[0] != "corp.internal" || got[1] != "example.com" {
		t.Fatalf("被父域覆盖的子域未剪除，实得 %v", got)
	}
}

func TestNormFQDNAndValidDNSName(t *testing.T) {
	if got := normFQDN("  OA.Corp.Internal.. "); got != "oa.corp.internal" {
		t.Fatalf("规范化结果 %q 不符合预期", got)
	}
	for _, bad := range []string{"*.cnki.net", "", "-oa.corp.internal", "oa..corp", "oa corp.internal", "汉字.internal"} {
		if validDNSName(normFQDN(bad)) {
			t.Errorf("%q 不应被判为合法域名（会变成一条永远答不出来的死记录）", bad)
		}
	}
	for _, ok := range []string{"oa.corp.internal", "a-b_c.corp.internal", "oa"} {
		if !validDNSName(ok) {
			t.Errorf("%q 应被判为合法域名", ok)
		}
	}
}

// ★解析器主机号必须从资源 VIP 的分配区间里挖掉。资源 VIP 从 .11 起连续递增，
// 不挖的话第 43 个资源正好落在 .53 上，与解析器抢地址——症状是「某一个应用死活连不上」，
// 具体是哪个取决于资源 id 的字典序，几乎不可能归因。用 60+ 个资源把这条越界跑出来。
func TestBuildProfile_ResolverVIPReservedFromAllocation(t *testing.T) {
	s := newProfileServer(t)
	var apps store.AppBundle
	var res []store.Resource
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("r%03d", i)
		backend := fmt.Sprintf("10.20.%d.%d:8080", i/250, i%250+1)
		apps.Apps = append(apps.Apps, store.App{
			ID: "app-" + id, Name: "应用" + id, Addr: backend, Mode: "web",
			Category: "office", Status: "running", ResourceID: id,
		})
		res = append(res, store.Resource{ID: id, Name: "资源" + id, Backend: backend})
	}
	// 追加一个域名资源，好让 DNS 段被真正下发（否则 Server 为空、无从比对）。
	apps.Apps = append(apps.Apps, store.App{
		ID: "app-zz", Name: "域名应用", Addr: "oa.corp.internal:8080", Mode: "web",
		Category: "office", Status: "running", ResourceID: "zz-domain",
	})
	res = append(res, store.Resource{ID: "zz-domain", Name: "域名资源", Backend: "oa.corp.internal:8080"})

	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)
	if p.DNS.Server != "10.99.0.53" {
		t.Fatalf("解析器 VIP 应为网段基址 +53，实得 %q", p.DNS.Server)
	}
	seen := map[string]string{}
	for _, a := range p.Apps {
		if a.VIP == "" {
			continue
		}
		if a.VIP == p.DNS.Server {
			t.Fatalf("资源 %s 的 VIP 撞上解析器 VIP %s", a.ResourceID, a.VIP)
		}
		if prev, dup := seen[a.VIP]; dup {
			t.Fatalf("VIP %s 被 %s 与 %s 重复分配", a.VIP, prev, a.ResourceID)
		}
		seen[a.VIP] = a.ResourceID
	}
}

// DNS 段同样要确定性：记录、分流域、解析器地址两次调用必须完全一致。
// 不稳定的后果与 VIP 漂移一样——用户每重连一次，某个域名就换一个落点。
func TestBuildProfile_DNSPlanIsStable(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileDomainFixture()
	a := s.buildProfile(context.Background(), "li.fang", "user", apps, res)
	b := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	if a.DNS.Server != b.DNS.Server {
		t.Fatalf("解析器 VIP 不稳定：%q vs %q", a.DNS.Server, b.DNS.Server)
	}
	if strings.Join(a.DNS.Domains, ",") != strings.Join(b.DNS.Domains, ",") {
		t.Fatalf("分流域不稳定：%v vs %v", a.DNS.Domains, b.DNS.Domains)
	}
	if len(a.DNS.Records) != len(b.DNS.Records) {
		t.Fatalf("记录条数不稳定：%d vs %d", len(a.DNS.Records), len(b.DNS.Records))
	}
	for k, v := range a.DNS.Records {
		if b.DNS.Records[k] != v {
			t.Fatalf("记录 %s 不稳定：%q vs %q", k, v, b.DNS.Records[k])
		}
	}
}

// 纯 IP 场景不下发解析器：客户端据此完全不动系统 DNS 配置——
// 少改一处系统状态，就少一处退出时要清理、清理漏了就留下永久副作用的东西。
func TestBuildProfile_NoDomainBackendMeansNoResolver(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileFixture()
	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	if p.DNS.Server != "" {
		t.Fatalf("无域名后端时不应下发解析器，实得 %q", p.DNS.Server)
	}
	if len(p.DNS.Records) != 0 || len(p.DNS.Domains) != 0 {
		t.Fatalf("无域名后端时 DNS 段应为空，实得 %+v", p.DNS)
	}
	if hasRoute(p.Routes, "10.99.0.53/32") {
		t.Fatalf("未启用解析器却下发了它的路由: %v", p.Routes)
	}
}

// 域名后端的「点开即用」地址用域名而不是 VIP：用 VIP 拼 URL 会让基于 Host/SNI 的
// 虚拟主机路由与 TLS 证书校验失败，现象是隧道通了、页面却 404 或证书告警。
func TestBuildProfile_DomainAppURLUsesHostname(t *testing.T) {
	s := newProfileServer(t)
	apps, res := profileDomainFixture()
	p := s.buildProfile(context.Background(), "li.fang", "user", apps, res)

	oa, _ := findApp(p, "d1")
	if oa.URL != "http://oa.corp.internal:8080" {
		t.Fatalf("域名 web 应用的 URL 应用域名，实得 %q", oa.URL)
	}
	git, _ := findApp(p, "d2")
	if git.URL != "git.corp.internal:22" {
		t.Fatalf("域名 tunnel 应用的 URL 应用域名，实得 %q", git.URL)
	}
	ipApp, _ := findApp(p, "d7")
	if ipApp.URL != ipApp.VIP+":22" {
		t.Fatalf("IP 后端仍应给 VIP 形式的 URL，实得 %q", ipApp.URL)
	}
}
