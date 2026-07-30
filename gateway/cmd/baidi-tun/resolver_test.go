package main

// 只测**纯函数**：域名规范化、文件名/规则名映射、记录表解析、清理清单推导。
//
// ★真正写系统解析器（/etc/resolver、resolvectl、NRPT）需要 root 且会改动本机配置，
// 单测里绝不真写——一个跑飞的测试会把开发机的 DNS 弄坏，而且症状（某域名解析失败）
// 与测试本身毫无关联，排查成本极高。那部分代码**未经实机验证**，见 resolver_*.go 的说明。

import (
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	ok := []struct{ in, want string }{
		{"corp.internal", "corp.internal"},
		{"  CORP.Internal  ", "corp.internal"}, // 大小写不敏感 + 去空白
		{"corp.internal.", "corp.internal"},    // 线上形制带尾点
		{".corp.internal", "corp.internal"},    // NRPT 形制带前导点
		{"*.corp.internal", "corp.internal"},   // 通配前缀语义等价于按后缀分流
		{"a-b.c-d.internal", "a-b.c-d.internal"},
		{"", ""}, // 空项由调用方跳过
		{" ", ""},
		{".", ""}, // 只有点 → 空，不是「根域接管」
	}
	for _, c := range ok {
		got, err := normalizeDomain(c.in)
		if err != nil {
			t.Fatalf("normalizeDomain(%q) 意外报错: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// 必须拒绝的：路径穿越（会被拼进 /etc/resolver/<domain>）、根域接管、畸形标签。
	bad := []string{
		"../../etc/passwd", // 含 '/' 与空标签，两道闸都挡
		"corp/internal",    // 含 '/'
		"corp..internal",   // 空标签
		"*",                // 根域 = 全局接管，本项目明确不做
		"-corp.internal",   // 标签以连字符起
		"corp-.internal",   // 标签以连字符止
		"corp internal",    // 空格
		"corp$.internal",   // 非法字符
	}
	for _, in := range bad {
		if got, err := normalizeDomain(in); err == nil {
			t.Errorf("normalizeDomain(%q) = %q, 期望报错", in, got)
		}
	}
}

func TestSplitDomainsDedup(t *testing.T) {
	// 去重必须在规范化**之后**：三种写法是同一个域，重复添加 NRPT 规则会让清理漏删一条。
	got, err := splitDomains("corp.internal, CORP.internal., *.corp.internal , ,git.corp.internal")
	if err != nil {
		t.Fatalf("splitDomains 报错: %v", err)
	}
	want := []string{"corp.internal", "git.corp.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitDomains = %v, want %v", got, want)
	}
	if _, err := splitDomains("corp.internal,bad/dom"); err == nil {
		t.Error("含非法项时应整体报错，不能只丢掉那一项（静默丢弃 = 某个域名莫名不走隧道）")
	}
}

func TestParseDNSRecords(t *testing.T) {
	// 键的规范化（大小写 + 尾点）必须与数据面查表口径一致，否则
	//「配了 OA.corp.internal 却查 oa.corp.internal. 查不到」。
	in := []byte(`{"OA.corp.internal.":"10.20.1.10","git.corp.internal":"10.30.5.7"}`)
	got, err := parseDNSRecords(in)
	if err != nil {
		t.Fatalf("parseDNSRecords 报错: %v", err)
	}
	want := map[string]string{"oa.corp.internal": "10.20.1.10", "git.corp.internal": "10.30.5.7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseDNSRecords = %v, want %v", got, want)
	}

	// 空文件 = 空表（合法：纯 IP 场景不需要记录）
	for _, empty := range [][]byte{nil, []byte(""), []byte("  \n")} {
		m, err := parseDNSRecords(empty)
		if err != nil || len(m) != 0 {
			t.Errorf("空记录表应解析为空 map，得到 %v, err=%v", m, err)
		}
	}

	bad := map[string][]byte{
		"非 JSON":     []byte("{"),
		"值不是 IP":     []byte(`{"oa.corp.internal":"backend-host"}`),
		"空域名":        []byte(`{"":"10.0.0.1"}`),
		"规范化后撞名且不一致": []byte(`{"OA.corp.internal":"10.0.0.1","oa.corp.internal.":"10.0.0.2"}`),
	}
	for name, b := range bad {
		if m, err := parseDNSRecords(b); err == nil {
			t.Errorf("%s：期望报错，得到 %v", name, m)
		}
	}

	// 规范化后撞名但地址一致：属于冗余不是冲突，应放行。
	if m, err := parseDNSRecords([]byte(`{"OA.corp.internal":"10.0.0.1","oa.corp.internal.":"10.0.0.1"}`)); err != nil || len(m) != 1 {
		t.Errorf("同名同址应放行，得到 %v, err=%v", m, err)
	}
}

// 记录表是 Tauri 侧按 JSON 落盘、这里再读回来的，两端形制必须对得上：
// 用 encoding/json 反向序列化一遍，确保 map[string]string 这一层没有额外包装。
func TestParseDNSRecordsRoundTrip(t *testing.T) {
	src := map[string]string{"oa.corp.internal": "10.20.1.10"}
	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseDNSRecords(b)
	if err != nil {
		t.Fatalf("parseDNSRecords 报错: %v", err)
	}
	if !reflect.DeepEqual(got, src) {
		t.Errorf("round-trip = %v, want %v", got, src)
	}
}

func TestResolverFileMapping(t *testing.T) {
	if got := resolverFilePath("corp.internal"); got != "/etc/resolver/corp.internal" {
		t.Errorf("resolverFilePath = %q", got)
	}
	// 清理清单必须与写入清单同源推导——两处各写一遍是漏删的经典来源，
	// 漏删的症状是「断开后该域名永久解析失败」。
	got := resolverFiles([]string{"corp.internal", "git.corp.internal"})
	want := []string{"/etc/resolver/corp.internal", "/etc/resolver/git.corp.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolverFiles = %v, want %v", got, want)
	}
	if len(resolverFiles(nil)) != 0 {
		t.Error("空域名清单不应推导出任何待清理文件")
	}
}

func TestResolverFileContentIsSelfIdentifying(t *testing.T) {
	c := resolverFileContent("10.99.0.53")
	if !isBaidiManaged(c) {
		t.Fatal("我们写的解析配置必须带所有权标记，否则清理时不敢删（只能永久残留）")
	}
	if !strings.Contains(c, "nameserver 10.99.0.53\n") {
		t.Errorf("缺少 nameserver 行:\n%s", c)
	}
	// 反向：管理员手写的同名文件不得被判为我们的（判错等于顺手删掉别人的配置）。
	if isBaidiManaged("nameserver 192.168.1.1\n") {
		t.Error("无标记的第三方配置被误判为本客户端所有")
	}
}

func TestNrptAndResolvectlFormats(t *testing.T) {
	// NRPT 的 Namespace 少了前导点会被当作「单个精确名字」而不是后缀，
	// 症状是 oa.corp.internal 不走隧道解析器而 corp.internal 走。
	if got := nrptNamespace("corp.internal"); got != ".corp.internal" {
		t.Errorf("nrptNamespace = %q, want .corp.internal", got)
	}
	// systemd-resolved 的 "~" 前缀表示「仅路由域」；少了它会变成搜索域语义，
	// 裸主机名会被拼上该域去查，属于没人要的行为改变。
	got := resolvectlDomainArgs([]string{"corp.internal", "git.corp.internal"})
	want := []string{"~corp.internal", "~git.corp.internal"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolvectlDomainArgs = %v, want %v", got, want)
	}
}

func TestRunDNSCleanupIsIdempotent(t *testing.T) {
	// 清理会被 defer、fatal 前的显式调用、信号协程三条路径触发，重复执行必须无害。
	n := 0
	setDNSCleanup(func() { n++ })
	runDNSCleanup()
	runDNSCleanup()
	runDNSCleanup()
	if n != 1 {
		t.Errorf("清理执行了 %d 次，期望恰好 1 次", n)
	}
	runDNSCleanup() // 未注册时调用也不能 panic
}

// 解析器 VIP 必须落在被接管网段内，否则查询包压根不进 utun：症状是「解析超时」
// 而非「解析到错误地址」，极易误判成解析器实现有问题。这道闸把它变成启动即失败。
func TestRoutesCover(t *testing.T) {
	routes := []string{"10.99.0.0/24", "10.20.1.10/32"}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.99.0.53", true},  // VIP 段内的解析器地址（正常情况）
		{"10.20.1.10", true},  // 单主机路由也算覆盖
		{"10.20.1.11", false}, // 差一台：/32 不覆盖邻居
		{"10.98.0.53", false}, // 典型笔误：网段写错一位
	}
	for _, c := range cases {
		if got := routesCover(routes, net.ParseIP(c.ip)); got != c.want {
			t.Errorf("routesCover(%v, %s) = %v, want %v", routes, c.ip, got, c.want)
		}
	}
	if routesCover(nil, net.ParseIP("10.99.0.53")) {
		t.Error("没有任何接管网段时不应判为已覆盖")
	}
}
