package store

import (
	"errors"
	"strings"
	"testing"
)

// ClassifyHost 是「这个地址能不能交给终端/浏览器去连」的**唯一**判据：
// 登记接入地址（NormalizeAccessHost）、剖面落点告警（api.endpointWarnings）、
// 七层入口推导（api.webHostUnroutable / webListenLoopback）三处共用。
//
// ★为什么不能只用 net.ParseIP：它认不出下面这些**真能解析/监听到回环**的写法，
// 而三处判据里只有七层那一处额外判了 `localhost`——同一个值两条接入路结论相反。
func TestClassifyHost(t *testing.T) {
	cases := map[string]HostKind{
		// 回环：四种写法都是同一台机器
		"127.0.0.1": HostLoopback, "127.8.8.8": HostLoopback, "::1": HostLoopback,
		"localhost": HostLoopback, "LOCALHOST": HostLoopback, "localhost.": HostLoopback,
		"::1%lo0": HostLoopback, "[::1]": HostLoopback,
		// 通配 / 空：监听语义，不是能连的地址
		"": HostWildcard, "   ": HostWildcard, "0.0.0.0": HostWildcard, "::": HostWildcard,
		// 形似 IP 的非标准写法：inet_aton 会展开成别的地址，控制面判不出是哪个
		"127.1": HostMalformed, "10.1": HostMalformed, "2130706433": HostMalformed,
		"0x7f.1": HostMalformed, "1.2.3.4.5": HostMalformed,
		// 正常值
		"10.0.0.5": HostRoutable, "198.51.100.7": HostRoutable, "fd00::1": HostRoutable,
		"gw.example.com": HostRoutable, "gw-1.corp.internal": HostRoutable,
		"localhost.corp.example": HostRoutable, // 只是名字里带 localhost，不是回环
	}
	for host, want := range cases {
		if got := ClassifyHost(host); got != want {
			t.Errorf("ClassifyHost(%q) = %v, want %v", host, got, want)
		}
	}
	// 两个派生判据与分类保持一致（消费方只用这两个）。
	if !IsLoopbackHost("localhost") || IsLoopbackHost("gw.example.com") {
		t.Error("IsLoopbackHost 与分类不一致")
	}
	if !IsUnroutableHost("127.1") || !IsUnroutableHost("") || IsUnroutableHost("10.0.0.5") {
		t.Error("IsUnroutableHost 与分类不一致")
	}
}

// 登记接口是这道判据的第一个执行方：必然连不通的写法当面拒，而不是存下来
// 让客户端拨自己（改造前 localhost / 127.1 / 2130706433 三种都能存进去）。
func TestNormalizeAccessHostRejectsUnreachable(t *testing.T) {
	for _, bad := range []string{"localhost", "localhost.", "127.0.0.1", "::1", "0.0.0.0", "::", "127.1", "2130706433"} {
		got, err := NormalizeAccessHost(bad)
		if !errors.Is(err, ErrBadAccessHost) {
			t.Errorf("★%q 应被拒（客户端与浏览器都会连到本机或判不出指向哪里），得 %q / %v", bad, got, err)
			continue
		}
		// 拒绝要说得出**为什么**：只说"格式不对"会让人反复换写法试。
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("拒绝文案应点名被拒的值 %q，得 %v", bad, err)
		}
	}
	for _, ok := range []string{"", "gw.example.com", "203.0.113.9", "fd00::1", "gw-1.corp.internal"} {
		if got, err := NormalizeAccessHost(ok); err != nil || got != strings.TrimSpace(ok) {
			t.Errorf("%q 应被接受，得 %q / %v", ok, got, err)
		}
	}
}
