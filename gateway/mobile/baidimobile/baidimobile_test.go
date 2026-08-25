package baidimobile

import (
	"strings"
	"testing"
)

// 移动端数据面此前对网关身份**一个字节都不校验**，也从不发 CONNECT 前导——
// 不是引擎不支持（internal/dataplane 与桌面 baidi-tun 同一套，两样都有），
// 而是这一层的 Config **根本没有这两个字段**，控制面剖面里下发的 tunnelPin 与
// resmap 在移动端无处可放。这组用例钉住那两个字段真的被传下去。

func TestParseResmap(t *testing.T) {
	if m, err := parseResmap(""); err != nil || m != nil {
		t.Fatalf("空串应视为「无映射」，实得 m=%v err=%v", m, err)
	}
	m, err := parseResmap(`{"10.99.0.36:8080":"oa","10.99.0.218:22":"git"}`)
	if err != nil {
		t.Fatalf("合法 JSON 应解析成功: %v", err)
	}
	if m["10.99.0.36:8080"] != "oa" || m["10.99.0.218:22"] != "git" {
		t.Fatalf("映射内容不对: %v", m)
	}
	// ★坏 JSON 必须报错而不是当空表。当空表的话每条连接都不发前导，
	//   而网关对无前导连接 fail-closed——症状是「隧道建起来了但什么都访问不了」，
	//   且两侧日志都不会说是映射表坏了。
	if _, err := parseResmap(`{不是JSON`); err == nil {
		t.Error("坏 JSON 必须报错，不能静默当成空表")
	} else if !strings.Contains(err.Error(), "资源映射表") {
		t.Errorf("错误要说得出是映射表的问题，实得: %v", err)
	}
}

// Start 的入口校验：缺令牌 / 缺控制面地址要在同步路径上就报人话，
// 而不是等 goroutine 起来后经 Session.Reason() 才浮现。
func TestStartRejectsBadConfig(t *testing.T) {
	if _, err := Start(-1, nil); err == nil {
		t.Error("nil config 应报错")
	}
	if _, err := Start(-1, &Config{}); err == nil || !strings.Contains(err.Error(), "身份令牌") {
		t.Errorf("缺令牌应报「缺少身份令牌」，实得: %v", err)
	}
	if _, err := Start(-1, &Config{Token: "t"}); err == nil || !strings.Contains(err.Error(), "控制中心") {
		t.Errorf("缺 control 应报「缺少控制中心地址」，实得: %v", err)
	}
	// 坏 resmap 要在建 TUN **之前**被拒（tunFd=-1 时若走到建 TUN 会是另一种错）。
	_, err := Start(-1, &Config{Token: "t", Control: "http://127.0.0.1:8090", ResmapJSON: "{坏"})
	if err == nil || !strings.Contains(err.Error(), "资源映射表") {
		t.Errorf("坏 resmap 应在建 TUN 前被拒，实得: %v", err)
	}
}
