package baidimobile

import (
	"os"
	"strings"
	"testing"

	"baidi.dev/gateway/internal/dataplane"
)

// 「读不到」与「确定为假」必须分得开：Health() 返回 nil 才是不可判定。
//
// ★合成一个零值 report 顶包的话，一台**根本没起过引擎**的会话，与一台**刚起步、还没敲第一次门**的
// 会话完全同形（六项全 false/空）——而前者是壳的 bug（该报错），后者是正常的接入中（该继续等）。
// 这正是 2026-09-03 真机上那个形态的同族错法，只是换了个地方犯。
func TestHealthNilWhenUndecidable(t *testing.T) {
	if got := (&Session{}).Health(); got != nil {
		t.Fatalf("没有健康状态载体的会话必须回 nil（不可判定），实得 %+v", got)
	}
	var nilSess *Session
	if got := nilSess.Health(); got != nil {
		t.Fatalf("nil 会话同样回 nil，实得 %+v", got)
	}

	s := &Session{health: dataplane.NewHealthState()}
	h := s.Health()
	if h == nil {
		t.Fatal("有载体就必须回一份报告（哪怕里面什么事都还没发生）")
	}
	// 刚建好：确实什么都没发生过——Observed 为假，但报告本身存在
	if h.Observed() {
		t.Error("引擎还没观察到任何事件时 Observed() 必须为假")
	}
	if h.Knock() || h.Tunnel() || h.KnockErr() != "" || h.TunnelErr() != "" || h.Err() != "" {
		t.Errorf("空状态的六项应全为零值：%+v", h)
	}
}

// 六项逐格对位：绑定层是纯搬运，任何一格搬错都是"界面上显示的是另一件事"。
//
// ★为什么值得单独钉：knockErr 与 tunnelErr 两格搬反了，编译过、类型对、用例（若只断言非空）也过，
// 而真机上的表现是「敲门失败」被显示成「隧道失败」——用户按着提示去查网关，问题却在控制面证书上。
// 六个值刻意互不相同且成对可辨。
func TestHealthReportMapsEveryFieldInPlace(t *testing.T) {
	snap := dataplane.HealthSnapshot{
		Observed: true, Knock: true, Tunnel: false,
		KnockErr: "敲门类原因", TunnelErr: "隧道类原因", Err: "当前生效原因",
	}
	h := newHealthReport(snap)
	checks := []struct {
		name      string
		got, want any
	}{
		{"Observed", h.Observed(), snap.Observed},
		{"Knock", h.Knock(), snap.Knock},
		{"Tunnel", h.Tunnel(), snap.Tunnel},
		{"KnockErr", h.KnockErr(), snap.KnockErr},
		{"TunnelErr", h.TunnelErr(), snap.TunnelErr},
		{"Err", h.Err(), snap.Err},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s() = %v，应为 %v", c.name, c.got, c.want)
		}
	}
}

// TestStartWiresHealthState 钉住「Start 必须把 HealthState 建好再塞进 dataplane.Config」。
//
// ★为什么是源码文本守卫而不是跑一次 Start：Start 在建 cfg **之前**要先拿到平台给的真 TUN fd，
// 本机造不出来（同 tundev_guard_test.go 那条守卫的处境）。而这条接线一旦漏掉，
// 后果是**静默**的：Health() 照样回一份非 nil 的报告，只是那份状态没有任何人写，
// Observed() 永远为假 → 原生壳永远停在「接入中」，日志里一个字的异常都没有。
// 这正是本仓「配置齐全却零报错不生效」那一族。
func TestStartWiresHealthState(t *testing.T) {
	b, err := os.ReadFile("baidimobile.go")
	if err != nil {
		t.Fatalf("读不到 baidimobile.go：%v", err)
	}
	src := string(b)
	if !strings.Contains(src, "dataplane.NewHealthState()") {
		t.Error("Start 必须自建 HealthState：引擎自建的那份活在 Run 内部，绑定层一个字都读不到——" +
			"那正是「引擎起来了、门没敲开、界面显示已接入」的成因")
	}
	if !strings.Contains(src, "Health: health") {
		t.Error("建好的 HealthState 必须塞进 dataplane.Config.Health，否则引擎写的是另一份状态")
	}
	if !strings.Contains(src, "health: health") {
		t.Error("同一份 HealthState 必须存进 Session，否则 Health() 读的是另一份状态")
	}
}
