package cplane

// L4 隧道身份姿态随心跳上报的 JSON 契约（wave11 行动 3）。
//
// ★这条用例是**接线**用的，不是逻辑用的：控制面侧那一半（三态各出各的告警）
// 已有 api/gatewaypage_test.go 钉住，但把 Register 里那三行删掉的话，那组照样全绿——
// 而现场后果正是这次要消灭的形态：一台逃生舱开着的网关，在网关页上与已收口的
// 那些长得一模一样。实测变异：删掉 payload 里的 tunnelIdStrict → 全仓一条不红。

import "testing"

// ① 未调 SetTunnelIDStrict（旧网关的行为）：报文里连键都没有。
// 控制面据此如实报「不可判定」，而不是替它断言「已开启」。
func TestRegisterOmitsTunnelIDWhenNotSet(t *testing.T) {
	body := registerBody(t, nil)
	if _, ok := body["tunnelIdStrict"]; ok {
		t.Errorf("没装姿态源时不该出现 tunnelIdStrict 字段，实际：%v", body["tunnelIdStrict"])
	}
}

// ② 严格模式开着也要报（**不能只在关掉时报**）。
// 只报 false 的话，「已收口」与「旧网关根本不会报」在控制面看来完全一样，
// 三态就塌成两态——而那两者的运维动作恰好相反（一个不用管，一个必须去升级）。
func TestRegisterCarriesTunnelIDStrictTrue(t *testing.T) {
	body := registerBody(t, func(c *Client) { c.SetTunnelIDStrict(true) })
	v, ok := body["tunnelIdStrict"]
	if !ok {
		t.Fatal("★严格模式开着时也必须上报：否则「已收口」与「旧网关不会报」分不开")
	}
	if v != true {
		t.Errorf("应上报 true，实得 %v", v)
	}
}

// ③ 逃生舱开着：如实上报 false，控制面据此在网关页逐台点名。
func TestRegisterCarriesTunnelIDStrictFalse(t *testing.T) {
	body := registerBody(t, func(c *Client) { c.SetTunnelIDStrict(false) })
	v, ok := body["tunnelIdStrict"]
	if !ok || v != false {
		t.Fatalf("逃生舱开着时应上报 false，实得 %v（存在=%v）", v, ok)
	}
}
