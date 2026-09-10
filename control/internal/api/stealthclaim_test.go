package api

import "testing"

// ── 「攻击面 = 0」的前提集（wave11 行动 13-②）──
//
// 这是整个网关页唯一一句**正向安全断言**。它此前有两条前提（隐身逐台 armed、
// 没有敞着的七层口），本波补上第三条（没有 DNAT 在网关公网地址上开着端口）。
// 判定在后端一处（stealthClaim），前端只渲染 —— 前提集分散在两条轨上时，
// 加一条必然漏改其中一处，而漏改的那处恰好是最强的那句话。
func TestStealthClaimPreconditions(t *testing.T) {
	armed := []StealthReceipt{{GatewayID: "gw-1", Status: StealthArmed}}
	mixed := []StealthReceipt{{GatewayID: "gw-1", Status: StealthArmed}, {GatewayID: "gw-2", Status: "off"}}
	unknown := []StealthReceipt{{GatewayID: "gw-1", Status: "unknown"}}

	cases := []struct {
		name     string
		receipts []StealthReceipt
		web      int
		exposed  []string
		unk      []string
		natKnown bool
		want     bool
		why      string
	}{
		{"三条前提齐", armed, 0, nil, nil, true, true,
			"隐身逐台实测生效、没有七层敞口、没有 DNAT 敞口且判得出来"},
		{"零台在线", nil, 0, nil, nil, true, false,
			"没有任何事实支撑这句话；空集恒真会让一台网关都没有的部署画出最强断言"},
		{"有一台没生效", mixed, 0, nil, nil, true, false, "隐身只要有一台不 armed 就不成立"},
		{"不可判定不算生效", unknown, 0, nil, nil, true, false,
			"unknown 是「我们不知道」，不是「没问题」"},
		{"七层口敞着", armed, 1, nil, nil, true, false,
			"L7 监听不受 SPA 隐身保护，nmap 对着它一扫一个准"},
		{"DNAT 已灌进内核", armed, 0, []string{"gw-1 tcp 1.2.3.4:443 → 10.0.0.5:8443"}, nil, true, false,
			"★本波补的第三条：DNAT 在网关公网地址上开着端口，隐身规则在 filter 表管不到 nat 表"},
		{"DNAT 运行态判不出来", armed, 0, nil, []string{"gw-1（当前离线）"}, true, false,
			"不可判定既不算敞口，也不能拿去支撑正向断言"},
		{"策略表读不到", armed, 0, nil, nil, false, false,
			"一次库读失败不该让页面在什么都不知道的情况下给出最强断言"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stealthClaim(c.receipts, c.web, c.exposed, c.unk, c.natKnown)
			if got != c.want {
				t.Fatalf("stealthClaim = %v，应为 %v —— %s", got, c.want, c.why)
			}
		})
	}
}
