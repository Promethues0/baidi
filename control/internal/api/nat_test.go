package api

import (
	"net/http"
	"testing"

	"baidi.dev/control/internal/auth"
)

// natReportIfaces 模拟网关心跳上报两张网卡（走真实的 register 端点，不直接写库——
// 要验的正是「心跳上报的网卡能被 NAT 用上」这条链路）。
func natReportIfaces(t *testing.T, h http.Handler) {
	t.Helper()
	code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-test", "proxy": "127.0.0.1:18443", "spa": "127.0.0.1:18201",
		"ifaces": []map[string]any{
			{"name": "eth2", "addrs": []string{"5.5.10.102/16"}, "up": true},
			{"name": "eth3", "addrs": []string{"155.155.10.102/16"}, "up": true},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("网关注册 http %d", code)
	}
}

func natTypeIfaces(t *testing.T, h http.Handler) {
	t.Helper()
	for name, typ := range map[string]string{"eth2": "lan", "eth3": "wan"} {
		code, out := doJSON(t, h, "PUT", "/api/v1/nat/ifaces/gw-test/"+name, adminToken(), map[string]any{"type": typ})
		if code != http.StatusOK {
			t.Fatalf("定性 %s 失败 http %d %v", name, code, out)
		}
	}
}

// 网卡必须来自心跳实测上报，而不是管理员手填——手填打错的症状是规则灌进内核后
// 一条流量都不匹配，无报错无日志。
func TestGatewayIfacesComeFromHeartbeat(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /nat http %d", code)
	}
	if ifs, _ := out["ifaces"].([]any); len(ifs) != 0 {
		t.Fatalf("还没有网关上报时网卡清单应为空，实际 %d 条", len(ifs))
	}

	natReportIfaces(t, h)
	_, out = doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	ifs, _ := out["ifaces"].([]any)
	if len(ifs) != 2 {
		t.Fatalf("心跳上报后应有 2 张网卡，实际 %d", len(ifs))
	}
}

// 旧网关不上报 ifaces 字段时**必须保留**库里已有的记录（含管理员定的 LAN/WAN）。
// 按空清单整体替换的话，一台未升级的网关每 15s 就会把定性清空一次，
// 症状是「NAT 策略突然全部校验失败」，看起来像策略坏了。
func TestOldGatewayHeartbeatKeepsIfaces(t *testing.T) {
	h := newTestServer(t)
	natReportIfaces(t, h)
	natTypeIfaces(t, h)

	// 旧网关心跳：完全没有 ifaces 键
	code, _ := doJSON(t, h, "POST", "/api/v1/gateways/register", gatewayToken(), map[string]any{
		"id": "gw-test", "proxy": "127.0.0.1:18443", "spa": "127.0.0.1:18201",
	})
	if code != http.StatusOK {
		t.Fatalf("旧网关注册应正常 http %d", code)
	}
	_, out := doJSON(t, h, "GET", "/api/v1/nat", adminToken(), nil)
	ifs, _ := out["ifaces"].([]any)
	if len(ifs) != 2 {
		t.Fatalf("旧网关心跳不该清空网卡记录，实际剩 %d 条", len(ifs))
	}
	for _, raw := range ifs {
		f, _ := raw.(map[string]any)
		if f["type"] == "" {
			t.Fatalf("管理员定的 LAN/WAN 被心跳清掉了：%v", f)
		}
	}
}

// NAT 策略必须随 gateways/policy 下发给数据面，否则策略只是一条数据库记录。
func TestNATPolicyReachesGatewayPolicy(t *testing.T) {
	h := newTestServer(t)
	natReportIfaces(t, h)
	natTypeIfaces(t, h)

	code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), map[string]any{
		"name": "内网代理上网", "type": "snat", "gatewayId": "gw-test",
		"srcIface": "eth2", "srcAddr": "5.5.0.0/16",
		"dstIface": "eth3", "dstAddr": "155.155.0.0/16", "enabled": true,
	})
	if code != http.StatusOK {
		t.Fatalf("建 SNAT 策略 http %d %v", code, out)
	}
	// 保存那一刻就要回告警（FR-NAT-12：管理员最需要知道「NAT 让 SPA 失效」的时刻
	// 是他刚点下保存时，而不是下次打开页面）。
	if w, _ := out["warnings"].([]any); len(w) == 0 {
		t.Error("保存启用中的 NAT 策略必须当场回风险提示")
	}

	code, pol := doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("拉网关策略 http %d", code)
	}
	nat, ok := pol["nat"].([]any)
	if !ok || len(nat) != 1 {
		t.Fatalf("网关策略里应有 1 条 NAT 规则，实际 %v", pol["nat"])
	}
	got, _ := nat[0].(map[string]any)
	if got["srcAddr"] != "5.5.0.0/16" || got["dstIface"] != "eth3" {
		t.Fatalf("下发的 NAT 规则字段不符：%v", got)
	}
}

// 停用的策略不下发（判定权在控制面，数据面只执行给它的那份），
// 且**别的网关**的策略绝不能被这台领走。
func TestNATDistributionIsScoped(t *testing.T) {
	h := newTestServer(t)
	natReportIfaces(t, h)
	natTypeIfaces(t, h)

	mk := func(name string, enabled bool) {
		code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", adminToken(), map[string]any{
			"name": name, "type": "snat", "gatewayId": "gw-test",
			"srcIface": "eth2", "srcAddr": "5.5.0.0/16",
			"dstIface": "eth3", "dstAddr": "155.155.0.0/16", "enabled": enabled,
		})
		if code != http.StatusOK {
			t.Fatalf("建策略 %s http %d %v", name, code, out)
		}
	}
	mk("启用的", true)
	mk("停用的", false)

	_, pol := doJSON(t, h, "GET", "/api/v1/gateways/policy", gatewayToken(), nil)
	nat, _ := pol["nat"].([]any)
	if len(nat) != 1 {
		t.Fatalf("只应下发启用中的那条，实际 %d 条", len(nat))
	}

	// 另一台网关：拿不到 gw-1 的规则。各网关网卡名与拓扑都不同，
	// 领错规则会灌出一堆不匹配的东西。
	otherTok := testKeys.Sign(auth.Claims{Sub: "gw-2", Role: "gateway", Name: "gw-2"}, tokenTTL)
	_, pol2 := doJSON(t, h, "GET", "/api/v1/gateways/policy", otherTok, nil)
	if nat2, _ := pol2["nat"].([]any); len(nat2) != 0 {
		t.Fatalf("gw-2 不该拿到 gw-test 的 NAT 规则，实际 %d 条", len(nat2))
	}
}

// 写端点归 PermSystem：给 security 的话，安全管理员能用一条 DNAT
// 把内网业务发布到公网——那是绕过整个零信任接入面的捷径。
func TestNATWritesRequireSystemPerm(t *testing.T) {
	h := newTestServer(t)
	natReportIfaces(t, h)
	natTypeIfaces(t, h)

	secTok := makeAdmin(t, h, "sec.only", "security")
	body := map[string]any{
		"name": "越权发布", "type": "snat", "gatewayId": "gw-test",
		"srcIface": "eth2", "srcAddr": "5.5.0.0/16",
		"dstIface": "eth3", "dstAddr": "155.155.0.0/16", "enabled": true,
	}
	if code, out := doJSON(t, h, "POST", "/api/v1/nat/policies", secTok, body); code != http.StatusForbidden {
		t.Fatalf("安全管理员建 NAT 策略应 403，实际 %d %v", code, out)
	}
	// 但读得到（读=任意管理员，角色现算）——看得见配置与看得见风险提示同样重要。
	if code, _ := doJSON(t, h, "GET", "/api/v1/nat", secTok, nil); code != http.StatusOK {
		t.Errorf("安全管理员应能读 NAT 配置，实际 %d", code)
	}
	// 普通用户连读都不行。
	userTok := testKeys.Sign(auth.Claims{Sub: "zhang.wei", Role: "user", Name: "张伟"}, tokenTTL)
	if code, _ := doJSON(t, h, "GET", "/api/v1/nat", userTok, nil); code != http.StatusForbidden {
		t.Errorf("普通用户读 NAT 配置应 403，实际 %d", code)
	}
}
