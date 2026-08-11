package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func natSeedIfaces(t *testing.T, s *SQLiteStore) {
	t.Helper()
	ctx := context.Background()
	if err := s.ReplaceGatewayIfaces(ctx, "gw-1", []GatewayIface{
		{Name: "eth2", Addrs: []string{"5.5.10.102/16"}, Up: true},
		{Name: "eth3", Addrs: []string{"155.155.10.102/16"}, Up: true},
	}); err != nil {
		t.Fatalf("上报网卡: %v", err)
	}
	if err := s.SetGatewayIfaceType(ctx, "gw-1", "eth2", IfaceLAN); err != nil {
		t.Fatalf("定性 eth2: %v", err)
	}
	if err := s.SetGatewayIfaceType(ctx, "gw-1", "eth3", IfaceWAN); err != nil {
		t.Fatalf("定性 eth3: %v", err)
	}
}

func snatFixture() NATPolicy {
	return NATPolicy{
		Name: "内网代理上网", Type: NATSnat, GatewayID: "gw-1",
		SrcIface: "eth2", SrcAddr: "5.5.0.0/16",
		DstIface: "eth3", DstAddr: "155.155.0.0/16", Enabled: true,
	}
}

func TestSaveSnatAndDnatRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	natSeedIfaces(t, s)

	got, err := s.SaveNATPolicy(ctx, snatFixture())
	if err != nil {
		t.Fatalf("保存 SNAT: %v", err)
	}
	if got.ID == "" || got.Protocol != NATProtoAll {
		t.Fatalf("SNAT 应自动分配 id 并归一协议为 all：%+v", got)
	}

	dnat := NATPolicy{
		Name: "发布 OA", Type: NATDnat, GatewayID: "gw-1",
		SrcIface: "eth3", SrcAddr: "0.0.0.0/0", // DNAT：源=WAN
		DstIface: "eth2", DstAddr: "5.5.10.102", Protocol: NATProtoTCP,
		DstPort: 9999, TranslatedAddr: "155.155.235.212", TranslatedPort: 8081, Enabled: true,
	}
	if _, err := s.SaveNATPolicy(ctx, dnat); err != nil {
		t.Fatalf("保存 DNAT: %v", err)
	}
	ps, err := s.NATPolicies(ctx)
	if err != nil || len(ps) != 2 {
		t.Fatalf("应有 2 条策略：%v（err=%v）", len(ps), err)
	}
}

// 方向选反是 NAT 最常见的配置错误，而它的症状是「规则灌进内核后一条流量都不匹配」
// ——没有报错、没有日志。必须在保存那一刻就拦住。
func TestWrongDirectionRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	natSeedIfaces(t, s)

	p := snatFixture()
	p.SrcIface, p.DstIface = "eth3", "eth2" // SNAT 却把 WAN 当源口
	_, err := s.SaveNATPolicy(ctx, p)
	if !errors.Is(err, ErrNATIfaceWrongDir) {
		t.Fatalf("SNAT 源口用 WAN 应被拒，实际 err=%v", err)
	}
	if !strings.Contains(err.Error(), "方向选反") {
		t.Errorf("错误文案要能指导下一步动作，实际：%v", err)
	}
}

func TestUnknownAndUntypedIfaceRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	natSeedIfaces(t, s)

	p := snatFixture()
	p.SrcIface = "eth9" // 网关没上报过
	if _, err := s.SaveNATPolicy(ctx, p); !errors.Is(err, ErrNATIfaceUnknown) {
		t.Errorf("未上报的网卡应被拒，实际 %v", err)
	}

	// 上报了但没定性 LAN/WAN 的卡同样不能用：没定性就无从判断方向。
	if err := s.ReplaceGatewayIfaces(ctx, "gw-1", []GatewayIface{
		{Name: "eth2", Up: true}, {Name: "eth3", Up: true}, {Name: "eth4", Up: true},
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.SetGatewayIfaceType(ctx, "gw-1", "eth3", IfaceWAN)
	p2 := snatFixture()
	p2.SrcIface = "eth4"
	if _, err := s.SaveNATPolicy(ctx, p2); !errors.Is(err, ErrNATIfaceUntyped) {
		t.Errorf("未定性的网卡应被拒，实际 %v", err)
	}
}

// 网卡清单每 15s 被心跳整体替换一次，但**管理员定的 LAN/WAN 必须保留**。
// 不保留的话，管理员每隔 15 秒就会发现自己的定性没了，
// 而症状是「NAT 策略突然全部校验失败」，看起来像策略坏了。
func TestIfaceTypeSurvivesHeartbeatReplace(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	natSeedIfaces(t, s)

	// 模拟下一次心跳：同样两张卡，地址略有变化
	if err := s.ReplaceGatewayIfaces(ctx, "gw-1", []GatewayIface{
		{Name: "eth2", Addrs: []string{"5.5.10.103/16"}, Up: true},
		{Name: "eth3", Addrs: []string{"155.155.10.102/16"}, Up: false},
	}); err != nil {
		t.Fatal(err)
	}
	ifs, err := s.GatewayIfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, f := range ifs {
		types[f.Name] = f.Type
	}
	if types["eth2"] != IfaceLAN || types["eth3"] != IfaceWAN {
		t.Fatalf("心跳替换后管理员定的类型必须保留，实际 %+v", types)
	}
	// 保留了定性，策略也必须还能存
	if _, err := s.SaveNATPolicy(ctx, snatFixture()); err != nil {
		t.Fatalf("定性仍在时策略应可保存：%v", err)
	}
}

func TestNATValidation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	natSeedIfaces(t, s)

	bad := []struct {
		name string
		mut  func(*NATPolicy)
		want string
	}{
		{"空名称", func(p *NATPolicy) { p.Name = "  " }, "名称"},
		{"非法网段", func(p *NATPolicy) { p.SrcAddr = "5.5.0.0/99" }, "网段"},
		// 源目填同一张卡时报的是**方向错误**而非「同卡」：LAN/WAN 定性已经蕴含了
		// 两者必然不同卡，故不存在单独的同卡检查（那会是永远不触发的死代码）。
		{"源目同卡→方向错误", func(p *NATPolicy) { p.DstIface = "eth2" }, "方向选反"},
		{"无网关", func(p *NATPolicy) { p.GatewayID = "" }, "网关"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			p := snatFixture()
			c.mut(&p)
			_, err := s.SaveNATPolicy(ctx, p)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("应因「%s」被拒，实际 err=%v", c.want, err)
			}
		})
	}

	// ICMP 带端口：生成的 nft 规则会语法错误，导致**整份**规则集灌不进去
	// ——一条策略配错连累其余全部 NAT 失效，必须在入口拦。
	icmp := NATPolicy{
		Name: "ping 转发", Type: NATDnat, GatewayID: "gw-1",
		SrcIface: "eth3", SrcAddr: "0.0.0.0/0", DstIface: "eth2", DstAddr: "5.5.10.102",
		Protocol: NATProtoICMP, DstPort: 80, TranslatedAddr: "10.0.0.9",
	}
	if _, err := s.SaveNATPolicy(ctx, icmp); err == nil || !strings.Contains(err.Error(), "ICMP") {
		t.Fatalf("ICMP 带端口应被拒，实际 %v", err)
	}
}

// SNAT 不该带转换后数据：带着落库的话页面上会显示一组永不生效的值。
func TestSnatStripsDnatOnlyFields(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	natSeedIfaces(t, s)

	p := snatFixture()
	p.TranslatedAddr, p.TranslatedPort, p.DstPort = "1.2.3.4", 8080, 9999
	got, err := s.SaveNATPolicy(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.TranslatedAddr != "" || got.TranslatedPort != 0 || got.DstPort != 0 {
		t.Fatalf("SNAT 必须清掉 DNAT 专属字段，实际 %+v", got)
	}
}

// 网段归一：10.1.2.3/16 落库成 10.1.0.0/16。不归一的话同一个网段有多种写法，
// 「规则是否变化」的比较会失准，网关每轮都会误判成有变化并重灌内核。
func TestCidrIsMasked(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	natSeedIfaces(t, s)

	p := snatFixture()
	p.SrcAddr = "5.5.10.102/16"
	got, err := s.SaveNATPolicy(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.SrcAddr != "5.5.0.0/16" {
		t.Fatalf("网段应归一为 5.5.0.0/16，实际 %s", got.SrcAddr)
	}
}

// 下发过滤：只给本网关、且只给启用中的策略。
func TestNATForGatewayFiltersByGatewayAndEnabled(t *testing.T) {
	all := []NATPolicy{
		{ID: "a", GatewayID: "gw-1", Enabled: true},
		{ID: "b", GatewayID: "gw-1", Enabled: false},
		{ID: "c", GatewayID: "gw-2", Enabled: true},
	}
	got := NATForGateway(all, "gw-1")
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("只应下发本网关启用中的策略，实际 %+v", got)
	}
	// 认不出网关身份时下发空集（fail-closed）：宁可不配 NAT，
	// 也不能把别人的规则灌进这台机器。
	if n := len(NATForGateway(all, "")); n != 0 {
		t.Fatalf("网关 id 为空时应下发空集，实际 %d 条", n)
	}
}

// 告警只在真有启用中的策略时给：没启用 NAT 的系统天天弹一条
// 「NAT 会让 SPA 失效」，只会让人对这条提示麻木。
func TestWarningsOnlyWhenEnabled(t *testing.T) {
	if w := NATWarnings(nil); len(w) != 0 {
		t.Errorf("无策略不该有告警，实际 %v", w)
	}
	if w := NATWarnings([]NATPolicy{{Enabled: false}}); len(w) != 0 {
		t.Errorf("全部停用不该有告警，实际 %v", w)
	}
	w := NATWarnings([]NATPolicy{{Enabled: true}})
	if len(w) == 0 || !strings.Contains(w[0], "SPA") {
		t.Fatalf("启用后必须当面给出 SPA 互斥告警（FR-NAT-12），实际 %v", w)
	}
}
