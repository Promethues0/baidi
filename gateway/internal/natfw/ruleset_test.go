package natfw

import (
	"strings"
	"testing"
)

// 规则生成是本包**唯一能在无 root 主机上验到的部分**，所以逐字断言而不是只看不报错：
// Linux 的 nft 语法在 mac 上没有任何东西会替我们检查它，写错了要到真机才炸。

var exempt = Exempt{TunnelPort: 18443, SPAPort: 18201}

func TestSnatRuleShape(t *testing.T) {
	rs := BuildNft([]Policy{{
		ID: "nat-1", Name: "内网代理上网", Type: "snat",
		SrcIface: "eth2", SrcAddr: "5.5.0.0/16",
		DstIface: "eth3", DstAddr: "155.155.0.0/16", Protocol: "all",
	}}, exempt)

	want := `iifname "eth2" oifname "eth3" ip saddr 5.5.0.0/16 ip daddr 155.155.0.0/16 counter masquerade comment "baidi:nat-1"`
	if !strings.Contains(rs, want) {
		t.Fatalf("SNAT 规则不符，期望包含：\n%s\n实际：\n%s", want, rs)
	}
	if !strings.Contains(rs, "type nat hook postrouting priority srcnat") {
		t.Error("SNAT 必须挂在 postrouting/srcnat：挂错钩子的话规则语法正确但永远不匹配")
	}
}

// FR-NAT-13：隧道与敲门流量必须被排除，且排除规则要排在转换规则**之前**。
// 顺序错了等于没排除——nft 是首次匹配即执行。
func TestTunnelTrafficExemptedBeforeSnat(t *testing.T) {
	rs := BuildNft([]Policy{{
		ID: "nat-1", Type: "snat", SrcIface: "eth2", SrcAddr: "5.5.0.0/16",
		DstIface: "eth3", DstAddr: "0.0.0.0/0", Protocol: "all",
	}}, exempt)

	for _, want := range []string{
		"tcp sport 18443 return", "tcp dport 18443 return",
		"udp sport 18201 return", "udp dport 18201 return",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("缺排除规则 %q——被 SNAT 改写源地址后隧道回包找不到发起方，症状是「配了 NAT 隧道就断」", want)
		}
	}
	exemptAt := strings.Index(rs, "tcp dport 18443 return")
	snatAt := strings.Index(rs, "masquerade")
	if exemptAt < 0 || snatAt < 0 || exemptAt > snatAt {
		t.Fatalf("排除规则必须排在 SNAT 之前（nft 首次匹配即执行）：exempt@%d snat@%d", exemptAt, snatAt)
	}
}

func TestDnatRuleShape(t *testing.T) {
	rs := BuildNft([]Policy{{
		ID: "nat-2", Type: "dnat", SrcIface: "eth2", SrcAddr: "0.0.0.0/0",
		DstIface: "eth3", DstAddr: "5.5.10.102", Protocol: "tcp",
		DstPort: 9999, TranslatedAddr: "155.155.235.212", TranslatedPort: 8081,
	}}, exempt)

	want := `iifname "eth2" ip daddr 5.5.10.102 tcp dport 9999 counter dnat to 155.155.235.212:8081 comment "baidi:nat-2"`
	if !strings.Contains(rs, want) {
		t.Fatalf("DNAT 规则不符，期望包含：\n%s\n实际：\n%s", want, rs)
	}
	if !strings.Contains(rs, "type nat hook prerouting priority dstnat") {
		t.Error("DNAT 必须挂在 prerouting/dstnat")
	}
}

// 源地址限制是 DNAT 的收敛面：0.0.0.0/0 可以省略（nft 里恒真），
// 但**非全放行时漏掉这一句，就是把「只允许某公网段」悄悄变成对全网公开**。
func TestDnatSourceRestrictionNeverDropped(t *testing.T) {
	rs := BuildNft([]Policy{{
		ID: "nat-3", Type: "dnat", SrcIface: "eth2", SrcAddr: "203.0.113.0/24",
		DstIface: "eth3", DstAddr: "5.5.10.102", Protocol: "tcp",
		DstPort: 443, TranslatedAddr: "10.0.0.9", TranslatedPort: 8443,
	}}, exempt)
	if !strings.Contains(rs, "ip saddr 203.0.113.0/24") {
		t.Fatalf("限定了源网段却没生成 saddr 条件——这条规则对全网开放：\n%s", rs)
	}

	open := BuildNft([]Policy{{
		ID: "nat-4", Type: "dnat", SrcIface: "eth2", SrcAddr: "0.0.0.0/0",
		DstIface: "eth3", DstAddr: "5.5.10.102", Protocol: "tcp",
		DstPort: 80, TranslatedAddr: "10.0.0.9", TranslatedPort: 8080,
	}}, exempt)
	if strings.Contains(open, "ip saddr 0.0.0.0/0") {
		t.Error("0.0.0.0/0 是恒真条件，不该写进规则（噪音）")
	}
}

// ICMP 没有端口：带上 dport 会让 nft 直接语法错误，整份规则集灌不进去
// ——一条策略配错会连累其余全部 NAT 规则失效。
func TestIcmpDnatHasNoPort(t *testing.T) {
	rs := BuildNft([]Policy{{
		ID: "nat-5", Type: "dnat", SrcIface: "eth2", SrcAddr: "0.0.0.0/0",
		DstIface: "eth3", DstAddr: "5.5.10.102", Protocol: "icmp",
		TranslatedAddr: "10.0.0.9",
	}}, exempt)
	if !strings.Contains(rs, "ip protocol icmp counter dnat to 10.0.0.9") {
		t.Fatalf("ICMP DNAT 规则不符：\n%s", rs)
	}
	// 只看这一条规则行——排除规则里的 "tcp dport 18443 return" 是合法的，
	// 拿整份规则集去搜 dport 会把它一起搜到（本用例第一版就是这么误报的）。
	line := ruleLine(t, rs, "baidi:nat-5")
	if strings.Contains(line, "dport") {
		t.Errorf("ICMP 规则里不该出现 dport（nft 会直接语法错误，导致整份规则集灌不进去）：%s", line)
	}
}

// ruleLine 取出注释含 marker 的那一行，供「只针对某条规则」的断言使用。
func ruleLine(t *testing.T, ruleset, marker string) string {
	t.Helper()
	for _, l := range strings.Split(ruleset, "\n") {
		if strings.Contains(l, marker) {
			return strings.TrimSpace(l)
		}
	}
	t.Fatalf("规则集里找不到 %s：\n%s", marker, ruleset)
	return ""
}

// 「所有协议」+ 指定端口：只有 tcp/udp 有端口概念，必须展开成两者，
// 而不是把端口条件丢掉（丢掉 = 把整个 IP 全部端口都映射过去）。
func TestAllProtocolWithPortExpandsTcpUdp(t *testing.T) {
	rs := BuildNft([]Policy{{
		ID: "nat-6", Type: "dnat", SrcIface: "eth2", SrcAddr: "0.0.0.0/0",
		DstIface: "eth3", DstAddr: "5.5.10.102", Protocol: "all",
		DstPort: 9999, TranslatedAddr: "10.0.0.9", TranslatedPort: 8081,
	}}, exempt)
	if !strings.Contains(rs, "meta l4proto { tcp, udp } th dport 9999") {
		t.Fatalf("all+端口应展开成 tcp/udp 两协议：\n%s", rs)
	}
}

// 同一批策略必须每次生成逐字相同的文本：Apply 靠文本比较决定要不要重灌内核，
// 顺序抖动会导致每轮都误判成「有变化」并 flush 一次 nat 表，
// 而 flush 的瞬间存在规则真空（偶发连接失败，极难复现）。
func TestRulesetIsDeterministic(t *testing.T) {
	ps := []Policy{
		{ID: "nat-b", Type: "snat", SrcIface: "eth2", SrcAddr: "10.0.0.0/8", DstIface: "eth3", DstAddr: "0.0.0.0/0"},
		{ID: "nat-a", Type: "snat", SrcIface: "eth2", SrcAddr: "172.16.0.0/12", DstIface: "eth3", DstAddr: "0.0.0.0/0"},
	}
	first := BuildNft(ps, exempt)
	shuffled := []Policy{ps[1], ps[0]}
	if second := BuildNft(shuffled, exempt); first != second {
		t.Fatal("同一批策略换个顺序就生成不同文本——Apply 会每轮误判有变化并重灌内核")
	}
	if strings.Index(first, "baidi:nat-a") > strings.Index(first, "baidi:nat-b") {
		t.Error("规则应按策略 id 排序")
	}
}

// 空策略集不能生成「一张空表」之外的东西，且 Apply 会走整表删除路径。
func TestEmptyPolicySetStillWellFormed(t *testing.T) {
	rs := BuildNft(nil, exempt)
	if !strings.Contains(rs, "table ip "+NftTable) {
		t.Fatal("空策略集也要产出结构完整的规则集")
	}
	if strings.Contains(rs, "masquerade") || strings.Contains(rs, "dnat to") {
		t.Error("空策略集不该有任何转换规则")
	}
}

func TestPfRulesetShape(t *testing.T) {
	ps := []Policy{
		{ID: "nat-1", Type: "snat", SrcIface: "en0", SrcAddr: "5.5.0.0/16", DstIface: "en1", DstAddr: "155.155.0.0/16"},
		{ID: "nat-2", Type: "dnat", SrcIface: "en0", SrcAddr: "0.0.0.0/0", DstIface: "en1",
			DstAddr: "5.5.10.102", Protocol: "tcp", DstPort: 9999, TranslatedAddr: "155.155.235.212", TranslatedPort: 8081},
	}
	rs := BuildPf(ps, exempt)
	if !strings.Contains(rs, "nat on en1 from 5.5.0.0/16 to 155.155.0.0/16 -> (en1)") {
		t.Errorf("pf SNAT 规则不符：\n%s", rs)
	}
	if !strings.Contains(rs, "rdr on en0 proto tcp from any to 5.5.10.102 port 9999 -> 155.155.235.212 port 8081") {
		t.Errorf("pf DNAT(rdr) 规则不符：\n%s", rs)
	}
	// pf 的 no nat 必须排在 nat 之前才优先生效。
	if strings.Index(rs, "no nat on any proto tcp") > strings.Index(rs, "nat on en1") {
		t.Error("pf 的 no nat 排除规则必须排在 nat 规则之前")
	}
}

// Apply 在内容无变化时不得重复灌内核（DryRun 下可验证这条控制流）。
func TestApplySkipsUnchangedRuleset(t *testing.T) {
	a := New(exempt)
	a.DryRun = true
	ps := []Policy{{ID: "nat-1", Type: "snat", SrcIface: "eth2", SrcAddr: "10.0.0.0/8", DstIface: "eth3", DstAddr: "0.0.0.0/0"}}

	if changed, err := a.Apply(ps); err != nil || !changed {
		t.Fatalf("首次应用应判定为有变化：changed=%v err=%v", changed, err)
	}
	if changed, err := a.Apply(ps); err != nil || changed {
		t.Fatalf("同一批策略再次应用不该重灌：changed=%v err=%v", changed, err)
	}
	ps[0].SrcAddr = "192.168.0.0/16"
	if changed, err := a.Apply(ps); err != nil || !changed {
		t.Fatalf("策略变化后必须重灌：changed=%v err=%v", changed, err)
	}
}
