package natfw

import (
	"go/ast"
	"go/parser"
	"go/token"
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

// FR-NAT-13：七层 Web 代理口必须进 SNAT 排除集。
//
// ★这个字段定义了、nft 与 pf 两个后端都写好了消费方，**唯独没有生产者**——
// 连本文件顶部的 exempt 变量都不填它。于是同时带 -web 与 -nat 启动的网关
// （PRD 8.3.3 的 B/S 免客户端接入 + 第 18 章的出口网关复用，正是手册描述的同一台
// 代理网关），其七层流量不在排除集里。pf 后端尤其真实：
// `nat on <WAN> from <Src> to <Dst> -> (<WAN>)` 对本机发出的报文同样生效，
// 只要网关自身地址落在 Src 网段内，L7 监听发回浏览器的回包与它拨向后端的连接
// 都会被改写源地址——症状是「配了 NAT 之后 B/S 入口时通时不通」。
func TestWebPortsAreExempted(t *testing.T) {
	ex := Exempt{TunnelPort: 18443, SPAPort: 18201, WebPorts: []int{18444}}

	nft := strings.Join(nftExemptRules(ex), "\n")
	for _, want := range []string{"tcp sport 18444 return", "tcp dport 18444 return"} {
		if !strings.Contains(nft, want) {
			t.Errorf("nft 排除集缺 %q：\n%s", want, nft)
		}
	}

	var hasWeb bool
	for _, pp := range exemptPorts(ex) {
		if pp.n == 18444 && pp.proto == "tcp" {
			hasWeb = true
		}
	}
	if !hasWeb {
		t.Error("pf 排除集缺 18444/tcp")
	}

	// 未配 -web 时不该混进一个 0 端口（portOf 对空地址回 0）
	for _, r := range nftExemptRules(Exempt{TunnelPort: 18443, SPAPort: 18201}) {
		if strings.Contains(r, " 0 return") {
			t.Errorf("未配 web 时不该产生 0 端口规则：%s", r)
		}
	}
}

// 生产者那一半：main.go 必须真的把 -web 端口填进 Exempt。
// ★字段有消费方、没生产者时，上面那些断言全都通过而功能是死的——
// 这正是本条缺陷此前的形态，所以判据要一直追到调用点。
//
// ★为什么走 go/parser 而不是 strings.Contains：**文本搜索会命中注释**。
// 改造前这里搜的是 "WebPorts:" 与 "portOf(*webAddr)" 两个子串，而 main.go 那段
// 构造代码上方正好有一段注释，逐字写着这两个词（那段注释解释的正是本缺陷）。
// 实测：把 `WebPorts: webPorts,` 整行注释掉（补 `_ = webPorts` 让它编得过），
// 本用例照旧 PASS——守卫等于不存在，而现场后果是同时带 -web 与 -nat 的网关
// 其 L7 回包与拨后端的连接一起被 SNAT 改写源地址（「配了 NAT 之后 B/S 入口
// 时通时不通」，两侧零报错）。注释不进语法树，换成 AST 之后
// 「注释里写了」与「代码里做了」在判据上再也不同形。
func TestWebPortsHaveProducer(t *testing.T) {
	const mainPath = "../../cmd/baidi-gateway/main.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, mainPath, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("解析 %s: %v", mainPath, err)
	}

	// ① 找到 natfw.Exempt{…} 这个构造点本身。
	var lit *ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := cl.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "natfw" && sel.Sel.Name == "Exempt" {
			lit = cl
		}
		return true
	})
	if lit == nil {
		t.Fatal("main.go 里找不到 natfw.Exempt{…} 构造点：排除集没有生产者，" +
			"nft/pf 两侧的消费方永远收到零值，隧道口与敲门口也一起不被排除")
	}

	// ② WebPorts 必须是这个字面量里真实存在的一个 key。
	var val ast.Expr
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "WebPorts" {
			val = kv.Value
		}
	}
	if val == nil {
		t.Fatal("main.go 构造 natfw.Exempt 时必须填 WebPorts——" +
			"否则 nft/pf 两侧的消费方永远收到空切片，FR-NAT-13 的排除规则等于不存在")
	}

	// ③ 值要能**追到** portOf(*webAddr)。当前写法是先算进一个局部变量
	//    （`if p := portOf(*webAddr); p > 0 { webPorts = append(webPorts, p) }`），
	//    所以这里做一次赋值定点传播，而不是只认「值就字面写着那个调用」——
	//    只认字面写法会逼着实现去迁就测试，而判据本来就是「端口取自 -web 监听地址」。
	tainted := map[string]bool{}
	var collected []ast.Expr
	if id, ok := val.(*ast.Ident); ok {
		tainted[id.Name] = true
	} else {
		collected = append(collected, val)
	}
	for range 8 { // 传播链就那么两跳，8 轮足够到定点
		grew := false
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			hit := false
			for _, l := range as.Lhs {
				if li, ok := l.(*ast.Ident); ok && tainted[li.Name] {
					hit = true
				}
			}
			if !hit {
				return true
			}
			for _, r := range as.Rhs {
				collected = append(collected, r)
				ast.Inspect(r, func(m ast.Node) bool {
					if mi, ok := m.(*ast.Ident); ok && !tainted[mi.Name] {
						tainted[mi.Name] = true
						grew = true
					}
					return true
				})
			}
			return true
		})
		if !grew {
			break
		}
	}
	found := false
	for _, e := range collected {
		ast.Inspect(e, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || fn.Name != "portOf" {
				return true
			}
			star, ok := call.Args[0].(*ast.StarExpr)
			if !ok {
				return true
			}
			// 只认 *webAddr：main.go 里还有 portOf(*proxyAddr)/portOf(*spaAddr)
			// 两个同名调用，认宽了就等于不认。
			if id, ok := star.X.(*ast.Ident); ok && id.Name == "webAddr" {
				found = true
			}
			return true
		})
	}
	if !found {
		t.Error("WebPorts 的值追不到 portOf(*webAddr)：排除的必须是 -web 真正监听的那个端口，" +
			"填成常量或别的端口时规则集保护的是别人，L7 流量照样被 SNAT 改写源地址")
	}
}
