// Command baidi-ipsec-e2e 是白帝**站点组网全链路自检**。
//
// 它要回答的不是「跑通了吗」，而是「凭什么说这是真的 IPSec」。因此每一条断言
// 都对应一种具体的「假通过」，并在输出里写明它排除了什么——一条断言若无法排除
// 任何东西，就不该存在（`return nil` 也能过的断言等于没有）。
//
// 分两部分，各自回答链路的一半：
//
//	【甲】真守护进程 —— 由 ipsec-e2e.sh 起两个真正的 baidi-ipsec 进程，本程序只经
//	      控制面 API 观察。回答：控制面下发的配置真的驱动了协商吗？回报的状态是
//	      实测值还是配置回显？改坏 PSK / 关掉 enabled 会不会如实反映？
//
//	【乙】进程内节点 —— 本程序自己托管两个 IPSec 节点（各带 gVisor netstack），
//	      跨隧道跑真实 HTTP。回答：ESP 真的加密了吗？密文里有明文吗？拆掉 SA 之后
//	      业务是不是真的断了（而不是一直在走旁路直连）？
//
// 为什么必须分两部分：netstack 数据面是**进程内**的，外部进程无从往它里面发包；
// 而只在进程内跑又证明不了「真的那个二进制在按控制面的配置干活」。两半合起来
// 才覆盖完整链路。唯一未覆盖的是 TUN 建卡（需 root），那一段由 datapath_tun.go 承担。
//
// 用法：先跑 gateway/ipsec-e2e.sh（它负责起栈、隔离数据库、预检端口）。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/esp"
	"baidi.dev/gateway/internal/ipsec/ike"
	"baidi.dev/gateway/internal/ipsec/site"
)

// control 控制面明文口。与 e2e.sh 的约定一致。
const control = "http://127.0.0.1:8090"

// canary 一段绝不该出现在密文里的明文标记。选一个足够长、足够独特的串，
// 避免与协议字节偶然碰撞造成假阴性。
const canary = "BAIDI-IPSEC-PLAINTEXT-CANARY-b7f3a91c"

var failures int

func ok(f string, a ...any)   { fmt.Printf("   ✓ "+f+"\n", a...) }
func info(f string, a ...any) { fmt.Printf("     %s\n", fmt.Sprintf(f, a...)) }

// die 记一条失败但**继续往下跑**：一次跑出全部问题，比修一个跑一次高效得多。
func die(f string, a ...any) {
	fmt.Printf("   ✗ "+f+"\n", a...)
	failures++
}

func fatal(f string, a ...any) {
	fmt.Printf("   ✗ "+f+"\n", a...)
	fmt.Println("\n（这一步是后续断言的前提，无法继续）")
	os.Exit(1)
}

func main() {
	// 排障开关：BAIDI_IPSEC_E2E_ONLY=a|b 只跑其中一半。
	// 甲需要 ipsec-e2e.sh 起好两个守护进程，乙不需要——分开跑能大幅缩短一次排障循环。
	only := os.Getenv("BAIDI_IPSEC_E2E_ONLY")

	if only != "b" {
		fmt.Println("════════ 甲、真守护进程：控制面 ↔ 数据面闭环 ════════")
		partA()
		fmt.Println()
	}
	if only != "a" {
		fmt.Println("════════ 乙、进程内节点：数据面真加密与真互通 ════════")
		partB()
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("✗ 自检失败：%d 条断言未通过\n", failures)
		os.Exit(1)
	}
	fmt.Println("✅ IPSec 全链路通过")
}

// ── 控制面 HTTP 小工具 ──

func adminToken() string {
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "baidi@123"})
	resp, err := http.Post(control+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		fatal("控制面不可达：%v", err)
	}
	defer resp.Body.Close()
	var r struct{ Token string }
	_ = json.NewDecoder(resp.Body).Decode(&r)
	if r.Token == "" {
		fatal("admin 登录失败")
	}
	return r.Token
}

func api(tok, method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, control+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal("请求 %s %s 失败：%v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// saState 控制面回报的一条运行态（字段取自 store.IpsecSAState）。
type saState struct {
	SiteID             string `json:"siteId"`
	GatewayID          string `json:"gatewayId"`
	State              string `json:"state"`
	IKESPIi            string `json:"ikeSpiI"`
	IKESPIr            string `json:"ikeSpiR"`
	ChildSPIIn         uint32 `json:"childSpiIn"`
	ChildSPIOut        uint32 `json:"childSpiOut"`
	NegotiatedProposal string `json:"negotiatedProposal"`
	EstablishedAt      int64  `json:"establishedAt"`
	LastError          string `json:"lastError"`
}

func states(tok string) map[string]saState {
	code, b := api(tok, "GET", "/api/v1/ipsec", nil)
	if code != 200 {
		fatal("读站点清单失败：HTTP %d %s", code, string(b))
	}
	var r struct {
		States []saState `json:"states"`
	}
	_ = json.Unmarshal(b, &r)
	out := map[string]saState{}
	for _, s := range r.States {
		// 同一站点可能被两台网关回报（各自视角），按 siteId+gatewayId 区分。
		out[s.SiteID+"@"+s.GatewayID] = s
	}
	return out
}

// waitState 轮询直到 pred 成立或超时。
// 全程不用固定 sleep：协商耗时受机器负载影响，固定等待要么慢要么随机红。
func waitState(tok string, d time.Duration, pred func(map[string]saState) bool) map[string]saState {
	deadline := time.Now().Add(d)
	var last map[string]saState
	for time.Now().Before(deadline) {
		last = states(tok)
		if pred(last) {
			return last
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

// ── 甲、真守护进程 ──

func partA() {
	tok := adminToken()

	fmt.Println("① 等两个 baidi-ipsec 完成协商（配置由控制面下发，不是本程序塞给它们的）")
	st := waitState(tok, 90*time.Second, func(m map[string]saState) bool {
		var up int
		for _, s := range m {
			if s.State == "up" {
				up++
			}
		}
		return up >= 2
	})
	var a, b saState
	for _, s := range st {
		switch s.GatewayID {
		case "ipsec-a":
			a = s
		case "ipsec-b":
			b = s
		}
	}
	if a.State != "up" || b.State != "up" {
		for k, s := range st {
			info("%s → state=%s lastError=%s", k, s.State, s.LastError)
		}
		fatal("两端未在 90s 内建立隧道（A=%s B=%s）", a.State, b.State)
	}
	ok("两端 state=up，协商结果：%s", a.NegotiatedProposal)

	fmt.Println("② SPI 交叉相等（排除「控制面自己把 state 改成 up」——旧实现正是如此）")
	// ★这是最硬的一条：A 的入向 SPI 是 A 自己生成、经 IKE 报文告诉 B 的，
	// B 把它记为出向。单端伪造不出这种交叉关系——除非两端真的交换过报文。
	if a.ChildSPIIn == 0 || b.ChildSPIIn == 0 {
		die("Child SPI 为 0，说明没有真正装载 SA")
	} else if a.ChildSPIIn != b.ChildSPIOut || b.ChildSPIIn != a.ChildSPIOut {
		die("SPI 不交叉：A(in=%#x out=%#x) B(in=%#x out=%#x)",
			a.ChildSPIIn, a.ChildSPIOut, b.ChildSPIIn, b.ChildSPIOut)
	} else {
		ok("A.in=%#x == B.out=%#x，B.in=%#x == A.out=%#x", a.ChildSPIIn, b.ChildSPIOut, b.ChildSPIIn, a.ChildSPIOut)
	}
	if a.IKESPIi == "" || a.IKESPIi == strings.Repeat("0", 16) {
		die("IKE SPIi 为空/全零")
	} else if a.IKESPIi != b.IKESPIi || a.IKESPIr != b.IKESPIr {
		die("两端 IKE SPI 不一致：A(%s/%s) B(%s/%s)", a.IKESPIi, a.IKESPIr, b.IKESPIi, b.IKESPIr)
	} else {
		ok("IKE SPI 两端一致：%s / %s", a.IKESPIi[:8]+"…", a.IKESPIr[:8]+"…")
	}

	fmt.Println("③ establishedAt 是真实时刻（排除「种子常量」与「中文相对时间串」）")
	if a.EstablishedAt <= 0 {
		die("establishedAt=%d，不是有效 Unix 时刻", a.EstablishedAt)
	} else if delta := time.Since(time.Unix(a.EstablishedAt, 0)); delta > 10*time.Minute || delta < -time.Minute {
		die("establishedAt 距今 %v，不像是本次协商产生的", delta)
	} else {
		ok("establishedAt=%s（%.0fs 前）", time.Unix(a.EstablishedAt, 0).Format("15:04:05"), time.Since(time.Unix(a.EstablishedAt, 0)).Seconds())
	}

	fmt.Println("④ 反例：改坏 PSK → 下次协商必须 AUTHENTICATION_FAILED，且原因能读到")
	// ★这一步串通「控制面 → 数据面 → 回报 → UI」整条链。只验成功路径的话，
	// 一个「回报通道只在成功时工作」的实现也能全绿。
	code, body := api(tok, "PUT", "/api/v1/ipsec/e2e-a/psk", map[string]string{"psk": "wrong-psk-deliberately-set-by-e2e"})
	if code != 200 {
		die("改 PSK 失败：HTTP %d %s", code, string(body))
	} else {
		bad := waitState(tok, 120*time.Second, func(m map[string]saState) bool {
			for _, s := range m {
				if strings.Contains(s.LastError, "AUTHENTICATION_FAILED") {
					return true
				}
			}
			return false
		})
		var hit string
		for _, s := range bad {
			if strings.Contains(s.LastError, "AUTHENTICATION_FAILED") {
				hit = s.LastError
			}
		}
		if hit == "" {
			for k, s := range bad {
				info("%s → state=%s lastError=%q", k, s.State, s.LastError)
			}
			die("改坏 PSK 后未回报 AUTHENTICATION_FAILED —— 失败路径没有被如实回报")
		} else {
			ok("回报到失败原因：%s", hit)
		}
	}

	fmt.Println("⑤ 反例：toggle enabled=false → SA 必须被拆（排除「enabled 只是装饰字段」）")
	code, body = api(tok, "POST", "/api/v1/ipsec/e2e-b/toggle", nil)
	if code != 200 {
		die("toggle 失败：HTTP %d %s", code, string(body))
	} else {
		down := waitState(tok, 90*time.Second, func(m map[string]saState) bool {
			for _, s := range m {
				if s.SiteID == "e2e-b" && s.State == "down" {
					return true
				}
			}
			return false
		})
		var got string
		for _, s := range down {
			if s.SiteID == "e2e-b" {
				got = s.State
			}
		}
		if got != "down" {
			die("toggle 停用后 state=%q，期望 down", got)
		} else {
			ok("站点已停用，state=down（且不是 failed —— 管理意图与故障是两回事）")
		}
	}
}

// ── 乙、进程内节点 ──

// node 一个进程内 IPSec 节点：UDP 通道 + netstack 数据面 + IKE 状态机 + ESP + 编排。
type node struct {
	udp     *ipsec.UDPTransport
	dp      *ipsec.NetstackDatapath
	prot    ipsec.Protector
	engine  *ike.Engine
	backend ipsec.Backend
	cancel  context.CancelFunc
	done    chan struct{}
}

// wiretap 记录所有经过网络的字节，供「密文里不该有明文」这类断言扫描。
type wiretap struct {
	inner ipsec.Transport
	sent  [][]byte
}

func (w *wiretap) Send(d ipsec.Datagram) error {
	w.sent = append(w.sent, append([]byte(nil), d.Payload...))
	return w.inner.Send(d)
}
func (w *wiretap) Recv() (ipsec.Datagram, error) { return w.inner.Recv() }
func (w *wiretap) Close() error                  { return w.inner.Close() }

// newNode 起一个进程内节点。
//
// ★bind 必须逐节点不同、而 ikePort/nattPort 两端**必须相同**——这是刻意镜像生产语义：
// RFC 3948 把 UDP 封装口定死为 4500，IKEv2 没有通告「对端封装端口」的机制，
// 所以实现只能按对称假设推算对端的 ESP 落点。若图省事让两个节点在同一个 IP 上各拿
// 一个随机端口，测出来的就是一条生产中不存在的路径，反而会掩盖真实缺陷
// （本项目就是这么漏掉「无 NAT 时 ESP 发错端口」的）。
func newNode(gwID string, bind netip.Addr, ikePort, nattPort uint16, local netip.Prefix, log *slog.Logger) (*node, *wiretap) {
	tr, err := ipsec.NewUDPTransport(bind, ikePort, nattPort)
	if err != nil {
		fatal("绑定 UDP %s:%d/%d 失败：%v", bind, ikePort, nattPort, err)
	}
	udp := tr.(*ipsec.UDPTransport)
	tap := &wiretap{inner: udp}

	dp, err := ipsec.NewNetstackDatapath(local, ipsec.DefaultTunnelMTU)
	if err != nil {
		fatal("建 netstack 数据面失败：%v", err)
	}
	prot := esp.New(log, time.Now)
	late := newLate()
	engine := ike.NewEngine(ike.EngineOptions{
		Transport: late, Protector: prot,
		LocalIKE: udp.LocalIKE(), LocalNAT: udp.LocalNAT(), Log: log,
	})
	backend, err := site.NewBackend(site.BackendOptions{
		GatewayID: gwID, Transport: tap, Datapath: dp,
		IKE: engine, Protector: prot, Log: log,
	})
	if err != nil {
		fatal("组装后端失败：%v", err)
	}
	late.set(backend.IKETransport())

	ctx, cancel := context.WithCancel(context.Background())
	n := &node{udp: udp, dp: dp, prot: prot, engine: engine, backend: backend, cancel: cancel, done: make(chan struct{})}
	go func() { defer close(n.done); _ = engine.Run(ctx) }()
	return n, tap
}

func (n *node) close() {
	n.cancel()
	<-n.done
	_ = n.backend.Close()
	_ = n.dp.Close()
	_ = n.udp.Close()
}

// lateTransport 解开「Backend 要 IKE、IKE 要 Backend 的 Transport」这个构造环。
// 与 cmd/baidi-ipsec 里的同名类型同义——那边是 package main，这里只能再写一份。
type lateTransport struct {
	ready chan struct{}
	inner ipsec.Transport
}

func newLate() *lateTransport { return &lateTransport{ready: make(chan struct{})} }

func (l *lateTransport) set(t ipsec.Transport) { l.inner = t; close(l.ready) }
func (l *lateTransport) Send(d ipsec.Datagram) error {
	<-l.ready
	return l.inner.Send(d)
}
func (l *lateTransport) Recv() (ipsec.Datagram, error) {
	<-l.ready
	return l.inner.Recv()
}
func (l *lateTransport) Close() error { return nil }

func partB() {
	// 默认丢弃日志（自检输出要干净）；排障时 BAIDI_IPSEC_E2E_DEBUG=1 打开——
	// 数据面不通的根因（ErrNoPolicy / TS 不匹配 / 解密失败）只在这些日志里看得见。
	out := io.Discard
	lvl := slog.LevelInfo
	if os.Getenv("BAIDI_IPSEC_E2E_DEBUG") != "" {
		out = os.Stderr
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: lvl}))

	// 两个「站点」：A 在 10.90.0.0/24，B 在 10.91.0.0/24。
	aNet := netip.MustParsePrefix("10.90.0.1/24")
	bNet := netip.MustParsePrefix("10.91.0.1/24")

	// 两端都在 127.0.0.1 上，故只能用不同端口（macOS 默认不给 lo0 分配 127.0.0.2，
	// 加别名要 root，而本自检的前提就是无 root）。端口不对称时，对端的 ESP 封装口
	// 无法靠对称假设推出来，必须由 SiteConfig.PeerNATPort 显式声明——
	// ★这正好顺带验证了那个字段真的接通了：不接通的话第 ⑦ 步会超时。
	const ikeA, nattA, ikeB, nattB = 15700, 15701, 15800, 15801
	lo := netip.MustParseAddr("127.0.0.1")
	na, tapA := newNode("ipsec-a", lo, ikeA, nattA, aNet, log)
	defer na.close()
	nb, _ := newNode("ipsec-b", lo, ikeB, nattB, bNet, log)
	defer nb.close()

	psk := []byte("e2e-shared-secret-32-bytes-long!!")
	mk := func(id, gw string, local, remote netip.Prefix, peer netip.AddrPort, peerEncap uint16, localID, remoteID string) ipsec.SiteConfig {
		return ipsec.SiteConfig{
			ID: id, Name: id, GatewayID: gw, Enabled: true,
			Peer: peer, LocalSubnet: local, RemoteSubnet: remote,
			LocalID: localID, RemoteID: remoteID,
			Auth: "psk", Suite: "standard",
			Phase1: ipsec.Phase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
			Phase2: ipsec.Phase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
			PFS:    true, PSK: psk, PSKVersion: 1,
			PeerNATPort: peerEncap,
		}
	}
	ctx := context.Background()
	if err := na.backend.Apply(ctx, []ipsec.SiteConfig{
		mk("s", "ipsec-a", aNet.Masked(), bNet.Masked(), nb.udp.LocalIKE(), nattB, "a.baidi", "b.baidi"),
	}); err != nil {
		fatal("A 应用配置失败：%v", err)
	}
	// B 指向 A 的实际落点；A 指向 B 的实际落点。
	if err := nb.backend.Apply(ctx, []ipsec.SiteConfig{
		mk("s", "ipsec-b", bNet.Masked(), aNet.Masked(), na.udp.LocalIKE(), nattA, "b.baidi", "a.baidi"),
	}); err != nil {
		fatal("B 应用配置失败：%v", err)
	}
	if err := na.backend.Apply(ctx, []ipsec.SiteConfig{
		mk("s", "ipsec-a", aNet.Masked(), bNet.Masked(), nb.udp.LocalIKE(), nattB, "a.baidi", "b.baidi"),
	}); err != nil {
		fatal("A 重新指向 B 失败：%v", err)
	}

	fmt.Println("⑥ 两个独立节点完成协商（各自的 IKE 状态机，只经 UDP 通信）")
	upBy := func(n *node) (ipsec.SiteState, bool) {
		ss, err := n.backend.States(ctx)
		if err != nil || len(ss) == 0 {
			return ipsec.SiteState{}, false
		}
		return ss[0], ss[0].State == ipsec.StateUp
	}
	deadline := time.Now().Add(60 * time.Second)
	var sa, sb ipsec.SiteState
	for time.Now().Before(deadline) {
		var oka, okb bool
		sa, oka = upBy(na)
		sb, okb = upBy(nb)
		if oka && okb && sa.ChildSPIIn == sb.ChildSPIOut && sb.ChildSPIIn == sa.ChildSPIOut {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if sa.State != ipsec.StateUp || sb.State != ipsec.StateUp {
		fatal("进程内两节点未建立隧道：A=%s(%s) B=%s(%s)", sa.State, sa.LastError, sb.State, sb.LastError)
	}
	ok("两端 up，SPI 交叉相等（A.in=%#x==B.out=%#x）", sa.ChildSPIIn, sb.ChildSPIOut)

	fmt.Println("⑦ 跨隧道跑真实 HTTP（管道通 ≠ 业务通）")
	// B 侧在自己的 netstack 里起一个 HTTP 服务，返回可辨识的 body。
	ln, err := nb.dp.ListenTCP(8080)
	if err != nil {
		fatal("B 侧监听失败：%v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "<h1>站点B · 内网业务</h1>%s\n", canary)
	})}
	// ★金丝雀必须同时出现在**请求**里。只放进响应体的话，一旦请求方向不通，
	// 「扫不到明文」就成了假通过——没有数据流动，当然扫不到。
	// 放进请求头后，A 的每一个出向包都必然带着它，⑧ 才真正在检验加密。
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	cli := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return na.dp.DialContext(ctx, network, addr)
		}},
	}
	target := fmt.Sprintf("http://%s:8080/", nb.dp.Addr())
	body := httpGet(cli, target)
	if !strings.Contains(body, "站点B") {
		die("跨隧道 HTTP 未拿到 B 侧响应，实得：%q", body)
		// ★失败时把两端计数打出来：这几个数字能一眼定位断在哪一段——
		//   PacketsOut=0        → 出向泵没读到包（协议栈没发 / 泵没跑）
		//   PacketsOut>0 In=0   → 发出去了但对端没收到或解不开（SPI/密钥/落点错）
		//   两端都 >0 但 HTTP 挂 → 包通了但内容错（MTU / TS 校验 / 协议栈注入）
		for name, n := range map[string]*node{"A": na, "B": nb} {
			if ss, err := n.backend.States(ctx); err == nil {
				for _, s := range ss {
					info("%s: state=%s 出向包=%d 入向包=%d 出向字节=%d 入向字节=%d SPI(in=%#x out=%#x) err=%s",
						name, s.State, s.PacketsOut, s.PacketsIn, s.TxBytes, s.RxBytes,
						s.ChildSPIIn, s.ChildSPIOut, s.LastError)
				}
			}
		}
	} else {
		ok("A → B 隧道内 HTTP 成功：%s", strings.SplitN(strings.TrimSpace(body), "\n", 2)[0])
	}

	fmt.Println("⑧ 线上无明文（排除「只有头部加密了」——全偏移扫描而非只看开头）")
	// ★先确认真的有 ESP 包发出去过，否则「扫不到明文」是空转——
	// 没有数据流动时，一个什么都不做的实现也能过这条断言。
	var espCount int
	if ss, err := na.backend.States(ctx); err == nil {
		for _, s := range ss {
			espCount += int(s.PacketsOut)
		}
	}
	if espCount == 0 {
		die("A 侧出向 ESP 包数为 0 —— 本条断言无从检验（扫描没有数据流动的链路等于没扫）")
	}
	var found int
	for _, p := range tapA.sent {
		if bytes.Contains(p, []byte(canary)) {
			found++
		}
	}
	if found > 0 {
		die("在 %d 条出站报文里扫到了明文金丝雀 —— ESP 没有真正加密", found)
	} else if espCount > 0 {
		ok("扫描 %d 条出站报文（其中 %d 个 ESP 包真实承载了业务），未发现金丝雀明文",
			len(tapA.sent), espCount)
	}

	fmt.Println("⑨ 反例：拆掉 B 的 Child SA → 同一个 GET 必须失败")
	// ★这条不能省。它是唯一能排除「流量其实从旁路直连过去了、隧道只是摆设」的断言：
	// 如果 HTTP 走的是别的路，拆了 SA 它照样通。
	if err := nb.backend.Apply(ctx, nil); err != nil {
		die("拆除 B 侧站点失败：%v", err)
	}
	time.Sleep(1 * time.Second)
	cli2 := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return na.dp.DialContext(ctx, network, addr)
		}},
	}
	if b2 := httpGet(cli2, target); strings.Contains(b2, "站点B") {
		die("拆掉 SA 后 HTTP 仍然通 —— 说明流量根本没走隧道，隧道是摆设")
	} else {
		ok("拆掉 SA 后 HTTP 不通（隧道确实承载着这条业务）")
	}
}

func httpGet(c *http.Client, url string) string {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "错误：" + err.Error()
	}
	// 金丝雀随请求发出：这样 A 的出向包里必然含它，⑧ 的明文扫描才有意义。
	req.Header.Set("X-Baidi-Canary", canary)
	resp, err := c.Do(req)
	if err != nil {
		return "错误：" + err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
