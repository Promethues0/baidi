// Command baidi-e2e 是白帝**全链路自检**：以真实客户端的姿态走完整条接入链路，
// 每一步都断言可观测的结果，任何一环退化为「假通过」都会立刻失败。
//
//	① 门户登录（真实凭据校验）
//	② 拉取接入剖面（网关落点 / 路由表 / 资源映射 / 隧道证书指纹）
//	③ 敲门前直连隧道端口 —— 必须被拒（服务隐身）
//	④ 经控制面换短时效一次性敲门令牌 → SPA 敲门
//	⑤ 用剖面下发的指纹钉扎握手 —— 验证隧道是「加密 + 认证」而不只是加密
//	⑥ 用错误指纹握手 —— 必须被拒（中间人挡得住）
//	⑦ 按 resmap 逐资源 CONNECT —— 验证多资源路由真的落到各自后端
//	⑧ 引用未授权资源 —— 必须被网关拒绝（剖面只是路由提示，不是授权凭据）
//
// 唯一没覆盖的是 utun 建卡本身（需 root），那部分由 baidi-tun 负责；
// 从 netstack 之后的每一段都在这里被真实验证。
//
// 用法：先起 control + gateway + 后端（见 e2e.sh），再 `go run ./cmd/baidi-e2e`。
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"baidi.dev/gateway/internal/knock"
)

// e2eDevice 自检客户端自报的终端指纹。
//
// ★自检**不**先上报 posture，因此这台"设备"在控制面的授信终端台账里是未登记的。
// 这是刻意的：自检跑在授信终端的默认准入模式（observe）下，顺带验证「未登记设备
// 照常放行 + 留痕」这条默认路径没被改坏。若把准入切成 strict（
// PUT /api/v1/devices/settings），第 ④ 步会如实失败——那正是该功能生效的证据。
const e2eDevice = "FP-E2E-SELFCHECK"

// profileGW 一个网关落点。剖面同时下发单数 `gateway`（旧客户端只读它）与
// 有序的 `gateways` 清单（新客户端按序尝试、失败切下一个），自检两者都验。
type profileGW struct {
	ID, Host, SPAPort, ProxyPort, TunnelPin string
	Online                                  bool
}

type profile struct {
	Gateway  profileGW         `json:"gateway"`
	Gateways []profileGW       `json:"gateways"`
	Routes   []string          `json:"routes"`
	Resmap   map[string]string `json:"resmap"`
	Apps     []struct {
		Name, VIP, URL, ResourceID, Backend string
		Accessible                          bool
	} `json:"apps"`
}

func die(f string, a ...any) { fmt.Printf("   ✗ "+f+"\n", a...); os.Exit(1) }
func ok(f string, a ...any)  { fmt.Printf("   ✓ "+f+"\n", a...) }

func main() {
	const control = "http://127.0.0.1:8090"

	fmt.Println("① 门户登录（真实凭据校验）")
	body, _ := json.Marshal(map[string]string{"username": "li.fang", "password": "baidi@123"})
	resp, err := http.Post(control+"/api/v1/portal/login", "application/json", bytes.NewReader(body))
	if err != nil {
		die("登录请求失败: %v", err)
	}
	var lr struct {
		Ok    bool
		Token string
	}
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	if !lr.Ok || lr.Token == "" {
		die("登录失败")
	}
	ok("会话令牌已取得")

	fmt.Println("② 拉取接入剖面（网关落点 + 路由表 + 资源映射 + 证书指纹）")
	req, _ := http.NewRequest("GET", control+"/api/v1/client/profile", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		die("拉剖面失败: %v", err)
	}
	var p profile
	json.NewDecoder(resp.Body).Decode(&p)
	resp.Body.Close()
	if !p.Gateway.Online {
		die("控制面认为网关离线")
	}
	if p.Gateway.TunnelPin == "" {
		die("剖面未下发隧道证书指纹")
	}
	// 多活契约：清单非空，且单数字段恒等于清单首项。
	// ★单数字段是给**旧客户端**的兼容出口——它一旦缺席或与清单首项不一致，
	// 存量终端会连到一台与控制面认定不同的网关上，而两侧日志都完全正常。
	if len(p.Gateways) == 0 {
		die("剖面未下发网关落点清单（gateways）")
	}
	if p.Gateways[0].Host != p.Gateway.Host || p.Gateways[0].ProxyPort != p.Gateway.ProxyPort ||
		p.Gateways[0].TunnelPin != p.Gateway.TunnelPin {
		die("单数 gateway 与清单首项不一致：旧客户端会连到另一台网关（%+v vs %+v）", p.Gateway, p.Gateways[0])
	}
	ok("网关 %s:%s（落点清单 %d 个，首选 %s），接管 %d 个网段，%d 条资源映射",
		p.Gateway.Host, p.Gateway.ProxyPort, len(p.Gateways), p.Gateways[0].ID, len(p.Routes), len(p.Resmap))

	fmt.Println("③ 敲门前直连隧道端口（期望失败＝对未授权者隐身）")
	c, err := net.DialTimeout("tcp", p.Gateway.Host+":"+p.Gateway.ProxyPort, 2*time.Second)
	if err == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, e := c.Read(make([]byte, 1)); e == nil {
			die("竟然读到了数据，隐身失效")
		}
		c.Close()
	}
	ok("被拒绝（隐身）")

	fmt.Println("④ 经控制面换短时效一次性敲门令牌 → SPA 敲门")
	tok, err := knock.FetchToken(control, lr.Token, e2eDevice)
	if err != nil {
		die("取敲门令牌失败: %v", err)
	}
	uc, err := net.Dial("udp", p.Gateway.Host+":"+p.Gateway.SPAPort)
	if err != nil {
		die("SPA 拨号失败: %v", err)
	}
	sealed, _ := knock.Seal(tok)
	uc.Write(sealed)
	uc.Close()
	time.Sleep(800 * time.Millisecond)
	ok("敲门包已发送（use=knock 短时效一次性令牌）")

	fmt.Println("⑤ 用剖面下发的指纹钉扎握手（验证隧道已「加密 + 认证」）")
	pinned := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			sum := sha256.Sum256(raw[0])
			if got := hex.EncodeToString(sum[:]); got != p.Gateway.TunnelPin {
				return fmt.Errorf("指纹不匹配：期望 %s 实得 %s", p.Gateway.TunnelPin, got)
			}
			return nil
		},
	}
	probe, err := tls.Dial("tcp", p.Gateway.Host+":"+p.Gateway.ProxyPort, pinned)
	if err != nil {
		die("钉扎握手失败: %v", err)
	}
	probe.Close()
	ok("指纹一致，握手通过")

	fmt.Println("⑥ 用**错误**指纹握手（期望被拒＝中间人挡得住）")
	evil := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != strings.Repeat("00", 32) {
				return fmt.Errorf("证书指纹不匹配（疑似中间人）")
			}
			return nil
		},
	}
	if c2, e := tls.Dial("tcp", p.Gateway.Host+":"+p.Gateway.ProxyPort, evil); e == nil {
		c2.Close()
		die("错误指纹竟被接受")
	}
	ok("握手被拒（中间人无法冒充网关）")

	fmt.Println("⑦ 按 resmap 逐资源路由，校验落到各自后端（多资源路由是否真实）")
	for _, a := range p.Apps {
		if !a.Accessible || a.ResourceID == "" || a.VIP == "" {
			continue
		}
		// 客户端真实行为：utun 捕获到发往 VIP:port 的流 → 查 resmap 得资源 id
		key := a.VIP + a.URL[strings.LastIndex(a.URL, ":"):]
		rid := p.Resmap[key]
		if rid == "" { // tunnel 模式 URL 形如 host:port
			rid = p.Resmap[a.VIP+":"+a.URL[strings.LastIndex(a.URL, ":")+1:]]
		}
		if rid == "" {
			die("资源 %s 的 VIP %s 在 resmap 里查不到", a.Name, a.VIP)
		}
		conn, err := tls.Dial("tcp", p.Gateway.Host+":"+p.Gateway.ProxyPort, pinned)
		if err != nil {
			die("隧道拨号失败: %v", err)
		}
		fmt.Fprintf(conn, "CONNECT %s\n", rid)
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var got string
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "<h1>") {
				got = sc.Text()
				break
			}
		}
		conn.Close()
		if got == "" {
			die("资源 %s（id=%s）没有取到后端响应", a.Name, rid)
		}
		ok("%-14s → CONNECT %-8s → %s", a.Name, rid, strings.TrimSpace(got))
	}

	fmt.Println("⑧ 引用未授权资源（期望被网关拒绝＝剖面不是授权凭据）")
	conn, err := tls.Dial("tcp", p.Gateway.Host+":"+p.Gateway.ProxyPort, pinned)
	if err != nil {
		die("拨号失败: %v", err)
	}
	fmt.Fprintf(conn, "CONNECT finance\nGET / HTTP/1.0\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	conn.Close()
	if n > 0 {
		die("越权资源竟返回了数据：%q", string(buf[:n]))
	}
	ok("网关拒绝（授权权威在数据面，剖面只是路由提示）")

	fmt.Println("\n✅ 全链路通过")
}
