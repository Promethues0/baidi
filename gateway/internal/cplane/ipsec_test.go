package cplane

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"baidi.dev/gateway/internal/ipsec"
)

// newTestClient 直接拼一个 Client 打到 httptest 上。
//
// 走内部测试（package cplane）而不是起一套真 mTLS：本文件要验的是 JSON 契约与
// 错误分类，不是 TLS 握手。真要求先签一套 CA 才能测，结果必然是这些规则根本没人测。
func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{control: srv.URL, httpc: srv.Client()}
}

func TestIpsecSites(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/gateways/ipsec" {
			t.Errorf("路径不对：%s", r.URL.Path)
		}
		// ★身份全在 mTLS 传输层：请求不该带任何 Bearer（网关在代码层已无签发能力）。
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("请求不该带 Authorization 头，实际带了 %q", got)
		}
		io.WriteString(w, `{"sites":[{
			"id":"site-sh","name":"上海分支","gatewayId":"ipsec-1","enabled":true,
			"peer":"203.0.113.21","localSubnet":"10.20.0.0/16","remoteSubnet":"10.40.0.0/16",
			"localId":"hq.baidi","remoteId":"sh.baidi",
			"auth":"psk","suite":"standard",
			"phase1":{"enc":"AES256-GCM","hash":"SHA256","dh":"group19"},
			"phase2":{"enc":"AES256-GCM","hash":"SHA256","dh":"group19"},
			"pfs":true,"pqHybrid":false,"pskVersion":3,
			"未来新增的字段":"必须被忽略而不是解析失败"
		}]}`)
	})
	sites, err := c.IpsecSites()
	if err != nil {
		t.Fatalf("拉站点失败：%v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("站点数 %d，期望 1", len(sites))
	}
	s := sites[0]
	if s.ID != "site-sh" || s.GatewayID != "ipsec-1" || !s.Enabled {
		t.Errorf("基础字段解析不对：%+v", s)
	}
	if s.Peer != "203.0.113.21" || s.LocalSubnet != "10.20.0.0/16" || s.RemoteSubnet != "10.40.0.0/16" {
		t.Errorf("地址字段解析不对：%+v", s)
	}
	if s.Phase1.Enc != "AES256-GCM" || s.Phase2.DH != "group19" || !s.PFS {
		t.Errorf("套件字段解析不对：%+v", s)
	}
	if s.PSKVersion != 3 {
		t.Errorf("pskVersion=%d，期望 3", s.PSKVersion)
	}
	// ★控制面当前不下发 ikeVersion：缺字段必须落成空串（= 没意见，跳过检查），
	// 而不是被当成"选了别的版本"而拒掉整条站点。
	if s.IKEVersion != "" {
		t.Errorf("控制面没下发 ikeVersion 时应为空串，实际 %q", s.IKEVersion)
	}
}

// 「拉到空列表」与「拉取失败」必须可区分：前者要拆掉本地全部 SA（管理员真删光了），
// 后者要 fail-closed 保留上次配置。混在一起会让一次控制面抖动拆掉全部隧道。
func TestIpsecSitesEmptyIsNotFailure(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"sites":[]}`)
	})
	sites, err := c.IpsecSites()
	if err != nil {
		t.Fatalf("空列表不该是错误：%v", err)
	}
	if sites == nil {
		t.Fatal("空列表应返回非 nil 的空切片（调用方一律用 err 判断，但 nil 切片容易被误读成失败）")
	}
	if len(sites) != 0 {
		t.Fatalf("站点数 %d，期望 0", len(sites))
	}
}

// 控制面把最有用的那句话写在 body 里（例如 CN 前缀写错时会说清实际 CN 与期望前缀），
// 只报状态码等于把它扔了——而 IPSec 的部署失败原因高度集中在这一条上。
func TestIpsecSitesErrorCarriesBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"error":"该接口只接受站点组网网关（证书 CN 需以 ipsec- 开头，本次为 gw-1）"}`)
	})
	_, err := c.IpsecSites()
	if err == nil {
		t.Fatal("403 应返回错误")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "ipsec-") {
		t.Errorf("错误信息里应同时有状态码与控制面的原话，实际：%v", err)
	}
}

func TestIpsecPSK(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/api/v1/gateways/ipsec/site-sh/psk"; r.URL.Path != want {
			t.Errorf("路径 %s，期望 %s", r.URL.Path, want)
		}
		io.WriteString(w, `{"psk":"YmFpZGktcHNr","version":7}`) // base64("baidi-psk")
	})
	psk, ver, err := c.IpsecPSK("site-sh")
	if err != nil {
		t.Fatalf("取 PSK 失败：%v", err)
	}
	// 口径：解码后的原文字节就是 prf(PSK, "Key Pad for IKEv2") 的 key，不做任何再编码。
	if string(psk) != "baidi-psk" {
		t.Errorf("PSK=%q，期望 baidi-psk（两端编码口径不一致只会得到一句无头无尾的「认证失败」）", psk)
	}
	if ver != 7 {
		t.Errorf("version=%d，期望 7", ver)
	}
}

// 404 必须能被 errors.Is 认出来：它意味着"重试一万次也没用"，
// 与"网络抖动取不到"的处置完全不同（前者置 failed 摆到界面上，后者沿用缓存继续跑）。
func TestIpsecPSKNotFound(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"error":"站点 site-x 尚未配置 PSK"}`)
	})
	_, _, err := c.IpsecPSK("site-x")
	if !errors.Is(err, ErrIpsecPSKUnavailable) {
		t.Fatalf("404 应可被 errors.Is(ErrIpsecPSKUnavailable) 认出，实际：%v", err)
	}
	if !strings.Contains(err.Error(), "site-x") {
		t.Errorf("错误信息应带站点 id，实际：%v", err)
	}
}

// ★空 PSK 必须在这里就被拦掉：空密钥两端一样能把 AUTH 算通、隧道一样建得起来、
// 界面一样显示 up，只是认证强度为零。「配错了连不上」是小事故，「配错了连上了」才是真事故。
func TestIpsecPSKEmptyRejected(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"psk":"","version":1}`)
	})
	_, _, err := c.IpsecPSK("site-empty")
	if !errors.Is(err, ErrIpsecPSKUnavailable) {
		t.Fatalf("空 PSK 必须被拒绝且归入「取不到」，实际：%v", err)
	}
}

func TestIpsecPSKBadBase64(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"psk":"这不是 base64","version":1}`)
	})
	if _, _, err := c.IpsecPSK("site-x"); err == nil {
		t.Fatal("非法 base64 应报错而不是静默给出半截密钥")
	}
}

func TestReportIpsecStatus(t *testing.T) {
	var got map[string]any
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type=%q", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("请求体不是合法 JSON：%v", err)
		}
		io.WriteString(w, `{"ok":true,"accepted":1,"rejected":["site-gone"]}`)
	})

	rejected, err := c.ReportIpsecStatus([]ipsec.SiteState{{
		SiteID: "site-sh", GatewayID: "ipsec-1", State: ipsec.StateUp,
		IKESPIi: "1122334455667788", ChildSPIIn: 0xA001, ChildSPIOut: 0xB001,
		Counters: ipsec.Counters{RxBytes: 4096, TxBytes: 2048},
	}})
	if err != nil {
		t.Fatalf("回报失败：%v", err)
	}
	// 控制面拒收 = 本网关在白报一条已删除/已改派的站点。咽下去的话，
	// 网关会一直白报，而管理员只会看到那条站点凭空消失。
	if len(rejected) != 1 || rejected[0] != "site-gone" {
		t.Errorf("rejected=%v，期望 [site-gone]", rejected)
	}

	states, _ := got["states"].([]any)
	if len(states) != 1 {
		t.Fatalf("states 长度 %d，期望 1", len(states))
	}
	st, _ := states[0].(map[string]any)
	for _, k := range []string{"siteId", "gatewayId", "state", "ikeSpiI", "childSpiIn", "childSpiOut"} {
		if _, ok := st[k]; !ok {
			t.Errorf("回报里缺字段 %s（控制面按 store.IpsecSAState 的 JSON 名解码，对不上就是静默丢字段）", k)
		}
	}
	// Counters 是内嵌结构体：JSON 里必须是**提升到顶层**的 rxBytes/txBytes，
	// 不是嵌套的 {"Counters":{...}}——嵌套的话控制面解出来永远是 0，
	// 而界面上"流量一直是 0"会被当成"没有业务在跑"。
	if _, ok := st["rxBytes"]; !ok {
		t.Error("rxBytes 未提升到顶层：控制面会解出 0，界面上表现为「隧道 up 但一直没流量」")
	}
}

// nil 与空列表在全量覆写语义下等价，但 JSON 的 null 与 [] 对解码器不等价。
func TestReportIpsecStatusNilBecomesEmptyArray(t *testing.T) {
	var raw string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
		io.WriteString(w, `{"ok":true}`)
	})
	if _, err := c.ReportIpsecStatus(nil); err != nil {
		t.Fatalf("回报 nil 失败：%v", err)
	}
	if !strings.Contains(raw, `"states":[]`) {
		t.Errorf("nil 应序列化成 []，实际请求体：%s", raw)
	}
}
