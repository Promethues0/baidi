package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// ── 同一承载网关上的重复对端（wave11 行动 10-②）──
//
// 数据面响应方 `ike.findSiteByPeer` 在 IKE_SA_INIT 阶段**只有对端 IP 可用**
// （IDr 要到 IKE_AUTH 才出现，TS 更在其后），协议层面区分不开两条同 peer 的站点。
// 入口不拦的话，管理员保存拿 200 OK，现场却是「一条本来健康的站点被间歇性打成
// 协商失败，且失败原因指向对端」——从控制台上完全看不出根因。

// mkSite 造一条最小可用的站点 JSON。
func mkSiteJSON(id, gw, peer, local, remote string) string {
	return `{"id":"` + id + `","name":"` + id + `","gatewayId":"` + gw + `",` +
		`"peer":"` + peer + `","localSubnet":"` + local + `","remoteSubnet":"` + remote + `",` +
		`"auth":"psk","suite":"standard","enabled":true}`
}

// TestSaveIpsecRejectsDuplicatePeerOnSameGateway 入口必须拒收。
//
// 变异验证：把 handleSaveIpsec 里那段 ipsecPeerConflict 调用删掉，本用例立刻变红。
func TestSaveIpsecRejectsDuplicatePeerOnSameGateway(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec",
		mkSiteJSON("dup-a", "ipsec-9", "198.51.100.7", "10.70.0.0/16", "10.71.0.0/16"), tok); code != http.StatusOK {
		t.Fatalf("第一条应保存成功：%d %v", code, resp)
	}
	code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec",
		mkSiteJSON("dup-b", "ipsec-9", "198.51.100.7", "10.72.0.0/16", "10.73.0.0/16"), tok)
	if code != http.StatusBadRequest {
		t.Fatalf("同网关同对端的第二条必须拒收，实得 %d %v", code, resp)
	}
	msg := errMsgOf(resp)
	// 拒绝要**说得出原因**（照 peer 拒收 FQDN 的先例）：笼统的"冲突"会让管理员
	// 反复换写法去试，而这里真正要传达的是"协议上区分不开"这个事实。
	for _, want := range []string{"dup-a", "198.51.100.7", "IKE_SA_INIT"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("拒绝文案缺少 %q：%s", want, msg)
		}
	}
	// 拦在写库**之前**：拦在之后就只是"下次读的时候提醒你一下"。
	sites, err := f.st.Ipsec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sites {
		if s.ID == "dup-b" {
			t.Fatal("被拒的站点仍然落库了——闸必须排在 SaveIpsecSite 之前")
		}
	}
}

// TestSaveIpsecDuplicatePeerIgnoresPort 端口不参与判定。
//
// ★数据面 findSiteByPeer 刻意**不比端口**（NAT 后的源端口是随机分配的）。
// 入口若按带端口的字符串去重，管理员改个端口就能绕过这道闸，而故障照旧发生。
func TestSaveIpsecDuplicatePeerIgnoresPort(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec",
		mkSiteJSON("p-a", "ipsec-9", "198.51.100.8:500", "10.70.0.0/16", "10.71.0.0/16"), tok); code != http.StatusOK {
		t.Fatalf("第一条应保存成功：%d %v", code, resp)
	}
	code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec",
		mkSiteJSON("p-b", "ipsec-9", "198.51.100.8:4500", "10.72.0.0/16", "10.73.0.0/16"), tok)
	if code != http.StatusBadRequest {
		t.Fatalf("换个端口不该能绕过这道闸（数据面只比 IP），实得 %d %v", code, resp)
	}
}

// TestSaveIpsecAllowsSamePeerOnDifferentGateways 不同网关上的同一对端是**正常拓扑**。
//
// ★这条反例守着一个真实存在的形态：`gateway/ipsec-e2e.sh` 里两条站点的 peer
// 都是 127.0.0.1、分属 ipsec-a / ipsec-b。按 IP 一刀切的判据会把自检整个打挂，
// 而它在生产上误伤的是"两台组网网关连同一个对端"这种完全合法的部署。
func TestSaveIpsecAllowsSamePeerOnDifferentGateways(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec",
		mkSiteJSON("g-a", "ipsec-a", "198.51.100.9", "10.70.0.0/16", "10.71.0.0/16"), tok); code != http.StatusOK {
		t.Fatalf("第一条应保存成功：%d %v", code, resp)
	}
	if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec",
		mkSiteJSON("g-b", "ipsec-b", "198.51.100.9", "10.72.0.0/16", "10.73.0.0/16"), tok); code != http.StatusOK {
		t.Fatalf("不同承载网关上的同一对端是合法拓扑，不该被拒：%d %v", code, resp)
	}
}

// TestSaveIpsecEditingSelfIsNotAConflict 改自己不算与自己冲突。
func TestSaveIpsecEditingSelfIsNotAConflict(t *testing.T) {
	f := newIpsecFixture(t)
	tok := adminToken()

	body := mkSiteJSON("self", "ipsec-9", "198.51.100.10", "10.70.0.0/16", "10.71.0.0/16")
	if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", body, tok); code != http.StatusOK {
		t.Fatalf("建站失败：%d %v", code, resp)
	}
	// 同 id 再存一次（只改网段）：不该被自己顶回来。
	again := mkSiteJSON("self", "ipsec-9", "198.51.100.10", "10.80.0.0/16", "10.81.0.0/16")
	if code, resp := f.callAdmin(t, http.MethodPost, "/api/v1/ipsec", again, tok); code != http.StatusOK {
		t.Fatalf("改自己被判成冲突了：%d %v", code, resp)
	}
}

// TestIpsecListReportsLegacyDuplicatePeers 存量重复必须在读端补报。
//
// 入口只拦新配置，库里已有的那对只能靠读端点名——不点名的话它们会一直
// 安静地互相打架，而两条站点各自的配置看着都对。
//
// 变异验证：把 handleIpsec 里 `d.PeerConflict = dups[site.ID]` 那行删掉，本用例变红。
func TestIpsecListReportsLegacyDuplicatePeers(t *testing.T) {
	f := newIpsecFixture(t)
	ctx := context.Background()
	// 绕过入口直接写库，模拟"这道闸上线之前就存在的两条站点"。
	for _, s := range []store.IpsecSite{
		{ID: "old-b", Name: "旧B", GatewayID: "ipsec-9", Enabled: true, Peer: "198.51.100.20",
			LocalSubnet: "10.70.0.0/16", RemoteSubnet: "10.71.0.0/16", Auth: "psk", Suite: "standard"},
		{ID: "old-a", Name: "旧A", GatewayID: "ipsec-9", Enabled: true, Peer: "198.51.100.20:4500",
			LocalSubnet: "10.72.0.0/16", RemoteSubnet: "10.73.0.0/16", Auth: "psk", Suite: "standard"},
	} {
		if _, err := f.st.SaveIpsecSite(ctx, s); err != nil {
			t.Fatal(err)
		}
	}

	code, resp := f.callAdmin(t, http.MethodGet, "/api/v1/ipsec", "", adminToken())
	if code != http.StatusOK {
		t.Fatalf("读清单失败：%d", code)
	}
	got := map[string]string{}
	for _, raw := range resp["sites"].([]any) {
		m := raw.(map[string]any)
		id, _ := m["id"].(string)
		pc, _ := m["peerConflict"].(string)
		got[id] = pc
	}
	// **两条都要**挂上告警：只标其中一条的话，管理员看另一条时完全无从察觉。
	for _, id := range []string{"old-a", "old-b"} {
		if got[id] == "" {
			t.Fatalf("站点 %s 没有挂上对端冲突告警", id)
		}
	}
	// 告诉管理员**谁会被选中**（字典序最小的 old-a），与数据面 findSiteByPeer 同判据。
	if !strings.Contains(got["old-b"], "old-a") {
		t.Fatalf("告警应点名会被选中的那条：%s", got["old-b"])
	}
	// 没有冲突的种子站点不该被误标。
	if got["site-sh"] != "" {
		t.Fatalf("无冲突的站点被误标：%s", got["site-sh"])
	}
}

// TestIpsecDuplicatePeersIgnoresUnassigned 未指派网关的站点不参与重复判定。
//
// 控制面按 CN 精确过滤下发，它们根本不会被任何网关装载，凑不成一对；
// 而它们另有 ConfigWarning 单独点名。误报的代价是把一条真告警变成噪声。
func TestIpsecDuplicatePeersIgnoresUnassigned(t *testing.T) {
	dups := ipsecDuplicatePeers([]store.IpsecSite{
		{ID: "x", GatewayID: "", Peer: "198.51.100.30"},
		{ID: "y", GatewayID: "", Peer: "198.51.100.30"},
	})
	if len(dups) != 0 {
		t.Fatalf("未指派网关的站点不该被判成冲突：%v", dups)
	}
}
