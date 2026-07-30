package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// oldSchemaIpsecDB 造一个**迁移前**的库：ipsec_sites 用旧 DDL（没有
// enabled/gateway_id/local_id/remote_id/psk_version 五列），并灌入几行数据。
//
// ★这是本文件存在的唯一理由。补列迁移只加列、不填值，于是任何在新列出现之前
// 建好的库，新列永久为 NULL；而 enabled 恰好是网关拉站点时的 `WHERE enabled=1`
// 依据，全 NULL 就等于「所有隧道静默消失」。这个失败形态在本项目发生过一次
// （apps.resource_id），当时全程零报错，只是「什么都没发生」。
// 单测必须真的走一遍 OpenSQLite 的迁移路径，而不是断言 SQL 字符串。
func oldSchemaIpsecDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE ipsec_sites (
  id TEXT PRIMARY KEY, name TEXT, peer TEXT, local_subnet TEXT, remote_subnet TEXT,
  ike_version TEXT, auth TEXT, suite TEXT, phase1 TEXT, phase2 TEXT, pfs INTEGER, pq_hybrid INTEGER,
  status TEXT, rx_bytes INTEGER, tx_bytes INTEGER, last_up TEXT, local_ref TEXT, remote_ref TEXT, updated_at TEXT
)`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	// 三行覆盖旧 status 的三种取值：up（管理员点过启用）/ down / connecting。
	// connecting 在旧后端其实从未被写入过（没有协商过程自然没有中间态），
	// 但种子与前端 MOCK 里有，库里出现它并非不可能。
	for _, r := range []struct {
		id, name, status string
		rx               int64
	}{
		{"site-old-up", "上海分支", "up", 184_320_512},
		{"site-old-down", "成都分支", "down", 0},
		{"site-old-conn", "广州分支", "connecting", 53_477_376},
	} {
		if _, err := db.Exec(`INSERT INTO ipsec_sites(id,name,peer,local_subnet,remote_subnet,ike_version,auth,suite,phase1,phase2,pfs,pq_hybrid,status,rx_bytes,tx_bytes,last_up,local_ref,remote_ref,updated_at)
VALUES(?,?,'203.0.113.1','10.20.0.0/16','10.40.0.0/16','IKEv2','psk','standard','{}','{}',1,0,?,?,0,'今天 08:02','','','2026-06-28 10:00:00')`,
			r.id, r.name, r.status, r.rx); err != nil {
			t.Fatalf("insert old row: %v", err)
		}
	}
	return path
}

// 种子站点的 gateway_id / local_id / remote_id 与 enabled 同批补列，必须一并回填。
//
// ★这条是线上实测发现的：演示机既有库升级后三条种子站点的 gatewayId 全为空，
// 而控制面按 gateway_id == 证书 CN 精确过滤下发——网关拉到的是**空列表而不是
// 错误**，站点安静地永远 down。只回填 enabled 会漏掉这一半。
func TestBackfillIpsecIdentityOnLegacyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE ipsec_sites (
  id TEXT PRIMARY KEY, name TEXT, peer TEXT, local_subnet TEXT, remote_subnet TEXT,
  ike_version TEXT, auth TEXT, suite TEXT, phase1 TEXT, phase2 TEXT, pfs INTEGER, pq_hybrid INTEGER,
  status TEXT, rx_bytes INTEGER, tx_bytes INTEGER, last_up TEXT, local_ref TEXT, remote_ref TEXT, updated_at TEXT
)`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	// 老库里的种子行（老 schema 没有 gateway_id/local_id/remote_id 这三列）
	for _, id := range []string{"site-sh", "site-gz", "site-cd"} {
		if _, err := db.Exec(`INSERT INTO ipsec_sites(id,name,peer,local_subnet,remote_subnet,ike_version,auth,suite,phase1,phase2,pfs,pq_hybrid,status,rx_bytes,tx_bytes,last_up,local_ref,remote_ref,updated_at)
VALUES(?,'分支','203.0.113.1','10.20.0.0/16','10.40.0.0/16','IKEv2','psk','standard','{}','{}',1,0,'down',0,0,'','','','2026-06-28 10:00:00')`, id); err != nil {
			t.Fatalf("insert seed row %s: %v", id, err)
		}
	}
	// 管理员自建的老站点：gateway_id 无从推断，必须留空而不是猜一个填进去
	if _, err := db.Exec(`INSERT INTO ipsec_sites(id,name,peer,local_subnet,remote_subnet,ike_version,auth,suite,phase1,phase2,pfs,pq_hybrid,status,rx_bytes,tx_bytes,last_up,local_ref,remote_ref,updated_at)
VALUES('site-custom','自建','203.0.113.9','10.20.0.0/16','10.70.0.0/16','IKEv2','psk','standard','{}','{}',1,0,'down',0,0,'','','','2026-06-28 10:00:00')`); err != nil {
		t.Fatalf("insert custom row: %v", err)
	}
	db.Close()

	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	defer st.Close()
	sites, err := st.Ipsec(context.Background())
	if err != nil {
		t.Fatalf("read sites: %v", err)
	}
	got := map[string]IpsecSite{}
	for _, s := range sites {
		got[s.ID] = s
	}
	for _, w := range []struct{ id, gw, local, remote string }{
		{"site-sh", "ipsec-1", "hq.baidi", "sh.baidi"},
		{"site-gz", "ipsec-1", "hq.baidi", "gz.baidi"},
		{"site-cd", "ipsec-1", "hq.baidi", "cd.baidi"},
	} {
		s := got[w.id]
		if s.GatewayID != w.gw || s.LocalID != w.local || s.RemoteID != w.remote {
			t.Fatalf("种子站点 %s 回填错误：gw=%q local=%q remote=%q，期望 %q/%q/%q（gatewayId 为空时网关拉到空列表且零报错）",
				w.id, s.GatewayID, s.LocalID, s.RemoteID, w.gw, w.local, w.remote)
		}
	}
	if got["site-custom"].GatewayID != "" {
		t.Fatalf("自建站点的 gatewayId 被猜了一个值 %q——无从推断时必须留空，靠 configWarning 提示管理员补",
			got["site-custom"].GatewayID)
	}

	// 幂等：管理员改过之后再迁移一次，不得被冲掉
	cur := got["site-sh"]
	cur.GatewayID = "ipsec-beijing"
	if _, err := st.SaveIpsecSite(context.Background(), cur); err != nil {
		t.Fatalf("save: %v", err)
	}
	st.Close()
	st2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	sites2, _ := st2.Ipsec(context.Background())
	for _, s := range sites2 {
		if s.ID == "site-sh" && s.GatewayID != "ipsec-beijing" {
			t.Fatalf("重复迁移把管理员改过的 gatewayId 冲回成 %q：回填只能填空值", s.GatewayID)
		}
	}
}

// ★核心回归：旧库跑完迁移后 enabled 必须被回填，且映射忠实于旧 status。
// 不回填时网关拉到的是空列表，控制台、网关日志、审计三处全程零报错。
func TestBackfillIpsecEnabledOnLegacyDB(t *testing.T) {
	path := oldSchemaIpsecDB(t)

	st, err := OpenSQLite(path) // 走真实迁移路径：CREATE IF NOT EXISTS → ALTER 补列 → 回填
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	defer st.Close()

	sites, err := st.Ipsec(context.Background())
	if err != nil {
		t.Fatalf("read sites: %v", err)
	}
	if len(sites) != 3 {
		t.Fatalf("迁移不该增删站点，应 3 条，实得 %d（种子是否误灌？）", len(sites))
	}
	want := map[string]bool{"site-old-up": true, "site-old-down": false, "site-old-conn": false}
	for _, s := range sites {
		w, ok := want[s.ID]
		if !ok {
			t.Fatalf("出现了预期外的站点 %s", s.ID)
		}
		if s.Enabled != w {
			t.Fatalf("站点 %s 的 enabled 回填错误：期望 %v，实得 %v（旧 status 是回填的唯一依据）",
				s.ID, w, s.Enabled)
		}
	}

	// 回填必须幂等：再开一次库不得把管理员后来的改动冲掉。
	// 模拟「管理员迁移后手动停用了 site-old-up」，再跑一次迁移。
	if _, err := st.SetIpsecEnabled(context.Background(), "site-old-up", false); err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	st.Close()
	st2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	sites2, _ := st2.Ipsec(context.Background())
	for _, s := range sites2 {
		if s.ID == "site-old-up" && s.Enabled {
			t.Fatal("重复迁移把管理员的停用改回去了：回填必须只填 NULL 行（WHERE enabled IS NULL）")
		}
	}
}

// 新库：迁移 + 播种后种子站点必须落库，且默认全部未启用。
// 种子的对端是 RFC 5737 文档地址，默认启用只会得到三条 failed。
func TestSeedIpsecSitesAreDisabledAndSupported(t *testing.T) {
	st := openTestStore(t)
	sites, err := st.Ipsec(context.Background())
	if err != nil || len(sites) != 3 {
		t.Fatalf("种子应 3 条：%d %v", len(sites), err)
	}
	for _, s := range sites {
		if s.Enabled {
			t.Fatalf("种子站点 %s 不应默认启用（对端是文档地址，启用即 failed）", s.ID)
		}
		// ★套件修正的回归：auth=cert / sm2cert、DH=group24、pqHybrid=true
		// 三者本轮网关全不支持，留在种子里就是留一条永远红的站点。
		if s.Auth != "psk" {
			t.Fatalf("站点 %s 的 auth=%q：本轮只实现 PSK，其余会在网关装载期被拒", s.ID, s.Auth)
		}
		if s.PqHybrid {
			t.Fatalf("站点 %s 开了 pqHybrid：该字段保留但网关未实现", s.ID)
		}
		for _, ph := range []IpsecPhase{s.Phase1, s.Phase2} {
			switch ph.DH {
			case "group14", "group19", "sm2p256":
			default:
				t.Fatalf("站点 %s 的 DH=%q 不在网关实现的群里（group14/group19/sm2p256）", s.ID, ph.DH)
			}
		}
		// 假流量常量必须已清零：运行态现在由网关回报，种子里放数字就是骗自己。
		if s.RxBytes != 0 || s.TxBytes != 0 {
			t.Fatalf("站点 %s 仍带种子流量常量 rx=%d tx=%d", s.ID, s.RxBytes, s.TxBytes)
		}
	}
}

// toggle 只改 enabled，一个运行态字节都不许动。
func TestSetIpsecEnabledDoesNotTouchRuntime(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// 先塞一条网关回报的运行态
	if err := st.ReplaceIpsecSAStates(ctx, "ipsec-1", []IpsecSAState{{
		SiteID: "site-sh", State: "up", IKESPIi: "1122334455667788", IKESPIr: "8877665544332211",
		ChildSPIIn: 0xc0a80101, ChildSPIOut: 0x3f9e0002, RxBytes: 4096, TxBytes: 2048,
		NegotiatedProposal: "AES256-GCM16/PRF-HMAC-SHA256/ECP256", EstablishedAt: 1700000000, ReportedAt: 1700000015,
	}}); err != nil {
		t.Fatalf("replace states: %v", err)
	}
	if _, err := st.SetIpsecEnabled(ctx, "site-sh", true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	states, _ := st.IpsecSAStates(ctx)
	if len(states) != 1 || states[0].State != "up" || states[0].RxBytes != 4096 {
		t.Fatalf("toggle 不该碰运行态：%+v", states)
	}
	if _, err := st.SetIpsecEnabled(ctx, "site-不存在", true); err != ErrIpsecSiteNotFound {
		t.Fatalf("不存在的站点应回 ErrIpsecSiteNotFound，实得 %v（静默成功会让管理员以为已生效）", err)
	}
}

// 运行态是**全量覆写**：网关不再回报的行必须消失，且只影响自己名下的行。
func TestReplaceIpsecSAStatesIsFullOverwritePerGateway(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	_ = st.ReplaceIpsecSAStates(ctx, "ipsec-1", []IpsecSAState{
		{SiteID: "site-sh", State: "up"}, {SiteID: "site-cd", State: "connecting"},
	})
	_ = st.ReplaceIpsecSAStates(ctx, "ipsec-2", []IpsecSAState{{SiteID: "site-gz", State: "failed"}})

	// ipsec-1 这一轮只报了一条：另一条必须消失（否则被删站点会永远停在最后一次 up）
	_ = st.ReplaceIpsecSAStates(ctx, "ipsec-1", []IpsecSAState{{SiteID: "site-sh", State: "rekeying"}})
	states, err := st.IpsecSAStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range states {
		got[s.GatewayID+"/"+s.SiteID] = s.State
	}
	if len(got) != 2 {
		t.Fatalf("应剩 2 行（ipsec-1/site-sh + ipsec-2/site-gz），实得 %v", got)
	}
	if got["ipsec-1/site-sh"] != "rekeying" {
		t.Fatalf("覆写后状态应为 rekeying：%v", got)
	}
	if got["ipsec-2/site-gz"] != "failed" {
		t.Fatalf("一台网关的覆写不得动到另一台的行：%v", got)
	}

	// gateway_id 一律用参数覆盖：网关自报的 GatewayID 不可信。
	_ = st.ReplaceIpsecSAStates(ctx, "ipsec-3", []IpsecSAState{
		{SiteID: "site-x", GatewayID: "ipsec-2", State: "up"}, // 冒充 ipsec-2
	})
	states, _ = st.IpsecSAStates(ctx)
	for _, s := range states {
		if s.SiteID == "site-x" && s.GatewayID != "ipsec-3" {
			t.Fatalf("body 里的 gatewayId 不该被采信：实得 %q", s.GatewayID)
		}
	}
}

// 删站点必须连带清掉密钥行与运行态行——留残影会让下一条同 id 的站点「一建好就已连接」。
func TestDeleteIpsecSiteCascades(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	if _, err := st.SaveIpsecSecret(ctx, IpsecSecret{
		SiteID: "site-sh", Alg: "AES-256-GCM", Nonce: []byte("012345678901"),
		Cipher: []byte("ciphertext"), Fingerprint: "deadbeef",
	}); err != nil {
		t.Fatalf("save secret: %v", err)
	}
	_ = st.ReplaceIpsecSAStates(ctx, "ipsec-1", []IpsecSAState{{SiteID: "site-sh", State: "up"}})

	if err := st.DeleteIpsecSite(ctx, "site-sh"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, found, _ := st.IpsecSecret(ctx, "site-sh"); found {
		t.Fatal("密钥行未随站点删除：新建同 id 站点会直接继承旧 PSK")
	}
	states, _ := st.IpsecSAStates(ctx)
	for _, s := range states {
		if s.SiteID == "site-sh" {
			t.Fatal("运行态行未随站点删除：界面上会留一条已消失站点的 up 残影")
		}
	}
}

// PSK 版本号必须随每次写入递增，且与密文同事务落库。
func TestSaveIpsecSecretBumpsVersion(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	for want := 1; want <= 3; want++ {
		v, err := st.SaveIpsecSecret(ctx, IpsecSecret{
			SiteID: "site-cd", Alg: "AES-256-GCM", Nonce: []byte("012345678901"),
			Cipher: []byte{byte(want)}, Fingerprint: "fp",
		})
		if err != nil || v != want {
			t.Fatalf("第 %d 次写入应得版本 %d，实得 %d（err=%v）", want, want, v, err)
		}
	}
	sites, _ := st.Ipsec(ctx)
	for _, s := range sites {
		if s.ID != "site-cd" {
			continue
		}
		if s.PSKVersion != 3 {
			t.Fatalf("ipsec_sites.psk_version 应为 3，实得 %d（版本与密文必须同进同退）", s.PSKVersion)
		}
		if !s.HasPSK || s.PSKFingerprint != "fp" {
			t.Fatalf("hasPsk/指纹回显异常：%+v", s)
		}
	}
	// 站点不存在时不得静默成功
	if _, err := st.SaveIpsecSecret(ctx, IpsecSecret{SiteID: "site-无"}); err != ErrIpsecSiteNotFound {
		t.Fatalf("应回 ErrIpsecSiteNotFound，实得 %v", err)
	}
}

// 配置型 upsert 不得回写 psk_version：改站点名时把版本退回去，
// 网关会认为密钥没变而继续用缓存——改了 PSK 却不生效，且两端零报错。
func TestUpsertIpsecSiteKeepsPSKVersion(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if _, err := st.SaveIpsecSecret(ctx, IpsecSecret{
		SiteID: "site-sh", Alg: "AES-256-GCM", Nonce: []byte("012345678901"), Cipher: []byte{1}, Fingerprint: "fp",
	}); err != nil {
		t.Fatal(err)
	}
	saved, err := st.SaveIpsecSite(ctx, IpsecSite{
		ID: "site-sh", Name: "上海分支（改名）", Peer: "203.0.113.21",
		LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.40.0.0/16",
		PSKVersion: 0, // 表单快照里的陈旧值，绝不能被写进库
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved.PSKVersion != 1 {
		t.Fatalf("保存站点不得改动 psk_version：期望 1，实得 %d", saved.PSKVersion)
	}
	if !saved.HasPSK {
		t.Fatal("保存站点不得丢掉已配置的 PSK")
	}
}

// 最小披露：只有 gateway_id 精确匹配的站点会被下发；空 gatewayId 一条都不发。
func TestIpsecSitesForGatewayIsExactMatch(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	base := IpsecSite{Peer: "203.0.113.9", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.70.0.0/16"}

	a := base
	a.ID, a.Name, a.GatewayID = "s-a", "A", "ipsec-1"
	b := base
	b.ID, b.Name, b.GatewayID = "s-b", "B", "ipsec-2"
	c := base
	c.ID, c.Name, c.GatewayID = "s-c", "C", "" // 未指派
	for _, s := range []IpsecSite{a, b, c} {
		if _, err := st.SaveIpsecSite(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.IpsecSitesForGateway(ctx, "ipsec-1")
	if err != nil {
		t.Fatal(err)
	}
	// 种子站点的 gateway_id 也是 ipsec-1，故只断言「不含别人的」与「含自己的」
	ids := map[string]bool{}
	for _, s := range got {
		ids[s.ID] = true
	}
	if !ids["s-a"] {
		t.Fatal("自己的站点没下发")
	}
	if ids["s-b"] || ids["s-c"] {
		t.Fatalf("下发了不属于本网关的站点：%v（这是一张现成的横向移动地图）", ids)
	}
	if empty, _ := st.IpsecSitesForGateway(ctx, ""); len(empty) != 0 {
		t.Fatalf("空 CN 不得拿到任何站点，实得 %d 条", len(empty))
	}
}
