package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/cplane"
	"baidi.dev/gateway/internal/ipsec"
)

// ── 测试替身 ──

// fakeControl 一个可编程的控制面。计数器是本文件多数断言的落点：
// 「不重复取密钥」这类规则只能靠调用次数来证明，看结果是看不出来的。
type fakeControl struct {
	sites    []cplane.IpsecSiteDTO
	sitesErr error

	psk     map[string]([]byte)
	pskVer  map[string]int
	pskErr  map[string]error
	pskHits map[string]int

	reported [][]ipsec.SiteState
	rejected []string
	reportEr error
}

func newFakeControl() *fakeControl {
	return &fakeControl{
		psk:     map[string][]byte{},
		pskVer:  map[string]int{},
		pskErr:  map[string]error{},
		pskHits: map[string]int{},
	}
}

func (f *fakeControl) IpsecSites() ([]cplane.IpsecSiteDTO, error) {
	if f.sitesErr != nil {
		return nil, f.sitesErr
	}
	return f.sites, nil
}

func (f *fakeControl) IpsecPSK(id string) ([]byte, int, error) {
	f.pskHits[id]++
	if err := f.pskErr[id]; err != nil {
		return nil, 0, err
	}
	p, ok := f.psk[id]
	if !ok {
		return nil, 0, fmt.Errorf("站点 %s：%w", id, cplane.ErrIpsecPSKUnavailable)
	}
	return append([]byte(nil), p...), f.pskVer[id], nil
}

func (f *fakeControl) ReportIpsecStatus(states []ipsec.SiteState) ([]string, error) {
	cp := make([]ipsec.SiteState, len(states))
	copy(cp, states)
	f.reported = append(f.reported, cp)
	return f.rejected, f.reportEr
}

// fakeBackend 记下每次 Apply 的入参，并按 applied 反射出一批「已建立」的状态。
type fakeBackend struct {
	applyCalls [][]ipsec.SiteConfig
	states     []ipsec.SiteState
}

func (b *fakeBackend) Apply(_ context.Context, sites []ipsec.SiteConfig) error {
	cp := make([]ipsec.SiteConfig, len(sites))
	copy(cp, sites)
	b.applyCalls = append(b.applyCalls, cp)
	// 默认回一批 up：这样"本地诊断能不能盖到 LastError 上"才有东西可盖。
	b.states = b.states[:0]
	for _, s := range sites {
		b.states = append(b.states, ipsec.SiteState{SiteID: s.ID, State: ipsec.StateUp})
	}
	return nil
}

func (b *fakeBackend) States(_ context.Context) ([]ipsec.SiteState, error) {
	out := make([]ipsec.SiteState, len(b.states))
	copy(out, b.states)
	return out, nil
}

func (b *fakeBackend) Close() error { return nil }

func (b *fakeBackend) lastApply(t *testing.T) []ipsec.SiteConfig {
	t.Helper()
	if len(b.applyCalls) == 0 {
		t.Fatal("Apply 从未被调用")
	}
	return b.applyCalls[len(b.applyCalls)-1]
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testSyncer(cp controlClient, back ipsec.Backend) *syncer {
	s := newSyncer(cp, "ipsec-1", back, quietLog(), nil)
	s.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return s
}

func dto(id string, ver int) cplane.IpsecSiteDTO {
	return cplane.IpsecSiteDTO{
		ID: id, Name: id, GatewayID: "ipsec-1", Enabled: true,
		Peer: "203.0.113.21", LocalSubnet: "10.20.0.0/16", RemoteSubnet: "10.40.0.0/16",
		LocalID: "hq.baidi", RemoteID: "sh.baidi",
		Auth: "psk", Suite: "standard",
		Phase1:     cplane.IpsecPhaseDTO{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		Phase2:     cplane.IpsecPhaseDTO{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		PFS:        true,
		PSKVersion: ver,
	}
}

func findCfg(t *testing.T, cfgs []ipsec.SiteConfig, id string) ipsec.SiteConfig {
	t.Helper()
	for _, c := range cfgs {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("下发给 Backend 的配置里没有站点 %s（实际 %d 条）", id, len(cfgs))
	return ipsec.SiteConfig{}
}

// ── PSK 版本触发 ──

// 版本没变就不该再取密钥：策略每 15s 拉一轮，密钥若跟着重传，
// 就是每 15s 让它在网络上出现一次。
func TestPSKFetchedOnlyWhenVersionChanges(t *testing.T) {
	cp := newFakeControl()
	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 1)}
	cp.psk["site-sh"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-sh"] = 1
	back := &fakeBackend{}
	s := testSyncer(cp, back)

	s.round(context.Background())
	s.round(context.Background())
	s.round(context.Background())
	if cp.pskHits["site-sh"] != 1 {
		t.Fatalf("三轮同步取了 %d 次密钥，期望 1 次（版本没变就不该重传密钥）", cp.pskHits["site-sh"])
	}

	// 管理员改了密钥 → 版本涨 → 必须重新取，且真的用上新密钥。
	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 2)}
	cp.psk["site-sh"] = []byte("psk-v2-fedcba9876543210")
	cp.pskVer["site-sh"] = 2
	s.round(context.Background())
	if cp.pskHits["site-sh"] != 2 {
		t.Fatalf("版本涨到 2 后取密钥次数 %d，期望 2", cp.pskHits["site-sh"])
	}
	got := findCfg(t, back.lastApply(t), "site-sh")
	if string(got.PSK) != "psk-v2-fedcba9876543210" || got.PSKVersion != 2 {
		t.Fatalf("新密钥没生效：PSKVersion=%d len=%d", got.PSKVersion, len(got.PSK))
	}
}

// ★取密钥失败时，下发给 Backend 的版本号必须也是**本地那把**的版本。
// 若把控制面的新版本连同旧密钥一起下发，site.fingerprint（含 PSKVersion）就变了，
// Backend 会判定"配置已变更"而拆掉重建 SA——用的还是旧密钥。
// 结果是每 15 秒重建一次、每次都认证失败，日志里却显示"配置已更新，重新协商"。
func TestPSKFetchFailureKeepsCachedVersion(t *testing.T) {
	cp := newFakeControl()
	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 1)}
	cp.psk["site-sh"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-sh"] = 1
	back := &fakeBackend{}
	s := testSyncer(cp, back)
	s.round(context.Background())

	// 控制面说密钥更新到 v2，但取密钥这一步网络抖动失败。
	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 2)}
	cp.pskErr["site-sh"] = errors.New("connection reset by peer")
	s.round(context.Background())

	got := findCfg(t, back.lastApply(t), "site-sh")
	if got.PSKVersion != 1 {
		t.Fatalf("下发的 PSKVersion=%d，期望 1（手上是 v1 就得报 v1，否则配置指纹漂移导致反复重建 SA）", got.PSKVersion)
	}
	if string(got.PSK) != "psk-v1-0123456789abcdef" {
		t.Fatalf("应沿用缓存的 v1 密钥继续跑，实际 len=%d", len(got.PSK))
	}
	// 沿用旧密钥这件事必须在控制台上说出来，否则"改了密钥没生效"变成玄学。
	assertLastErrorContains(t, cp, "site-sh", "v1")
}

// pskVersion=0 = 控制面明说还没配密钥。★不能拿空 PSK 去协商：
// 两端都空时 AUTH 完全通得过，隧道真的建起来、界面真的显示 up，但认证强度为零。
func TestPSKVersionZeroNeverFetchesAndReportsReason(t *testing.T) {
	cp := newFakeControl()
	cp.sites = []cplane.IpsecSiteDTO{dto("site-new", 0)}
	back := &fakeBackend{}
	s := testSyncer(cp, back)
	s.round(context.Background())

	if cp.pskHits["site-new"] != 0 {
		t.Errorf("pskVersion=0 时不该去取密钥，实际取了 %d 次", cp.pskHits["site-new"])
	}
	got := findCfg(t, back.lastApply(t), "site-new")
	if len(got.PSK) != 0 {
		t.Error("未配置 PSK 的站点不该被塞进任何密钥")
	}
	assertLastErrorContains(t, cp, "site-new", "尚未为该站点配置 PSK")
}

// 控制面回 404（未配置或已改派）且本地有缓存时：继续跑，但把原因摆出来。
func TestPSKUnavailableKeepsRunningWithCached(t *testing.T) {
	cp := newFakeControl()
	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 1)}
	cp.psk["site-sh"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-sh"] = 1
	back := &fakeBackend{}
	s := testSyncer(cp, back)
	s.round(context.Background())

	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 2)}
	cp.pskErr["site-sh"] = fmt.Errorf("站点 site-sh：%w", cplane.ErrIpsecPSKUnavailable)
	s.round(context.Background())

	got := findCfg(t, back.lastApply(t), "site-sh")
	if got.PSKVersion != 1 || len(got.PSK) == 0 {
		t.Fatalf("应沿用缓存密钥继续跑：PSKVersion=%d len=%d", got.PSKVersion, len(got.PSK))
	}
	assertLastErrorContains(t, cp, "site-sh", "取不到该站点的 PSK")
}

// 站点从控制面消失后必须清掉密钥缓存：
// 不清的话，同 id 站点被重建时会先拿一把陈旧密钥去协商，得到一句"认证失败"，
// 而管理员刚刚才设过密钥。
func TestPSKCacheDroppedWhenSiteDisappears(t *testing.T) {
	cp := newFakeControl()
	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 1)}
	cp.psk["site-sh"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-sh"] = 1
	s := testSyncer(cp, &fakeBackend{})
	s.round(context.Background())
	if len(s.psk) != 1 {
		t.Fatalf("首轮后本地应缓存 1 把密钥，实际 %d", len(s.psk))
	}

	cp.sites = nil
	s.round(context.Background())
	if len(s.psk) != 0 {
		t.Fatalf("站点消失后应清掉密钥缓存，实际还剩 %d 把", len(s.psk))
	}
}

// ── fail-closed ──

// ★控制面拉不到时必须**保留上一轮配置**：传空列表会被 Backend 当成
// "管理员把站点删光了"而拆掉全部隧道——控制面抖一下就让所有分支断网。
func TestPullFailureKeepsLastConfig(t *testing.T) {
	cp := newFakeControl()
	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 1)}
	cp.psk["site-sh"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-sh"] = 1
	back := &fakeBackend{}
	s := testSyncer(cp, back)
	s.round(context.Background())
	if len(back.applyCalls) != 1 {
		t.Fatalf("首轮应对账一次，实际 %d 次", len(back.applyCalls))
	}

	cp.sitesErr = errors.New("dial tcp 127.0.0.1:8443: connect: connection refused")
	s.round(context.Background())
	s.round(context.Background())
	if len(back.applyCalls) != 1 {
		t.Fatalf("拉取失败后不该再调 Apply（会把站点全拆了），实际累计 %d 次", len(back.applyCalls))
	}
	// 但"配置可能已过期"必须看得见：不说的话，管理员看到的是一条状态正常的隧道，
	// 而它跑的可能是十分钟前的配置。
	assertLastErrorContains(t, cp, "site-sh", "未响应")
	assertLastErrorContains(t, cp, "site-sh", "配置可能已过期")

	// 恢复后要能重新对账。
	cp.sitesErr = nil
	s.round(context.Background())
	if len(back.applyCalls) != 2 {
		t.Fatalf("控制面恢复后应重新对账，实际累计 %d 次", len(back.applyCalls))
	}
	if got := lastState(t, cp, "site-sh"); strings.Contains(got.LastError, "未响应") {
		t.Errorf("恢复后不该再挂着过期提示：%q", got.LastError)
	}
}

// ── 归属过滤 ──

// 不归本机的站点整条忽略：多网关下两台抢同一条站点会各建一条 SA、互相 rekey/删除，
// 表现为隧道周期性抖动，而两台各自的日志都显示"一切正常"。
func TestForeignSiteIgnoredEntirely(t *testing.T) {
	cp := newFakeControl()
	mine, theirs := dto("site-mine", 1), dto("site-theirs", 1)
	theirs.GatewayID = "ipsec-2"
	cp.sites = []cplane.IpsecSiteDTO{mine, theirs}
	cp.psk["site-mine"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-mine"] = 1
	cp.psk["site-theirs"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-theirs"] = 1
	back := &fakeBackend{}
	s := testSyncer(cp, back)
	s.round(context.Background())

	cfgs := back.lastApply(t)
	if len(cfgs) != 1 || cfgs[0].ID != "site-mine" {
		t.Fatalf("只该下发本机的站点，实际 %d 条：%+v", len(cfgs), cfgs)
	}
	// 连密钥都不该去取：别人的站点密钥没有任何理由经过本机。
	if cp.pskHits["site-theirs"] != 0 {
		t.Errorf("不该取别家站点的密钥，实际取了 %d 次", cp.pskHits["site-theirs"])
	}
}

// ── 解析失败的站点必须留在界面上 ──

// 丢掉的后果是它在控制台上凭空消失，管理员看不到任何错误也找不到那条站点。
func TestUnparsableSiteIsReportedNotDropped(t *testing.T) {
	cp := newFakeControl()
	bad := dto("site-bad", 1)
	bad.RemoteSubnet = "10.40.0.0" // 少了前缀长度，是最常见的手误
	cp.sites = []cplane.IpsecSiteDTO{bad}
	cp.psk["site-bad"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-bad"] = 1
	back := &fakeBackend{}
	s := testSyncer(cp, back)
	s.round(context.Background())

	cfgs := back.lastApply(t)
	if len(cfgs) != 1 {
		t.Fatalf("解析失败的站点也要下发（交给 Validate 拒绝并回报原因），实际 %d 条", len(cfgs))
	}
	if cfgs[0].RemoteSubnet.IsValid() {
		t.Error("解析失败的字段应保持零值，让 Validate 当面拒绝")
	}
	assertLastErrorContains(t, cp, "site-bad", "remoteSubnet")
	assertLastErrorContains(t, cp, "site-bad", "缺少前缀长度")
}

// ── 退出前的最后一次回报 ──

// 不报的话，库里那行 state=up 会永久留着——控制台上就是一条"已建立"却早已不存在的隧道。
func TestShutdownReportMarksSitesDown(t *testing.T) {
	cp := newFakeControl()
	cp.sites = []cplane.IpsecSiteDTO{dto("site-sh", 1)}
	cp.psk["site-sh"] = []byte("psk-v1-0123456789abcdef")
	cp.pskVer["site-sh"] = 1
	back := &fakeBackend{}
	s := testSyncer(cp, back)
	s.round(context.Background())

	s.shutdownReport(context.Background(), "收到停止信号")
	got := lastState(t, cp, "site-sh")
	// failed 而不是 down：down 的语义是"管理员没启用"，而此刻的事实是
	// "启用着，但承载它的网关退出了"——那是故障不是意图。
	if got.State != ipsec.StateFailed {
		t.Errorf("退出前应把站点报成 failed，实际 %q", got.State)
	}
	if !strings.Contains(got.LastError, "已退出") {
		t.Errorf("退出原因应写清楚，实际 %q", got.LastError)
	}
}

// ── 纯函数 ──

func TestParsePeer(t *testing.T) {
	// 端口留 0 交给 Validate 补 500：缺省值只能有一个来源。
	if ap, err := parsePeer("203.0.113.21"); err != nil || ap.Port() != 0 || ap.Addr().String() != "203.0.113.21" {
		t.Errorf("裸 IP 解析不对：%v %v", ap, err)
	}
	if ap, err := parsePeer("203.0.113.21:1500"); err != nil || ap.Port() != 1500 {
		t.Errorf("带端口解析不对：%v %v", ap, err)
	}
	if _, err := parsePeer(""); err == nil {
		t.Error("空 peer 必须报错（网关不猜对端在哪）")
	}
	// ★不做 DNS：隧道对端在 DNS 抖动时切换落点，会得到一条谁也解释不清的间歇性故障。
	if _, err := parsePeer("peer.example.com"); err == nil {
		t.Error("域名形态应被拒绝")
	}
}

func TestParsePrefix(t *testing.T) {
	if p, err := parsePrefix("localSubnet", "10.20.0.0/16"); err != nil || p.String() != "10.20.0.0/16" {
		t.Errorf("正常 CIDR 解析不对：%v %v", p, err)
	}
	if _, err := parsePrefix("remoteSubnet", "10.40.0.0"); err == nil ||
		!strings.Contains(err.Error(), "缺少前缀长度") {
		t.Errorf("漏写前缀长度时应给出可照抄的写法，实际：%v", err)
	}
	if _, err := parsePrefix("localSubnet", ""); err == nil {
		t.Error("空网段必须报错（它就是 TSi/TSr）")
	}
	// 4-in-6 与同值 IPv4 用 == 比不相等，混进来会在多处静默对不上。
	if _, err := parsePrefix("localSubnet", "::ffff:10.20.0.0/120"); err == nil {
		t.Error("4-in-6 形态应当面拒绝")
	}
}

// 路由清单必须来自控制面下发的 remoteSubnet，且**只含已启用的站点**。
func TestDesiredRoutes(t *testing.T) {
	cfgs := []ipsec.SiteConfig{
		{ID: "a", Enabled: true, RemoteSubnet: netip.MustParsePrefix("10.40.0.0/16")},
		{ID: "b", Enabled: true, RemoteSubnet: netip.MustParsePrefix("10.50.0.0/16")},
		{ID: "c", Enabled: false, RemoteSubnet: netip.MustParsePrefix("10.60.0.0/16")},
		{ID: "d", Enabled: true, RemoteSubnet: netip.MustParsePrefix("10.40.0.0/16")}, // 重复
		{ID: "e", Enabled: true}, // 网段没解析出来
	}
	got := desiredRoutes(cfgs)
	want := []string{"10.40.0.0/16", "10.50.0.0/16"}
	if len(got) != len(want) {
		t.Fatalf("路由数 %d，期望 %d：%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("第 %d 条路由 %s，期望 %s（顺序必须稳定，否则两次运行的日志无法对比）", i, got[i], want[i])
		}
	}
}

// ── 启动期硬校验 ──

func TestResolveGatewayID(t *testing.T) {
	if id, err := resolveGatewayID("", "ipsec-1"); err != nil || id != "ipsec-1" {
		t.Errorf("留空应取证书 CN：%q %v", id, err)
	}
	if id, err := resolveGatewayID("ipsec-1", "ipsec-1"); err != nil || id != "ipsec-1" {
		t.Errorf("一致时应通过：%q %v", id, err)
	}
	// ★不一致必须启动期拒绝：控制面按 CN 下发、本地按 gwid 判归属，
	// 对不上时每条站点都被整条忽略，现象是"站点永远 connecting 且零报错"。
	if _, err := resolveGatewayID("ipsec-2", "ipsec-1"); err == nil {
		t.Error("gwid 与证书 CN 不一致必须拒绝启动")
	}
	// CN 没有 ipsec- 前缀 → 三个端点全部 403，每 15 秒失败一次。
	if _, err := resolveGatewayID("", "gw-1"); err == nil {
		t.Error("CN 不以 ipsec- 开头必须拒绝启动")
	}
}

// ── 断言辅助 ──

func lastState(t *testing.T, cp *fakeControl, id string) ipsec.SiteState {
	t.Helper()
	if len(cp.reported) == 0 {
		t.Fatal("从未回报过状态")
	}
	for _, st := range cp.reported[len(cp.reported)-1] {
		if st.SiteID == id {
			return st
		}
	}
	t.Fatalf("最近一次回报里没有站点 %s", id)
	return ipsec.SiteState{}
}

func assertLastErrorContains(t *testing.T, cp *fakeControl, id, want string) {
	t.Helper()
	got := lastState(t, cp, id).LastError
	if !strings.Contains(got, want) {
		t.Errorf("站点 %s 回报的 LastError 里应含 %q，实际 %q", id, want, got)
	}
}
