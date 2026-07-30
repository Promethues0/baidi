package site

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/gateway/internal/ipsec"
	"baidi.dev/gateway/internal/ipsec/esp"
)

// 本文件只验**对账逻辑**，不碰协议：IKE 状态机被换成一个假引擎。
//
// 为什么值得单独隔出来验：Apply 每 15 秒被调用一次，它的每一个分支都对应一种
// 现场故障——「改了配置没生效」「停用了还在通」「隧道永远停在协商中」——
// 而这些分支若混在真握手里测，一次失败要花很久才能定位到底是对账错了还是协议错了。
//
// 辅助一律加 bkt 前缀（backend test）。

// bktIKE 假的 IKE 状态机：只记录被要求做了什么，并允许注入返回值。
type bktIKE struct {
	mu      sync.Mutex
	added   []string                   // AddSite 调用序列（含重复，用来抓"每轮都重建"）
	removed []string                   // RemoveSite 调用序列
	addErr  map[string]error           // 注入某站点的装载失败
	live    map[string]ipsec.SiteState // 注入"状态机眼里的实测状态"
	touched []uint32
}

func newBktIKE() *bktIKE {
	return &bktIKE{addErr: map[string]error{}, live: map[string]ipsec.SiteState{}}
}

func (f *bktIKE) AddSite(cfg ipsec.SiteConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, cfg.ID)
	return f.addErr[cfg.ID]
}

func (f *bktIKE) RemoveSite(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	return nil
}

func (f *bktIKE) States() []ipsec.SiteState {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ipsec.SiteState, 0, len(f.live))
	for _, st := range f.live {
		out = append(out, st)
	}
	return out
}

func (f *bktIKE) Run(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

func (f *bktIKE) Touch(spi uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, spi)
}

func (f *bktIKE) addCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.added {
		if a == id {
			n++
		}
	}
	return n
}

func (f *bktIKE) removeCount(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.removed {
		if a == id {
			n++
		}
	}
	return n
}

func bktLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// bktBackend 组一个只做对账、不跑数据面的 Backend（数据面用一对内存管道占位）。
func bktBackend(t *testing.T, gwID string, extra func(string) ipsec.ExtraOptions) (*GoBackend, *bktIKE, *esp.Engine) {
	t.Helper()
	netw := ipsec.NewMemNet()
	tr, err := netw.Bind(netip.MustParseAddrPort("192.0.2.10:4500"))
	if err != nil {
		t.Fatalf("绑定内存网失败：%v", err)
	}
	dp, host := ipsec.NewPairDatapath(1400)
	prot := esp.New(bktLog(), time.Now)
	fake := newBktIKE()
	b, err := NewBackend(BackendOptions{
		GatewayID: gwID,
		Transport: tr,
		Datapath:  dp,
		IKE:       fake,
		Protector: prot,
		Log:       bktLog(),
		Extra:     extra,
	})
	if err != nil {
		t.Fatalf("组装 Backend 失败：%v", err)
	}
	t.Cleanup(func() {
		_ = b.Close()
		_ = host.Close()
		_ = tr.Close()
	})
	return b, fake, prot
}

func bktCfg(id string) ipsec.SiteConfig {
	return ipsec.SiteConfig{
		ID:           id,
		Name:         id,
		GatewayID:    "gw-1",
		Enabled:      true,
		Peer:         netip.MustParseAddrPort("203.0.113.88:500"),
		LocalSubnet:  netip.MustParsePrefix("10.10.0.0/16"),
		RemoteSubnet: netip.MustParsePrefix("10.20.0.0/16"),
		LocalID:      "gw-a.baidi",
		RemoteID:     "gw-b.baidi",
		Auth:         "psk",
		Suite:        "standard",
		Phase1:       ipsec.Phase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		Phase2:       ipsec.Phase{Enc: "AES256-GCM", Hash: "SHA256", DH: "group19"},
		PFS:          true,
		PSK:          []byte("baidi-ipsec-psk-0123456789abcdef"),
	}
}

func bktStates(t *testing.T, b *GoBackend) map[string]ipsec.SiteState {
	t.Helper()
	sts, err := b.States(context.Background())
	if err != nil {
		t.Fatalf("取状态失败：%v", err)
	}
	m := make(map[string]ipsec.SiteState, len(sts))
	for _, s := range sts {
		m[s.SiteID] = s
	}
	return m
}

// ★本文件最重要的一条：**配置没变就什么都不做**。
// 同步循环 15 秒一轮，若每轮都重建 SA，隧道会永远停在握手中、业务永远不通，
// 而每一轮的日志都显示"正在协商"——看起来一切都在努力工作。
func TestApplyIsIdempotent(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	cfg := []ipsec.SiteConfig{bktCfg("site-a")}

	for i := 0; i < 5; i++ {
		if err := b.Apply(context.Background(), cfg); err != nil {
			t.Fatalf("第 %d 轮 Apply 失败：%v", i, err)
		}
	}
	if n := fake.addCount("site-a"); n != 1 {
		t.Errorf("同一份配置连下发 5 轮，AddSite 应当只被调用 1 次，实得 %d 次（每轮重建 SA = 隧道永远建不起来）", n)
	}
	if n := fake.removeCount("site-a"); n != 0 {
		t.Errorf("配置没变不该拆站点，实得 RemoveSite %d 次", n)
	}
}

// Validate 会就地补缺省值，因此指纹计算必须发生在补齐**之后**——
// 否则第一轮补了默认值、第二轮又与原始值比对，会判成"配置变了"而无限重建。
// 上面那条测试已经覆盖了这个陷阱（传进去的配置没填生存期）。

// 改了 PSK 必须重建 SA。
// ★不重建的后果：隧道继续用旧密钥跑，直到下一次 rekey 才突然认证失败——
// 那时距离改密钥可能已过去几小时，没人会把两件事联系起来。
func TestApplyRebuildsOnPSKChange(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	cfg := bktCfg("site-a")
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{cfg}); err != nil {
		t.Fatal(err)
	}
	cfg.PSK = []byte("baidi-ipsec-psk-CHANGED-000000000")
	cfg.PSKVersion = 2
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{cfg}); err != nil {
		t.Fatal(err)
	}
	if n := fake.addCount("site-a"); n != 2 {
		t.Errorf("PSK 变更后应当重建（AddSite 2 次），实得 %d 次", n)
	}
	if n := fake.removeCount("site-a"); n != 1 {
		t.Errorf("重建前应先拆掉旧的（RemoveSite 1 次），实得 %d 次", n)
	}
}

func TestApplyRebuildsOnSubnetChange(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	cfg := bktCfg("site-a")
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{cfg}); err != nil {
		t.Fatal(err)
	}
	cfg.RemoteSubnet = netip.MustParsePrefix("10.30.0.0/16")
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{cfg}); err != nil {
		t.Fatal(err)
	}
	if n := fake.addCount("site-a"); n != 2 {
		t.Errorf("网段变更后应当重建，AddSite 实得 %d 次", n)
	}
}

// ★enabled=false 必须**真的**让流量停掉：既拆 IKE 侧，也清 ESP 侧的 SA。
// 只拆一半会留下"界面显示 down、流量照常通过"的隧道，这是最坏的一种不一致。
func TestApplyDisabledSiteIsTornDownBothSides(t *testing.T) {
	b, fake, prot := bktBackend(t, "gw-1", nil)
	cfg := bktCfg("site-a")
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{cfg}); err != nil {
		t.Fatal(err)
	}
	// 装一条 Child SA，模拟"已经建好了"。
	if err := prot.Install(bktChildSA("site-a")); err != nil {
		t.Fatalf("装载 SA 失败：%v", err)
	}
	if _, ok := prot.Info(0x00001001); !ok {
		t.Fatalf("SA 应当已装载")
	}

	cfg.Enabled = false
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{cfg}); err != nil {
		t.Fatal(err)
	}
	if n := fake.removeCount("site-a"); n != 1 {
		t.Errorf("停用后应当拆 IKE 侧，RemoveSite 实得 %d 次", n)
	}
	if _, ok := prot.Info(0x00001001); ok {
		t.Errorf("停用后 ESP 侧的 SA 仍在——界面会显示 down 而流量照常通过")
	}
	if st := bktStates(t, b)["site-a"]; st.State != ipsec.StateDown {
		t.Errorf("停用的站点状态应为 down（管理意图，不是故障），实得 %s", st.State)
	}
}

// 从下发清单里消失的站点必须被拆掉。
func TestApplyRemovesVanishedSite(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bktCfg("site-a"), bktCfg("site-b")}); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bktCfg("site-a")}); err != nil {
		t.Fatal(err)
	}
	if n := fake.removeCount("site-b"); n != 1 {
		t.Errorf("已从清单移除的站点应当被拆，RemoveSite(site-b) 实得 %d 次", n)
	}
	if _, ok := bktStates(t, b)["site-b"]; ok {
		t.Errorf("已移除的站点不该继续回报状态")
	}
}

// ★装载期拒绝必须变成那条站点的 failed + 中文原因，而不是"网关默默跳过、界面永远 connecting"。
func TestApplyRejectedConfigBecomesFailedWithReason(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	bad := bktCfg("site-bad")
	bad.Phase1.DH = "group24"
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bad}); err != nil {
		t.Fatalf("单站点拒绝不该让整批失败：%v", err)
	}
	if n := fake.addCount("site-bad"); n != 0 {
		t.Errorf("校验没过的站点绝不该交给状态机，实得 AddSite %d 次", n)
	}
	st := bktStates(t, b)["site-bad"]
	if st.State != ipsec.StateFailed {
		t.Fatalf("状态应为 failed，实得 %s", st.State)
	}
	for _, want := range []string{"site-bad", "group24", "phase1.dh"} {
		if !strings.Contains(st.LastError, want) {
			t.Errorf("回报的原因里缺少 %q（管理员据此才知道改哪一格）：%s", want, st.LastError)
		}
	}
	if st.LastErrorAt == 0 {
		t.Errorf("failed 状态必须带时间戳")
	}
}

// 空 PSK 是重点：它能协商成功，所以只能靠装载期拦。
func TestApplyRejectsEmptyPSK(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	bad := bktCfg("site-nopsk")
	bad.PSK = nil
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bad}); err != nil {
		t.Fatal(err)
	}
	if fake.addCount("site-nopsk") != 0 {
		t.Errorf("空 PSK 的站点绝不该被装载")
	}
	if st := bktStates(t, b)["site-nopsk"]; st.State != ipsec.StateFailed || !strings.Contains(st.LastError, "PSK") {
		t.Errorf("应回报 failed 且说明是 PSK 的问题，实得 %s / %s", st.State, st.LastError)
	}
}

// 控制面下发了 pqHybrid=true / ikeVersion=IKEv1 时，必须经 Extra 钩子当面拒掉。
// ★不接这个钩子，网关会照常按 IKEv2 无 PQ 跑起来并显示 up——界面与实际彻底脱节。
func TestApplyRejectsUnsupportedExtraOptions(t *testing.T) {
	extra := func(id string) ipsec.ExtraOptions {
		if id == "site-pq" {
			return ipsec.ExtraOptions{PqHybrid: true}
		}
		return ipsec.ExtraOptions{IKEVersion: "ikev2"}
	}
	b, fake, _ := bktBackend(t, "gw-1", extra)
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bktCfg("site-pq"), bktCfg("site-ok")}); err != nil {
		t.Fatal(err)
	}
	if fake.addCount("site-pq") != 0 {
		t.Errorf("pqHybrid=true 的站点不该被装载")
	}
	if fake.addCount("site-ok") != 1 {
		t.Errorf("正常站点应当被装载")
	}
	if st := bktStates(t, b)["site-pq"]; !strings.Contains(st.LastError, "pqHybrid") {
		t.Errorf("原因里应点名 pqHybrid，实得：%s", st.LastError)
	}
}

// 不归本机的站点整条忽略、连状态都不回报——否则会与真正负责的那台网关
// 在同一行里互相覆盖。
func TestApplyIgnoresOtherGatewaysSites(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	other := bktCfg("site-other")
	other.GatewayID = "gw-2"
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bktCfg("site-a"), other}); err != nil {
		t.Fatal(err)
	}
	if fake.addCount("site-other") != 0 {
		t.Errorf("别的网关的站点不该被本机装载")
	}
	if _, ok := bktStates(t, b)["site-other"]; ok {
		t.Errorf("别的网关的站点不该由本机回报状态")
	}
}

// ★无主站点（gatewayId 为空）不是"谁都能跑"，而是配置缺失：必须当面拒绝。
// 静默跳过的话，界面上永远没有任何解释。
func TestApplyRejectsUnassignedSite(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	orphan := bktCfg("site-orphan")
	orphan.GatewayID = ""
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{orphan}); err != nil {
		t.Fatal(err)
	}
	if fake.addCount("site-orphan") != 0 {
		t.Errorf("无主站点不该被装载")
	}
	st := bktStates(t, b)["site-orphan"]
	if st.State != ipsec.StateFailed || !strings.Contains(st.LastError, "gatewayId") {
		t.Errorf("应当 failed 且点名 gatewayId，实得 %s / %s", st.State, st.LastError)
	}
}

// 状态机侧的装载拒绝（如它不认识的算法名）同样要落到那条站点上。
func TestApplySurfacesEngineRejection(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	fake.addErr["site-a"] = &ipsec.ConfigError{SiteID: "site-a", Field: "phase1.enc", Reason: "AES512-GCM 无法识别"}
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bktCfg("site-a")}); err != nil {
		t.Fatal(err)
	}
	st := bktStates(t, b)["site-a"]
	if st.State != ipsec.StateFailed || !strings.Contains(st.LastError, "AES512-GCM") {
		t.Errorf("状态机的拒绝原因必须原样回报，实得 %s / %s", st.State, st.LastError)
	}
}

// 同一批里两条同 id：保留先到的并把冲突写进它的状态。
// 静默取后者会让"改了配置没生效"变成玄学。
func TestApplyReportsDuplicateIDs(t *testing.T) {
	b, _, _ := bktBackend(t, "gw-1", nil)
	a1 := bktCfg("site-dup")
	a2 := bktCfg("site-dup")
	a2.RemoteSubnet = netip.MustParsePrefix("10.90.0.0/16")
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{a1, a2}); err != nil {
		t.Fatal(err)
	}
	st := bktStates(t, b)["site-dup"]
	if !strings.Contains(st.LastError, "id 相同") {
		t.Errorf("重复 id 应当被明确指出，实得：%s", st.LastError)
	}
}

// 已装载但状态机还没报状态：应当是 connecting（刚 AddSite 完的正常空窗），
// 不能是 down（会被误读成"管理员没启用"）也不能是 failed（会被误读成故障）。
func TestStatesConnectingBeforeEngineReports(t *testing.T) {
	b, _, _ := bktBackend(t, "gw-1", nil)
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bktCfg("site-a")}); err != nil {
		t.Fatal(err)
	}
	st := bktStates(t, b)["site-a"]
	if st.State != ipsec.StateConnecting {
		t.Errorf("刚装载完应为 connecting，实得 %s", st.State)
	}
	if st.GatewayID != "gw-1" {
		t.Errorf("回报必须带上是哪台网关报的（ipsec_sa_state 主键含 gateway_id），实得 %q", st.GatewayID)
	}
	if st.ReportedAt == 0 {
		t.Errorf("回报必须带时间戳，否则无法判断状态是不是陈旧的")
	}
}

// 状态机报的 up 要能透出来，且流量数字必须来自 ESP 的实测计数。
func TestStatesUsesMeasuredCounters(t *testing.T) {
	b, fake, prot := bktBackend(t, "gw-1", nil)
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{bktCfg("site-a")}); err != nil {
		t.Fatal(err)
	}
	// 状态机谎报一个流量数字，模拟"回显配置"式的假数据。
	fake.live["site-a"] = ipsec.SiteState{
		SiteID: "site-a", State: ipsec.StateUp,
		Counters: ipsec.Counters{RxBytes: 999999, TxBytes: 888888},
	}
	if err := prot.Install(bktChildSA("site-a")); err != nil {
		t.Fatal(err)
	}
	st := bktStates(t, b)["site-a"]
	if st.State != ipsec.StateUp {
		t.Errorf("应透出状态机的 up，实得 %s", st.State)
	}
	// ★UI 上的流量数字只允许来自 ESP 实测计数。没跑过流量就该是 0，
	// 而不是任何别处来的数字——这条守着"toggle 一下界面就显示有流量"的老毛病。
	if st.RxBytes != 0 || st.TxBytes != 0 {
		t.Errorf("流量数字必须取自 ESP 实测计数（此刻应为 0），实得 rx=%d tx=%d", st.RxBytes, st.TxBytes)
	}
}

// 状态机里有、本层不认识的站点不能被悄悄藏起来：那说明某次拆除没拆干净。
func TestStatesSurfacesOrphanEngineSites(t *testing.T) {
	b, fake, _ := bktBackend(t, "gw-1", nil)
	fake.live["site-ghost"] = ipsec.SiteState{SiteID: "site-ghost", State: ipsec.StateUp}
	st := bktStates(t, b)["site-ghost"]
	if st.SiteID != "site-ghost" || !strings.Contains(st.LastError, "残留") {
		t.Errorf("状态机里的残留站点必须被暴露，实得 %+v", st)
	}
}

// 输出顺序必须稳定，否则界面每次刷新都在跳、测试也没法断言。
func TestStatesAreSorted(t *testing.T) {
	b, _, _ := bktBackend(t, "gw-1", nil)
	if err := b.Apply(context.Background(), []ipsec.SiteConfig{
		bktCfg("site-c"), bktCfg("site-a"), bktCfg("site-b"),
	}); err != nil {
		t.Fatal(err)
	}
	sts, err := b.States(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range sts {
		got = append(got, s.SiteID)
	}
	if strings.Join(got, ",") != "site-a,site-b,site-c" {
		t.Errorf("状态应按站点 id 排序，实得 %v", got)
	}
}

func TestNewBackendRequiresAllPieces(t *testing.T) {
	netw := ipsec.NewMemNet()
	tr, _ := netw.Bind(netip.MustParseAddrPort("192.0.2.99:4500"))
	defer tr.Close()
	dp, host := ipsec.NewPairDatapath(1400)
	defer host.Close()
	prot := esp.New(bktLog(), time.Now)

	full := BackendOptions{GatewayID: "gw-1", Transport: tr, Datapath: dp, IKE: newBktIKE(), Protector: prot, Log: bktLog()}
	for name, mut := range map[string]func(*BackendOptions){
		"GatewayID": func(o *BackendOptions) { o.GatewayID = "" },
		"Transport": func(o *BackendOptions) { o.Transport = nil },
		"Datapath":  func(o *BackendOptions) { o.Datapath = nil },
		"IKE":       func(o *BackendOptions) { o.IKE = nil },
		"Protector": func(o *BackendOptions) { o.Protector = nil },
	} {
		o := full
		mut(&o)
		if _, err := NewBackend(o); err == nil {
			t.Errorf("缺少 %s 时应当拒绝组装（早失败好过起来后静默不工作）", name)
		}
	}
}

// Close 必须能返回。★早期版本在 Close 里 pumps.Wait()，
// 而出向泵此刻正阻塞在 Datapath.ReadOutbound 上——结果是"进程停不下来"。
func TestCloseReturnsEvenWhilePumpBlocked(t *testing.T) {
	b, _, _ := bktBackend(t, "gw-1", nil)
	done := make(chan struct{})
	go func() { _ = b.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("Close 没有返回（多半是在等一条阻塞在数据面读上的泵）")
	}
}

// bktChildSA 造一条最小可用的 Child SA（AES-256-GCM）。
func bktChildSA(siteID string) ipsec.ChildSAParams {
	key := make([]byte, 36) // 32 密钥 + 4 salt
	for i := range key {
		key[i] = byte(i)
	}
	return ipsec.ChildSAParams{
		SiteID:     siteID,
		InSPI:      0x00001001,
		OutSPI:     0x00002002,
		EncrID:     20, // ENCR_AES_GCM_16
		KeyBits:    256,
		IntegID:    0, // combined mode 下必须是 NONE
		OutEncrKey: key,
		InEncrKey:  key,
		LocalTS:    netip.MustParsePrefix("10.10.0.0/16"),
		RemoteTS:   netip.MustParsePrefix("10.20.0.0/16"),
		Local:      netip.MustParseAddrPort("192.0.2.10:4500"),
		Peer:       netip.MustParseAddrPort("192.0.2.20:4500"),
		CreatedAt:  time.Now(),
		HardExpire: time.Now().Add(time.Hour),
	}
}
