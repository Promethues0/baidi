package api

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/standby"
	"baidi.dev/control/internal/store"
)

// 控制面温备（PRD 15.5）的主机侧用例。三条主线：
//   ① 身份闸——**普通管理员令牌不得拉走备份**，网关/组网证书同样不行；
//   ② 台账语义——失败回报不许推进"上次成功同步"；
//   ③ 集群视图三态，且与 /diag checkCluster 同口径。

const testStandbyPass = "standby-passphrase-1"

type sbFixture struct {
	st    *store.SQLiteStore
	srv   *Server
	admin http.Handler
	mtls  http.Handler
}

func newStandbyFixture(t *testing.T, pass string) *sbFixture {
	t.Helper()
	// ★口令要在 New 之前注入：Server 在构造期读它（与 postureStrict 同一条做法）。
	t.Setenv("BAIDI_STANDBY_PASSPHRASE", pass)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "standby.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, false)
	return &sbFixture{st: st, srv: s,
		admin: auth.Middleware(testKeys, s.IsOpen)(s.Routes()),
		mtls:  s.MTLSHandler()}
}

func (f *sbFixture) callMTLS(t *testing.T, method, path, cn, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: cn}},
	}}
	w := httptest.NewRecorder()
	f.mtls.ServeHTTP(w, r)
	return w
}

// ── ① 身份闸 ──

// TestStandbyBackupRejectsAdminToken **这条最要紧**：一份备份 = CA 私钥 + 三把签名私钥 +
// 审计链密钥 + 全部凭据 + 整个库。它绝不能挂在明文口 + Bearer 上，否则一次令牌泄露
// 等于整套系统被完整复制走，而现场只留下一条看起来很正常的审计。
func TestStandbyBackupRejectsAdminToken(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	for _, tok := range []string{
		testKeys.Sign(auth.Claims{Sub: "admin", Role: "admin", Name: "admin"}, tokenTTL),
		userToken("li.fang"),
	} {
		for _, p := range []string{standby.PathBackup, standby.PathStatus} {
			r := httptest.NewRequest(http.MethodGet, p, nil)
			r.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			f.admin.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s 在明文口必须 403（得 %d）：管理员令牌不能拉走整套信任材料", p, w.Code)
			}
			if strings.Contains(w.Body.String(), standby.CNPrefix) == false {
				t.Errorf("拒绝理由要说清「只在 mTLS 口 + standby- 证书」，否则会被读成路径写错：%s", w.Body.String())
			}
		}
	}
}

// TestStandbyBackupRejectsGatewayCerts 网关与组网证书都拉不走备份。
// 允许的话，等于把 CA 私钥发给被保护方——数据面持有签发能力正是这套设计一直在拆的东西。
func TestStandbyBackupRejectsGatewayCerts(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	for _, cn := range []string{"gw-1", "ipsec-gw-1", "", "standby"} {
		if w := f.callMTLS(t, http.MethodGet, standby.PathBackup, cn, ""); w.Code != http.StatusForbidden {
			t.Fatalf("CN=%q 拉备份应 403，得 %d", cn, w.Code)
		}
	}
}

// TestStandbyCertCannotCallGatewayAPIs 反方向也要堵：备机证书调不到网关接口。
// 让它注册成网关的话，剖面会把这台不转发流量的机器当可用落点下发给终端。
func TestStandbyCertCannotCallGatewayAPIs(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	for _, p := range []string{"/api/v1/gateways/policy", "/api/v1/gateways/ipsec"} {
		if w := f.callMTLS(t, http.MethodGet, p, "standby-1", ""); w.Code != http.StatusForbidden {
			t.Fatalf("备机证书调 %s 应 403，得 %d", p, w.Code)
		}
	}
	w := f.callMTLS(t, http.MethodPost, "/api/v1/gateways/register", "standby-1", `{"id":"standby-1"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("备机证书注册成网关应 403，得 %d", w.Code)
	}
}

// TestStandbyBackupWithoutPassphraseIsRefused 没配口令就不产出备份（fail-closed）。
// 回一份不加密的备份是这里唯一不能接受的降级。
func TestStandbyBackupWithoutPassphraseIsRefused(t *testing.T) {
	f := newStandbyFixture(t, "")
	w := f.callMTLS(t, http.MethodGet, standby.PathBackup, "standby-1", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("未配口令应 503，得 %d", w.Code)
	}
	if w.Body.Len() > 0 && strings.Contains(w.Body.String(), "BAIDI-BACKUP") {
		t.Fatal("绝不能在未配口令时产出任何备份内容")
	}
}

// TestStandbyBackupIsRealAndVerifiable 备机证书拿到的是一份**真能解开**的备份，
// 且解开后必须含数据库——走的就是备机侧那条校验路径（同一个函数）。
func TestStandbyBackupIsRealAndVerifiable(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	w := f.callMTLS(t, http.MethodGet, standby.PathBackup, "standby-1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("备机拉备份应 200，得 %d：%s", w.Code, w.Body.String())
	}
	meta, files, err := standby.VerifyBackup(w.Body.Bytes(), testStandbyPass)
	if err != nil {
		t.Fatalf("主机产出的备份必须能通过备机侧同一条校验：%v", err)
	}
	if meta.Version != Version || !strings.Contains(meta.Note, "standby-1") {
		t.Errorf("备份头应记录版本与拉取方：%+v", meta)
	}
	if len(files) == 0 {
		t.Error("备份里应含材料清单")
	}
	// 换个口令必须解不开
	if _, _, err := standby.VerifyBackup(w.Body.Bytes(), "wrong-passphrase-x"); err == nil {
		t.Error("换口令还能解开的话，加密就没有意义")
	}
	// 拉取动作两侧都要留痕
	if !hasAuditContaining(t, f.st, "温备节点拉取配置备份") {
		t.Error("备机拉走整套信任材料这件事必须落审计")
	}
}

// ── ② 台账语义 ──

// TestStandbyStatusFailDoesNotAdvanceLastSync 失败回报不许推进"上次成功同步"。
// 推进了就等于把「拉失败」显示成「刚同步过」，方向完全反了。
func TestStandbyStatusFailDoesNotAdvanceLastSync(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	ok := `{"addr":"10.0.0.2","intervalSec":600,"status":"ok","backupVersion":"0.3.0",` +
		`"backupCreatedAt":"2026-08-11 10:00:00","sha256":"abcdef0123456789abcdef"}`
	if w := f.callMTLS(t, http.MethodPost, standby.PathStatus, "standby-1", ok); w.Code != http.StatusOK {
		t.Fatalf("回报成功应 200，得 %d：%s", w.Code, w.Body.String())
	}
	first := onlyNode(t, f)
	if first.LastSyncAt == 0 || first.LastStatus != "ok" || first.IntervalSec != 600 {
		t.Fatalf("成功回报应落库：%+v", first)
	}
	if first.BackupSHA256 == "" || first.Addr != "10.0.0.2" {
		t.Fatalf("备份指纹与落点应落库：%+v", first)
	}

	bad := `{"addr":"10.0.0.2","intervalSec":600,"status":"fail","detail":"主机回 503"}`
	if w := f.callMTLS(t, http.MethodPost, standby.PathStatus, "standby-1", bad); w.Code != http.StatusOK {
		t.Fatalf("回报失败也应被接收（这正是要记的事），得 %d", w.Code)
	}
	after := onlyNode(t, f)
	if after.LastSyncAt != first.LastSyncAt {
		t.Fatalf("失败回报推进了 last_sync_at：%d → %d", first.LastSyncAt, after.LastSyncAt)
	}
	if after.LastStatus != "fail" || !strings.Contains(after.LastDetail, "503") {
		t.Fatalf("失败详情应落库：%+v", after)
	}
	if after.BackupVersion != "0.3.0" {
		t.Fatalf("失败那次没有新备份头，不该把上一次的抹成空：%+v", after)
	}
	if !hasAuditContaining(t, f.st, "温备节点回报同步失败") {
		t.Error("同步失败必须落审计（且不节流：连续失败正是唯一需要被看见的信号）")
	}
}

// TestStandbyNodeIDComesFromCertCN 节点 id 只认证书 CN。
// 按请求体自报的话，一台备机能顶着另一台的名字回报"同步正常"。
func TestStandbyNodeIDComesFromCertCN(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	body := `{"nodeId":"standby-9","addr":"1.2.3.4","intervalSec":600,"status":"ok"}`
	if w := f.callMTLS(t, http.MethodPost, standby.PathStatus, "standby-1", body); w.Code != http.StatusOK {
		t.Fatalf("回报应 200，得 %d", w.Code)
	}
	if n := onlyNode(t, f); n.NodeID != "standby-1" {
		t.Fatalf("节点 id 必须取自证书 CN，得到 %q", n.NodeID)
	}
}

// ── ③ 集群视图三态 + 与 /diag 同口径 ──

// TestClusterViewThreeStates 未配置 / 新鲜 / 落后，三态都要能从真实台账算出来。
func TestClusterViewThreeStates(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	ctx := t.Context()

	// ① 未配置备机
	v := f.srv.clusterView(ctx)
	if v.Deployed || v.Status != "skip" || !strings.Contains(v.Summary, "未配置备机") {
		t.Fatalf("空台账应回「未配置备机」skip：%+v", v)
	}
	if v.PromoteCmd == "" || len(v.Boundaries) == 0 {
		t.Error("边界与切换命令必须随视图下发（页面要直接展示，不能只写在文档里）")
	}

	// ② 新鲜
	now := time.Now().Unix()
	mustSaveStatus(t, f, standby.Node{NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600}, true, now-60)
	v = f.srv.clusterView(ctx)
	if !v.Deployed || v.Status != "pass" || v.Mode != standby.ModeWarm {
		t.Fatalf("刚同步过应回 warm-standby/pass：%+v", v)
	}
	if !strings.Contains(v.RPO, "RPO") || !strings.Contains(v.RPO, "10 分钟") {
		t.Errorf("RPO 必须在视图里明说（= 同步间隔）：%q", v.RPO)
	}

	// ③ 落后
	mustSaveStatus(t, f, standby.Node{NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600}, true, now-4*3600)
	v = f.srv.clusterView(ctx)
	if v.Status != "warn" || v.Nodes[0].State != standby.StateStale {
		t.Fatalf("落后 4 小时应判 stale/warn：%+v", v)
	}
	if v.Nodes[0].LagSeconds < 3600 {
		t.Errorf("落后秒数应实算：%+v", v.Nodes[0])
	}
}

// TestDiagClusterMatchesSystemPage /diag 与 System 页读同一个 clusterView。
// 此前两处各写死一段文案——那种形态下"改一处漏一处"没有任何报错，
// 只会让两个页面对同一件事给出不同答案。
func TestDiagClusterMatchesSystemPage(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	ctx := t.Context()

	c := f.srv.checkCluster(ctx)
	v := f.srv.clusterView(ctx)
	if c.Status != v.Status || c.Summary != v.Summary {
		t.Fatalf("未配置备机时两处应同口径：diag=%+v view=%+v", c, v)
	}
	if c.Status != "skip" {
		t.Fatalf("未配置备机应 skip（不参与健康分），得 %q", c.Status)
	}

	mustSaveStatus(t, f, standby.Node{NodeID: "standby-1", Addr: "10.0.0.2", IntervalSec: 600},
		true, time.Now().Unix()-4*3600)
	c, v = f.srv.checkCluster(ctx), f.srv.clusterView(ctx)
	if c.Status != v.Status || c.Status != "warn" {
		t.Fatalf("落后时两处都应 warn：diag=%q view=%q", c.Status, v.Status)
	}
	if len(c.Items) != 1 || c.Items[0].Label != "standby-1" {
		t.Fatalf("诊断应逐台列出备机：%+v", c.Items)
	}
	if !strings.Contains(c.Metric, "备机 1") {
		t.Errorf("指标应给出备机台数：%q", c.Metric)
	}
}

// TestSystemPageCarriesClusterView 系统管理页的响应里带真实集群块（形状不变，内容变真）。
func TestSystemPageCarriesClusterView(t *testing.T) {
	f := newStandbyFixture(t, testStandbyPass)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system", nil)
	r.Header.Set("Authorization", "Bearer "+testKeys.Sign(
		auth.Claims{Sub: "admin", Role: "admin", Name: "admin"}, tokenTTL))
	w := httptest.NewRecorder()
	f.admin.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("系统页应 200，得 %d：%s", w.Code, w.Body.String())
	}
	var body struct {
		Roles   []map[string]any    `json:"roles"`
		Admins  []map[string]any    `json:"admins"`
		Cluster standby.ClusterView `json:"cluster"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Roles) == 0 || len(body.Admins) == 0 {
		t.Fatal("角色与管理员仍应下发（嵌入结构不能把原字段挤掉）")
	}
	if body.Cluster.Status != "skip" || body.Cluster.PromoteCmd == "" {
		t.Fatalf("集群块应是真实视图：%+v", body.Cluster)
	}
}

// TestClusterViewWarnsWhenPassphraseMissing 配了备机却没配口令：当场说清楚。
// 不说的话要等好几轮才在"落后"里间接体现，而根因（主机 503）在页面上完全看不见。
func TestClusterViewWarnsWhenPassphraseMissing(t *testing.T) {
	f := newStandbyFixture(t, "")
	mustSaveStatus(t, f, standby.Node{NodeID: "standby-1", IntervalSec: 600}, true, time.Now().Unix())
	v := f.srv.clusterView(t.Context())
	if v.Status != "warn" || !strings.Contains(v.Note, "BAIDI_STANDBY_PASSPHRASE") {
		t.Fatalf("主机缺口令应当场 warn 并点名：%+v", v)
	}
}

// ── 小工具 ──

func mustSaveStatus(t *testing.T, f *sbFixture, n standby.Node, ok bool, at int64) {
	t.Helper()
	if err := f.st.SaveStandbyStatus(t.Context(), n, ok, at); err != nil {
		t.Fatalf("落备机状态: %v", err)
	}
}

func onlyNode(t *testing.T, f *sbFixture) standby.Node {
	t.Helper()
	ns, err := f.st.StandbyNodes(t.Context())
	if err != nil {
		t.Fatalf("读备机台账: %v", err)
	}
	if len(ns) != 1 {
		t.Fatalf("应恰好一台备机，得到 %d 台", len(ns))
	}
	return ns[0]
}

func hasAuditContaining(t *testing.T, st *store.SQLiteStore, sub string) bool {
	t.Helper()
	b, err := st.Audit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range b.Logs {
		if strings.Contains(e.Event, sub) {
			return true
		}
	}
	return false
}
