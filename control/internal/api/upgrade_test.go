package api

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/pki"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/upgrade"

	// 直接用 SQL 读归档里那份库：不经任何白帝代码，避免"自己验自己"。
	_ "modernc.org/sqlite"
)

func userTokenFor(account string) string {
	return testKeys.Sign(auth.Claims{Sub: account, Role: "user", Name: account}, tokenTTL)
}

// 升级页要如实告知边界——PRD 第 4 章有大量源产品专有内容，
// 不说清楚的话管理员会以为界面上没有的是「还没做完」而不是「刻意不做」。
func TestUpgradeBundleStatesBoundaries(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "GET", "/api/v1/upgrade", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /upgrade http %d", code)
	}
	if out["control"] != Version {
		t.Errorf("应回控制面真实版本 %s，实际 %v", Version, out["control"])
	}
	b, _ := out["boundaries"].([]any)
	if len(b) == 0 {
		t.Fatal("必须下发边界声明")
	}
	rules, _ := out["rules"].(map[string]any)
	if rules["allowDowngrade"] != false || rules["requireComponentMatch"] != true {
		t.Errorf("出厂规则应为禁降级 + 要求组件一致：%v", rules)
	}
	if hops, _ := rules["hops"].([]any); len(hops) != 0 {
		t.Errorf("出厂规则不该内置版本链（那是源产品的历史）：%v", hops)
	}
}

// 未配置发布公钥时验签必须**拒绝**而不是跳过。
func TestUpgradeCheckRejectsWhenNoPublisherKey(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "POST", "/api/v1/upgrade/check", adminToken(), map[string]any{
		"manifest":  map[string]any{"product": "baidi", "component": "control", "version": "9.9.9", "sha256": repeat64()},
		"signature": "AAAA",
	})
	if code != http.StatusOK {
		t.Fatalf("http %d", code)
	}
	if out["blocked"] != true {
		t.Fatalf("未配公钥时必须拦住，不得静默放行：%v", out)
	}
}

func repeat64() string {
	s := ""
	for i := 0; i < 32; i++ {
		s += "ab"
	}
	return s
}

// 灰度：保存 → 终端检查更新 → 拿到判定结果。这是本章唯一能端到端跑通的链路。
func TestGrayPlanDrivesClientUpdate(t *testing.T) {
	h := newTestServer(t)

	// 全量发布：所有人都应拿到新版本
	code, out := doJSON(t, h, "PUT", "/api/v1/upgrade/gray", adminToken(), map[string]any{
		"platform": "macos", "version": "0.5.0", "stable": "0.4.0", "percent": 100,
	})
	if code != http.StatusOK {
		t.Fatalf("保存灰度计划 http %d %v", code, out)
	}

	code, upd := doJSON(t, h, "GET", "/api/v1/client/update?platform=macos&version=0.4.0",
		userTokenFor("zhang.wei"), nil)
	if code != http.StatusOK {
		t.Fatalf("检查更新 http %d", code)
	}
	if upd["latest"] != "0.5.0" || upd["update"] != true || upd["inGray"] != true {
		t.Fatalf("全量发布下应提示更新到 0.5.0：%v", upd)
	}

	// 已经是新版本的终端不该再被提示更新
	_, same := doJSON(t, h, "GET", "/api/v1/client/update?platform=macos&version=0.5.0",
		userTokenFor("zhang.wei"), nil)
	if same["update"] != false {
		t.Errorf("已是最新版不该提示更新：%v", same)
	}

	// ★比当前版本更旧的目标绝不能被标成「更新」——用户点下去就是降级。
	code, _ = doJSON(t, h, "PUT", "/api/v1/upgrade/gray", adminToken(), map[string]any{
		"platform": "macos", "version": "0.5.0", "stable": "0.4.0", "percent": 0,
	})
	if code != http.StatusOK {
		t.Fatal("改比例失败")
	}
	_, older := doJSON(t, h, "GET", "/api/v1/client/update?platform=macos&version=0.9.0",
		userTokenFor("zhang.wei"), nil)
	if older["update"] != false {
		t.Errorf("目标版本低于当前版本时不得提示更新（那是降级）：%v", older)
	}

	// 没有计划的平台如实说没有
	_, none := doJSON(t, h, "GET", "/api/v1/client/update?platform=windows", userTokenFor("zhang.wei"), nil)
	if none["update"] != false {
		t.Errorf("无计划平台不该提示更新：%v", none)
	}
}

// 灰度版本低于稳定版必须被拒——那不是灰度，是把一部分用户降级。
func TestGrayPlanRejectsDowngradeDisguisedAsGray(t *testing.T) {
	h := newTestServer(t)
	code, _ := doJSON(t, h, "PUT", "/api/v1/upgrade/gray", adminToken(), map[string]any{
		"platform": "macos", "version": "0.3.0", "stable": "0.4.0", "percent": 50,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("灰度版本低于稳定版应 400，实际 %d", code)
	}
}

// 权限：升级与备份归 PermSystem。备份尤其不能给 security——
// 一份备份含 CA 私钥与全部凭据，能导出备份等于能带走整套系统的信任材料。
func TestUpgradeWritesRequireSystemPerm(t *testing.T) {
	h := newTestServer(t)
	secTok := makeAdmin(t, h, "sec.only", "security")

	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"PUT", "/api/v1/upgrade/rules", map[string]any{"allowDowngrade": true}},
		{"PUT", "/api/v1/upgrade/gray", map[string]any{"platform": "macos", "version": "0.5.0", "stable": "0.4.0"}},
		{"POST", "/api/v1/upgrade/backup", map[string]any{"passphrase": "correct-horse-battery"}},
		{"POST", "/api/v1/upgrade/check", map[string]any{"manifest": map[string]any{}, "signature": ""}},
	} {
		if code, _ := doJSON(t, h, c.method, c.path, secTok, c.body); code != http.StatusForbidden {
			t.Errorf("安全管理员调 %s %s 应 403，实际 %d", c.method, c.path, code)
		}
	}
	// 读得到（读=任意管理员）
	if code, _ := doJSON(t, h, "GET", "/api/v1/upgrade", secTok, nil); code != http.StatusOK {
		t.Errorf("安全管理员应能读升级页，实际 %d", code)
	}
	// 普通用户连读都不行
	if code, _ := doJSON(t, h, "GET", "/api/v1/upgrade", userTokenFor("zhang.wei"), nil); code != http.StatusForbidden {
		t.Errorf("普通用户读升级页应 403，实际 %d", code)
	}
	// 但普通用户能查自己的客户端更新（那是终端自助能力）
	if code, _ := doJSON(t, h, "GET", "/api/v1/client/update?platform=macos",
		userTokenFor("zhang.wei"), nil); code != http.StatusOK {
		t.Errorf("普通用户应能检查客户端更新，实际 %d", code)
	}
}

// 备份口令过短要被拒，且拒绝理由要说清为什么（备份里装着什么）。
func TestBackupRejectsWeakPassphrase(t *testing.T) {
	h := newTestServer(t)
	code, out := doJSON(t, h, "POST", "/api/v1/upgrade/backup", adminToken(),
		map[string]any{"passphrase": "123"})
	if code != http.StatusBadRequest {
		t.Fatalf("短口令应 400，实际 %d %v", code, out)
	}
}

// 备份必须真的含数据库。
//
// 回归背景：backupSources 最初从 BAIDI_DB 环境变量**重新推导**库路径，而不是问
// 真正在用的那个 store。两处推导一旦不一致（运维改用别的方式指定路径、或进程 cwd
// 变了），备份会静默不含数据库，而管理员以为自己有一份完整备份——这类错误
// 只在真正需要恢复的那天才暴露。现在库路径来自 store.DBPath()，且找不到就直接失败。
func TestBackupContainsDatabase(t *testing.T) {
	h := newTestServer(t)
	req := httptest.NewRequest("POST", "/api/v1/upgrade/backup",
		strings.NewReader(`{"passphrase":"correct-horse-battery","note":"回归用"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("备份应成功，实际 %d %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("应作为附件下载：%q", cd)
	}
	meta, files, err := upgrade.OpenBackup(rec.Body.Bytes(), "correct-horse-battery")
	if err != nil {
		t.Fatalf("导出的备份应能被同一口令解开：%v", err)
	}
	if meta.Version != Version {
		t.Errorf("备份头部应记当时的控制面版本：%q", meta.Version)
	}
	db, ok := files["baidi.db"]
	if !ok || len(db) == 0 {
		t.Fatalf("备份里必须含数据库，实际归档内容：%v", keysOf(files))
	}
	// SQLite 文件头是固定的魔数——确认装进去的确实是库文件而不是空壳
	if !bytes.HasPrefix(db, []byte("SQLite format 3")) {
		t.Errorf("归档里的 baidi.db 不像 SQLite 文件（前 16 字节：%q）", db[:min(16, len(db))])
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestBackupContainsAuditChainKeyAndSigningKeys 备份必须含审计链密钥与**三把**签名私钥。
//
// 回归背景（温备落地时发现）：
//   - 审计链 HMAC 密钥原先按 `os.Getenv("BAIDI_AUDIT_HMAC_KEY_FILE")` 收集，而该变量
//     **默认为空**（默认路径由 OpenSQLite 按库文件目录推导），于是标准部署导出的备份里
//     根本没有它。恢复后 control 重新生成一把新的 → **全链校验永久失败**：
//     审计数据都在、每一条都验不过，且只在有人点「审计链校验」的那天才发现。
//   - BAIDI_JWT_WEB_KEY 那把（七层 Web 代理票据）整个漏掉了。恢复后 control 重生成，
//     而各网关 L7 监听装的还是旧的 web.pub → 所有 B/S 应用点开都验不过票，
//     而隧道路径一切正常（最难往"备份缺了个文件"上想的一种失效）。
//
//   - **本轮（wave9）**：上面那次修复只补齐了"少列哪几项"，判据仍是
//     `os.Getenv("BAIDI_JWT_*_KEY")` 与 `os.Getenv("BAIDI_PKI_DIR")`——而这四项在
//     config 里**都有非空默认值**（jwt-ed25519{,-knock,-web}.pem / pki）。标准部署
//     根本不设那些环境变量，于是四项材料在 add() 里因空路径被静默跳过，
//     备份照样"成功"、备机校验（解得开 + 含 baidi.db）照样通过。
//     ★而这条用例当时是靠 `t.Setenv` 设上环境变量才通过的——它证明的是
//     「设了环境变量时收得到」，恰恰守不住真实部署那种不设的形态，
//     给了一种虚假的安全感。现在改成：**一个环境变量都不设**，用真实装载的
//     Keys/CA（它们各自记住自己实际装载自哪里），与 store.AuditKeyPath() 同构。
//
// 现在：库/审计密钥/三把签名私钥/内部 CA，一律问**真正在用它们的那个对象**要路径。
func TestBackupContainsAuditChainKeyAndSigningKeys(t *testing.T) {
	dir := t.TempDir()
	// ★一个环境变量都不设——这正是标准部署的形态，也是旧判据失效的地方。
	for _, k := range []string{
		"BAIDI_PKI_DIR", "BAIDI_JWT_KEY", "BAIDI_JWT_KNOCK_KEY", "BAIDI_JWT_WEB_KEY",
		"BAIDI_AUDIT_HMAC_KEY_FILE",
	} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	// 三把私钥落在真实路径上；LoadOrCreateKeys 会记住它们（auth.Keys.Paths()）。
	realKeys, err := auth.LoadOrCreateKeys(
		filepath.Join(dir, "jwt-ed25519.pem"),
		filepath.Join(dir, "jwt-ed25519-knock.pem"),
		filepath.Join(dir, "jwt-ed25519-web.pem"), testSecret, true)
	if err != nil {
		t.Fatalf("生成签名密钥: %v", err)
	}
	ca, err := pki.LoadOrCreate(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatalf("生成内部 CA: %v", err)
	}
	st, err := store.OpenSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, realKeys, "test", t.TempDir(), nil, ca, false)
	h := auth.Middleware(realKeys, s.IsOpen)(s.Routes())

	req := httptest.NewRequest("POST", "/api/v1/upgrade/backup",
		strings.NewReader(`{"passphrase":"correct-horse-battery"}`))
	req.Header.Set("Authorization", "Bearer "+realKeys.Sign(auth.Claims{
		Sub: "admin", Role: "admin", Name: "admin"}, tokenTTL))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("备份应成功，实际 %d %s", rec.Code, rec.Body.String())
	}
	_, files, err := upgrade.OpenBackup(rec.Body.Bytes(), "correct-horse-battery")
	if err != nil {
		t.Fatalf("解开备份: %v", err)
	}
	for _, want := range []string{
		"baidi.db", "audit-hmac.key",
		"jwt-ed25519.pem", "jwt-ed25519.pem.pub",
		"jwt-ed25519-knock.pem", "jwt-ed25519-knock.pem.pub",
		"jwt-ed25519-web.pem", "jwt-ed25519-web.pem.pub",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("备份里缺 %s（恢复出来的系统会以一种没人看得出的方式坏掉）；实际：%v",
				want, keysOf(files))
		}
	}
	// 内部 CA 整个目录：丢了就签不出网关 mTLS 证书、也验不了已签发的那些——
	// 恢复之后网关全部连不上控制面，而库、令牌、页面一切正常。
	var hasCA bool
	for n := range files {
		if strings.HasPrefix(n, "pki/") {
			hasCA = true
		}
	}
	if !hasCA {
		t.Errorf("备份里缺内部 CA 目录（pki/）；实际：%v", keysOf(files))
	}
}

// ★备份导出要 PermSystem ∩ PermAdmins（实际只有 root）。
//
// 这份备份就是温备端点吐出来的那一份：CA 私钥 + 三把签名私钥 + 审计链密钥 + 整个库，
// 口令还由导出者自己指定。单 PermSystem 时三权分立有一条直路可绕：系统管理员导出备份
// → 解出 BAIDI_JWT_KEY → 自签一张 Name=某 root 的会话令牌 → 角色按账号现算，直接全权
// （含他本不该有的 PermAudit）。「能拿走全部信任材料」等价于「能造任意管理员」。
func TestBackupRequiresSystemAndAdminsPerm(t *testing.T) {
	h := newTestServer(t)
	sysTok := makeAdmin(t, h, "sys.backup", "system")
	body := map[string]any{"passphrase": "correct-horse-battery"}

	code, out := doJSON(t, h, "POST", "/api/v1/upgrade/backup", sysTok, body)
	if code != http.StatusForbidden {
		t.Fatalf("★只有 system 权的管理员不得导出备份（等于能自签任意管理员），得 %d %v", code, out)
	}
	// 对照：超管可以（否则上面的 403 可能只是把所有人都挡住了）
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/upgrade/backup",
		strings.NewReader(`{"passphrase":"correct-horse-battery"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken())
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("超管应能导出备份，得 %d %s", rec.Code, rec.Body.String())
	}
	// 头部只读端点仍是单 system 权（它只解析上传文件的明文头，不产出任何材料）
	if code, _ := doJSON(t, h, "POST", "/api/v1/upgrade/backup/inspect", sysTok, nil); code == http.StatusForbidden {
		t.Fatal("备份头部预览不该被两权闸误伤")
	}
}

// ★备份里必须有**刚刚提交**的那条数据，而不是"上一次 checkpoint 为止"的库。
//
// 库跑在 WAL 模式（store/sqlite.go 的 DSN），提交只落 baidi.db-wal，主库文件要等
// 攒够约 4MB WAL 才被 checkpoint 写回；连接池长期留着空闲连接，也不会发生
// 「关连接顺带 checkpoint」。退回旧实现（直接 os.ReadFile 主库文件、且不带 -wal）
// 这条用例会红得非常彻底——归档里那个 baidi.db 连表都可能没有。
//
// 而它的现网形态是完全静默的：备份解得开、含 baidi.db，备机 VerifyBackup 通过、
// standby_nodes 推进、页面显示「同步新鲜 · RPO = 10 分钟」，真实 RPO 是
// 「距上次 checkpoint 多久」——没有上界，只在切换那天暴露。
func TestBackupCapturesCommittedWALWrites(t *testing.T) {
	st := openTestSQLite(t)
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	// 一条刚刚提交、几乎必定还躺在 WAL 里的写入
	const marker = "wal-canary-resource"
	if code, out := doJSON(t, h, "POST", "/api/v1/resources", adminToken(), map[string]any{
		"id": marker, "name": "WAL 金丝雀", "backend": "127.0.0.1:9",
	}); code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("前置条件：建资源应成功，得 %d %v", code, out)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/upgrade/backup",
		strings.NewReader(`{"passphrase":"correct-horse-battery"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken())
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("备份应成功，得 %d %s", rec.Code, rec.Body.String())
	}
	_, files, err := upgrade.OpenBackup(rec.Body.Bytes(), "correct-horse-battery")
	if err != nil {
		t.Fatalf("备份应能解开：%v", err)
	}
	db := files["baidi.db"]
	if len(db) == 0 {
		t.Fatalf("备份里必须含数据库，归档内容：%v", keysOf(files))
	}
	// 归档里的库**不该**带 -wal 边车（VACUUM INTO 出来的快照本身就是完整的）；
	// 恢复脚本会 rm -f baidi.db-wal，靠边车补数据的话那一步就把数据删了。
	for _, n := range keysOf(files) {
		if strings.HasSuffix(n, "-wal") || strings.HasSuffix(n, "-shm") {
			t.Fatalf("归档不该带 WAL 边车（恢复脚本会删掉它）：%s", n)
		}
	}

	// 把归档里那份库落盘、直接用 SQL 查——不经任何白帝代码，避免"自己验自己"
	p := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(p, db, 0o600); err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("sqlite", "file:"+p+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var n int
	if err := conn.QueryRow(`SELECT count(*) FROM resources WHERE id = ?`, marker).Scan(&n); err != nil {
		t.Fatalf("★归档里的库读不出 resources 表（多半是拷了尚未 checkpoint 的主库文件）：%v", err)
	}
	if n != 1 {
		t.Fatalf("★刚提交的那条数据不在备份里（真实 RPO = 距上次 checkpoint 多久，无上界）")
	}
}
