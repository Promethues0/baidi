package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/upgrade"
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
// 现在：库/审计密钥问 store 要真正在用的那份，三把签名私钥逐一收集。
func TestBackupContainsAuditChainKeyAndSigningKeys(t *testing.T) {
	dir := t.TempDir()
	// 三把签名密钥各造一份（内容不重要，测的是"有没有被收进备份"）
	for _, k := range []struct{ env, name string }{
		{"BAIDI_JWT_KEY", "jwt-ed25519.pem"},
		{"BAIDI_JWT_KNOCK_KEY", "jwt-ed25519-knock.pem"},
		{"BAIDI_JWT_WEB_KEY", "jwt-ed25519-web.pem"},
	} {
		p := filepath.Join(dir, k.name)
		if err := os.WriteFile(p, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p+".pub", []byte("-----BEGIN PUBLIC KEY-----\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv(k.env, p)
	}
	// ★刻意**不设** BAIDI_AUDIT_HMAC_KEY_FILE：这正是出问题的那种标准部署。
	st, err := store.OpenSQLite(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, false)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	req := httptest.NewRequest("POST", "/api/v1/upgrade/backup",
		strings.NewReader(`{"passphrase":"correct-horse-battery"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken())
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
		"jwt-ed25519.pem", "jwt-ed25519-knock.pem", "jwt-ed25519-web.pem",
		"jwt-ed25519-web.pem.pub",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("备份里缺 %s（恢复出来的系统会以一种没人看得出的方式坏掉）；实际：%v",
				want, keysOf(files))
		}
	}
}
