package api

// License 的 REST 面与两处容量执行点。判定数学在 internal/license 测；
// 这里钉的是：权限、无公钥拒导入、席位真的拦得住、换证/吊销/提权不误占席位、
// 以及 demo 模式恒不限（演示环境一个都不能被拦）。

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/license"
	"baidi.dev/control/internal/pki"
	"baidi.dev/control/internal/store"
)

// licFixture 带发行钥与 CA 的测试栈：返回 handler、发行私钥、直通 store（造异常态用）。
func licFixture(t *testing.T, withKeys bool) (http.Handler, ed25519.PrivateKey, *store.SQLiteStore) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if withKeys {
		t.Setenv("BAIDI_LICENSE_PUBKEY", base64.StdEncoding.EncodeToString(pub))
	} else {
		t.Setenv("BAIDI_LICENSE_PUBKEY", "")
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "lic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ca, err := pki.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, st, testKeys, "test", t.TempDir(), nil, ca, true)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), priv, st
}

// licBlob 签出一份 license 文件原文。
func licBlob(t *testing.T, priv ed25519.PrivateKey, expires string, maxUsers, maxGw int) []byte {
	t.Helper()
	m, _ := json.Marshal(license.Manifest{Product: "baidi", Licensee: "测试客户",
		IssuedAt: "2026-01-01", ExpiresAt: expires, MaxUsers: maxUsers, MaxGateways: maxGw})
	f, err := license.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f)
	return raw
}

// importLic 用原始字节 POST /license（doJSON 会重编码 JSON，这里必须原文直发）。
func importLic(t *testing.T, h http.Handler, token string, blob []byte) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/license", bytes.NewReader(blob))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func mkUser(t *testing.T, h http.Handler, account string) int {
	t.Helper()
	code, _ := doJSON(t, h, "POST", "/api/v1/users", adminToken(),
		map[string]any{"name": account, "account": account})
	return code
}

func TestLicenseDemoIsUnlimited(t *testing.T) {
	h, _, _ := licFixture(t, true)
	code, out := doJSON(t, h, "GET", "/api/v1/license", adminToken(), nil)
	if code != http.StatusOK || out["mode"] != "demo" {
		t.Fatalf("未导入应 demo，实得 %d %v", code, out["mode"])
	}
	if mkUser(t, h, "demo.free") != http.StatusCreated {
		t.Fatal("demo 模式建号不受限")
	}
}

func TestLicenseImportGates(t *testing.T) {
	// 无公钥：有效 license 也必须拒——"跳过验签当有效"是被禁止的方向。
	h0, priv0, _ := licFixture(t, false)
	if code, out := importLic(t, h0, adminToken(), licBlob(t, priv0, "2099-01-01", 0, 0)); code != http.StatusBadRequest {
		t.Fatalf("无公钥导入应 400，实得 %d %v", code, out)
	}

	h, priv, _ := licFixture(t, true)
	// 权限：security 管理员 403（PermSystem 端点）。
	secTok := makeAdmin(t, h, "sec.lic", "security")
	if code, _ := importLic(t, h, secTok, licBlob(t, priv, "2099-01-01", 0, 0)); code != http.StatusForbidden {
		t.Error("安全管理员导入应 403")
	}
	// 篡改拒收 + 落审计路径（不断言审计条数，行为已由 400 表达）。
	blob := bytes.Replace(licBlob(t, priv, "2099-01-01", 5, 0), []byte(`"maxUsers":5`), []byte(`"maxUsers":500`), 1)
	if code, _ := importLic(t, h, adminToken(), blob); code != http.StatusBadRequest {
		t.Error("篡改的 license 应 400")
	}
	// 已过期拒收。
	if code, _ := importLic(t, h, adminToken(), licBlob(t, priv, "2000-01-01", 0, 0)); code != http.StatusBadRequest {
		t.Error("过期 license 应拒绝导入")
	}
	// 正常导入。
	if code, out := importLic(t, h, adminToken(), licBlob(t, priv, "2099-01-01", 0, 0)); code != http.StatusOK {
		t.Fatalf("有效导入应 200，实得 %d %v", code, out)
	}
	if _, out := doJSON(t, h, "GET", "/api/v1/license", adminToken(), nil); out["mode"] != "licensed" {
		t.Fatalf("导入后应 licensed，实得 %v", out["mode"])
	}
}

func TestLicenseUserSeats(t *testing.T) {
	h, priv, _ := licFixture(t, true)
	// 先读当前席位占用，把上限设成 现有+1：留一个席位。
	_, out := doJSON(t, h, "GET", "/api/v1/license", adminToken(), nil)
	cur := int(mapOf(t, out["usage"])["users"].(float64))
	if cur <= 0 {
		t.Fatalf("种子库应有用户，实得 %d", cur)
	}
	if code, o := importLic(t, h, adminToken(), licBlob(t, priv, "2099-01-01", cur+1, 0)); code != http.StatusOK {
		t.Fatalf("导入失败 %d %v", code, o)
	}
	// 第 1 个：占掉最后一席。
	if mkUser(t, h, "seat.one") != http.StatusCreated {
		t.Fatal("还有席位时建号应成功")
	}
	// 第 2 个：409，且理由把数字说全。
	code, o := doJSON(t, h, "POST", "/api/v1/users", adminToken(),
		map[string]any{"name": "seat.two", "account": "seat.two"})
	if code != http.StatusConflict {
		t.Fatalf("席位满建号应 409，实得 %d %v", code, o)
	}
	// 新建管理员同样占席位 → 409。
	if code, _ := doJSON(t, h, "POST", "/api/v1/admins", adminToken(),
		map[string]any{"account": "seat.admin", "roleKey": "audit"}); code != http.StatusConflict {
		t.Error("席位满建管理员应 409")
	}
	// ★提权已有账号不占新席位：席位满也必须成功——这条是"提权分支早已 return"的回归。
	if code, o := doJSON(t, h, "POST", "/api/v1/admins", adminToken(),
		map[string]any{"account": "seat.one", "roleKey": "audit"}); code != http.StatusOK {
		t.Fatalf("提权已有账号不该被席位拦，实得 %d %v", code, o)
	}
}

func TestLicenseGatewaySeats(t *testing.T) {
	h, priv, _ := licFixture(t, true)
	if code, _ := importLic(t, h, adminToken(), licBlob(t, priv, "2099-01-01", 0, 1)); code != http.StatusOK {
		t.Fatal("导入失败")
	}
	issue := func(id string) (int, map[string]any) {
		return doJSON(t, h, "POST", "/api/v1/pki/gateway-certs", adminToken(), map[string]any{"gatewayId": id})
	}
	code, first := issue("gw-a")
	if code != http.StatusCreated {
		t.Fatalf("首台网关签发应成功，实得 %d %v", code, first)
	}
	if code, o := issue("gw-b"); code != http.StatusConflict {
		t.Fatalf("席位满签第二台应 409，实得 %d %v", code, o)
	}
	// 换证不占新席位。
	if code, _ := issue("gw-a"); code != http.StatusCreated {
		t.Error("同 id 换证不该被席位拦")
	}
	// 吊销释放席位后，第二台可签。
	fp := first["fingerprint"].(string)
	if code, o := doJSON(t, h, "POST", "/api/v1/pki/gateway-certs/"+fp+"/revoke", adminToken(),
		map[string]any{"reason": "退役"}); code != http.StatusOK {
		t.Fatalf("吊销失败 %d %v", code, o)
	}
	// gw-a 还有一张换证时签的未吊销证书 → 席位仍占着；把它也吊掉。
	_, list := doJSON(t, h, "GET", "/api/v1/pki/gateway-certs", adminToken(), nil)
	for _, raw := range list["certs"].([]any) {
		c := mapOf(t, raw)
		if c["gatewayId"] == "gw-a" && c["revoked"] != true {
			doJSON(t, h, "POST", "/api/v1/pki/gateway-certs/"+c["fingerprint"].(string)+"/revoke",
				adminToken(), map[string]any{"reason": "退役"})
		}
	}
	if code, o := issue("gw-b"); code != http.StatusCreated {
		t.Fatalf("吊销释放席位后应可签发，实得 %d %v", code, o)
	}
}

// 异常态 fail-closed：blob 被写坏（模拟库被篡改/公钥换错）→ invalid，建号被拒。
// ★方向必须与 demo 相反：demo 是"从未声称被许可"（不限），invalid 是"声称过但验不过"
// ——此时放开容量正是攻击者想要的方向。
func TestLicenseInvalidBlobFailsClosed(t *testing.T) {
	h, _, st := licFixture(t, true)
	if err := st.SetSetting(t.Context(), "license.blob", "corrupted-not-json"); err != nil {
		t.Fatal(err)
	}
	if _, out := doJSON(t, h, "GET", "/api/v1/license", adminToken(), nil); out["mode"] != "invalid" {
		t.Fatalf("坏 blob 应 invalid，实得 %v", out["mode"])
	}
	if code, o := doJSON(t, h, "POST", "/api/v1/users", adminToken(),
		map[string]any{"name": "x", "account": "x.invalid"}); code != http.StatusConflict {
		t.Fatalf("invalid 态建号应 409（fail-closed），实得 %d %v", code, o)
	}
}
