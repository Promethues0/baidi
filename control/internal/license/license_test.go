package license

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func manifest(expires string) []byte {
	b, _ := json.Marshal(Manifest{Product: "baidi", Licensee: "测试客户",
		IssuedAt: "2026-01-01", ExpiresAt: expires, MaxUsers: 10, MaxGateways: 2})
	return b
}

// signedBlob 签发并按落盘形态（json.Marshal）序列化。
func signedBlob(t *testing.T, manifestRaw []byte, priv ed25519.PrivateKey) []byte {
	t.Helper()
	f, err := Sign(manifestRaw, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, _ := json.Marshal(f)
	return raw
}

var now = time.Date(2026, 8, 13, 12, 0, 0, 0, time.Local)

func TestSignVerifyRoundtrip(t *testing.T) {
	pub, priv := keypair(t)
	st := Evaluate(signedBlob(t, manifest("2027-01-01"), priv), []ed25519.PublicKey{pub}, now)
	if st.Mode != ModeLicensed {
		t.Fatalf("应 licensed，实得 %s（%s）", st.Mode, st.Reason)
	}
	if st.Manifest.MaxUsers != 10 || st.Manifest.Licensee != "测试客户" {
		t.Errorf("manifest 字段没带出来：%+v", st.Manifest)
	}
}

// ★回归：manifest 输入带缩进时，签完序列化再验必须仍通过。
//
// 踩过的原坑：Sign 直接对带缩进的原文签名，而 encoding/json 序列化内嵌 RawMessage
// 时会重排空白（MarshalIndent 整段重新缩进）——落盘字节 ≠ 签名字节，
// 刚签出来的 license 自己都验不过（CLI 用 -example 的缩进输出签发时当场复现）。
// Sign 现在先 json.Compact 再签；这条用例把"缩进输入"这条路钉死。
func TestSignAcceptsIndentedManifest(t *testing.T) {
	pub, priv := keypair(t)
	indented, _ := json.MarshalIndent(Manifest{Product: "baidi", Licensee: "缩进客户",
		IssuedAt: "2026-01-01", ExpiresAt: "2027-01-01", MaxUsers: 5}, "", "  ")
	st := Evaluate(signedBlob(t, indented, priv), []ed25519.PublicKey{pub}, now)
	if st.Mode != ModeLicensed {
		t.Fatalf("缩进 manifest 签出的 license 应有效，实得 %s（%s）", st.Mode, st.Reason)
	}
	// 再过一遍 MarshalIndent（比如有人把导入的 blob pretty-print 后存回）也得仍然有效：
	// MarshalIndent 会连内嵌 RawMessage 一起重排空白，所以签名定义在 compact 形上、
	// Verify 先 compact 再验——空白不进签名语义，键序与内容仍逐字节进。
	var f File
	if err := json.Unmarshal(signedBlob(t, indented, priv), &f); err != nil {
		t.Fatal(err)
	}
	pretty, _ := json.MarshalIndent(f, "", "  ")
	if st := Evaluate(pretty, []ed25519.PublicKey{pub}, now); st.Mode != ModeLicensed {
		t.Fatalf("pretty-print 后的 license 应仍有效，实得 %s（%s）", st.Mode, st.Reason)
	}
}

func TestTamperedManifestRejected(t *testing.T) {
	pub, priv := keypair(t)
	f, err := Sign(manifest("2027-01-01"), priv)
	if err != nil {
		t.Fatal(err)
	}
	// 篡改容量：把 10 改成 9999。验签对象是原始字节，任何一字节变动都得翻脸。
	f.Manifest = json.RawMessage(strings.Replace(string(f.Manifest), `"maxUsers":10`, `"maxUsers":9999`, 1))
	raw, _ := json.Marshal(f)
	if st := Evaluate(raw, []ed25519.PublicKey{pub}, now); st.Mode != ModeInvalid {
		t.Fatalf("篡改后的 license 应 invalid，实得 %s", st.Mode)
	}
}

func TestNoKeysIsInvalidNotTrusted(t *testing.T) {
	_, priv := keypair(t)
	blob := signedBlob(t, manifest("2027-01-01"), priv)
	// ★没配公钥必须 invalid（fail-closed），绝不能"跳过验签当有效"——
	// 那会让"把控制面的 BAIDI_LICENSE_PUBKEY 删掉"成为伪造 license 的完整攻击路径。
	if st := Evaluate(blob, nil, now); st.Mode != ModeInvalid {
		t.Fatalf("无公钥应 invalid，实得 %s", st.Mode)
	}
}

func TestExpiryIsInclusive(t *testing.T) {
	pub, priv := keypair(t)
	keys := []ed25519.PublicKey{pub}
	// 到期日当天仍有效（含当日）。
	if st := Evaluate(signedBlob(t, manifest("2026-08-13"), priv), keys, now); st.Mode != ModeLicensed {
		t.Errorf("到期日当天应仍有效，实得 %s（%s）", st.Mode, st.Reason)
	}
	// 次日过期。
	if st := Evaluate(signedBlob(t, manifest("2026-08-12"), priv), keys, now); st.Mode != ModeExpired {
		t.Errorf("昨天到期应 expired，实得 %s", st.Mode)
	}
}

func TestDemoAndGarbage(t *testing.T) {
	if st := Evaluate(nil, nil, now); st.Mode != ModeDemo {
		t.Errorf("空 blob 应 demo，实得 %s", st.Mode)
	}
	if st := Evaluate([]byte("not json"), nil, now); st.Mode != ModeInvalid {
		t.Errorf("垃圾 blob 应 invalid，实得 %s", st.Mode)
	}
	pub, priv := keypair(t)
	// product 不对：结构就该拒，轮不到验签。
	b, _ := json.Marshal(Manifest{Product: "zhulong", ExpiresAt: "2027-01-01"})
	if st := Evaluate(signedBlob(t, b, priv), []ed25519.PublicKey{pub}, now); st.Mode != ModeInvalid {
		t.Errorf("别家产品的 license 应 invalid，实得 %s", st.Mode)
	}
}

// 密钥轮换：多把公钥任一命中即通过。
func TestKeyRotation(t *testing.T) {
	oldPub, oldPriv := keypair(t)
	newPub, _ := keypair(t)
	blob := signedBlob(t, manifest("2027-01-01"), oldPriv)
	if st := Evaluate(blob, []ed25519.PublicKey{newPub, oldPub}, now); st.Mode != ModeLicensed {
		t.Fatalf("旧钥签的 license 在轮换期（新旧并存）应仍有效，实得 %s", st.Mode)
	}
	if st := Evaluate(blob, []ed25519.PublicKey{newPub}, now); st.Mode != ModeInvalid {
		t.Fatalf("旧钥已下线后应 invalid，实得 %s", st.Mode)
	}
}
