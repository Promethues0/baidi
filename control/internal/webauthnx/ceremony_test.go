package webauthnx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"baidi.dev/control/internal/store"
)

// 软件认证器：按 WebAuthn 规范构造 attestation / assertion，端到端验证服务端校验链
// （challenge 绑定、origin、rpIdHash、断言签名、计数器）确实生效——而不是"库调通了就算数"。

const (
	testRPID   = "localhost"
	testOrigin = "http://localhost:5193"
)

type softAuthenticator struct {
	key       *ecdsa.PrivateKey
	credID    []byte
	signCount uint32
}

func newSoftAuthenticator(t *testing.T) *softAuthenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softAuthenticator{key: k, credID: id, signCount: 0}
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// coseKey 按 COSE_Key(ES256) 编码公钥。
func (a *softAuthenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
	// map: 1(kty)=2(EC2), 3(alg)=-7(ES256), -1(crv)=1(P-256), -2=x, -3=y
	m := map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y}
	b, err := cbor.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// authData 构造认证器数据。flags: UP|UV(|AT 当带凭据数据)。
func (a *softAuthenticator) authData(t *testing.T, withCred bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(testRPID))
	flags := byte(0x01 | 0x04) // UP | UV
	if withCred {
		flags |= 0x40 // AT
	}
	out := append([]byte{}, rpIDHash[:]...)
	out = append(out, flags)
	cnt := make([]byte, 4)
	binary.BigEndian.PutUint32(cnt, a.signCount)
	out = append(out, cnt...)
	if withCred {
		out = append(out, make([]byte, 16)...) // AAGUID 全零
		idLen := make([]byte, 2)
		binary.BigEndian.PutUint16(idLen, uint16(len(a.credID)))
		out = append(out, idLen...)
		out = append(out, a.credID...)
		out = append(out, a.coseKey(t)...)
	}
	return out
}

func clientDataJSON(t *testing.T, typ, challenge, origin string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// attestationResponse 生成注册响应体（fmt=none）。
func (a *softAuthenticator) attestationResponse(t *testing.T, challenge, origin string) []byte {
	t.Helper()
	cd := clientDataJSON(t, "webauthn.create", challenge, origin)
	att := map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(t, true)}
	ao, err := cbor.Marshal(att)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u(cd), "attestationObject": b64u(ao)},
	})
	return body
}

// assertionResponse 生成断言响应体（用私钥对 authData||SHA256(clientDataJSON) 签名）。
func (a *softAuthenticator) assertionResponse(t *testing.T, challenge, origin string) []byte {
	t.Helper()
	a.signCount++
	cd := clientDataJSON(t, "webauthn.get", challenge, origin)
	ad := a.authData(t, false)
	sum := sha256.Sum256(cd)
	signed := append(append([]byte{}, ad...), sum[:]...)
	digest := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	asn1Sig := encodeASN1Sig(r, s)
	body, _ := json.Marshal(map[string]any{
		"id": b64u(a.credID), "rawId": b64u(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(asn1Sig),
		},
	})
	return body
}

// encodeASN1Sig 把 (r,s) 编成 ASN.1 DER（WebAuthn ES256 签名格式）。
func encodeASN1Sig(r, s *big.Int) []byte {
	enc := func(i *big.Int) []byte {
		b := i.Bytes()
		if len(b) > 0 && b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	rb, sb := enc(r), enc(s)
	body := append(rb, sb...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

func newTestRP(t *testing.T) *RP {
	t.Helper()
	rp, err := New(testRPID, testOrigin, "白帝测试")
	if err != nil || rp == nil {
		t.Fatalf("构造 RP 失败: %v", err)
	}
	return rp
}

func req(body []byte) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// 端到端：注册 → 落库 → 用注册出的凭据断言，全链路校验通过。
func TestCeremonyRegisterThenLogin(t *testing.T) {
	rp := newTestRP(t)
	auth := newSoftAuthenticator(t)

	u, err := NewUser("u-1", "li.fang", "李芳", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, sess, err := rp.BeginRegistration(u)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	cred, err := rp.FinishRegistration(u, *sess, req(auth.attestationResponse(t, ChallengeOf(sess), testOrigin)))
	if err != nil {
		t.Fatalf("注册应通过: %v", err)
	}
	if cred.CredentialID != b64u(auth.credID) || cred.PublicKey == "" {
		t.Fatalf("落库凭据异常: %+v", cred)
	}

	// 用刚注册的凭据做断言
	cred.Account, cred.UserID = "li.fang", "u-1"
	u2, err := NewUser("u-1", "li.fang", "李芳", []store.WebauthnCredential{cred})
	if err != nil {
		t.Fatal(err)
	}
	_, lsess, err := rp.BeginLogin(u2)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	gotID, newCount, err := rp.FinishLogin(u2, *lsess, req(auth.assertionResponse(t, ChallengeOf(lsess), testOrigin)))
	if err != nil {
		t.Fatalf("断言应通过: %v", err)
	}
	if gotID != cred.CredentialID {
		t.Fatalf("断言凭据 id 不符: %s vs %s", gotID, cred.CredentialID)
	}
	if newCount != auth.signCount {
		t.Fatalf("计数器应回传 %d, 得 %d", auth.signCount, newCount)
	}
}

// ★origin 不匹配必须被拒——这是 WebAuthn 抗钓鱼的核心。
func TestCeremonyRejectsWrongOrigin(t *testing.T) {
	rp := newTestRP(t)
	auth := newSoftAuthenticator(t)
	u, _ := NewUser("u-1", "li.fang", "李芳", nil)
	_, sess, _ := rp.BeginRegistration(u)
	_, err := rp.FinishRegistration(u, *sess, req(auth.attestationResponse(t, ChallengeOf(sess), "https://evil.example.com")))
	if err == nil {
		t.Fatal("钓鱼站 origin 必须被拒")
	}
}

// ★challenge 不匹配必须被拒（防重放/伪造）。
func TestCeremonyRejectsWrongChallenge(t *testing.T) {
	rp := newTestRP(t)
	auth := newSoftAuthenticator(t)
	u, _ := NewUser("u-1", "li.fang", "李芳", nil)
	_, sess, _ := rp.BeginRegistration(u)
	_, err := rp.FinishRegistration(u, *sess, req(auth.attestationResponse(t, b64u([]byte("not-the-challenge-000000000000")), testOrigin)))
	if err == nil {
		t.Fatal("错误 challenge 必须被拒")
	}
}

// ★用别的密钥签名（凭据被冒用）必须被拒。
func TestCeremonyRejectsWrongKey(t *testing.T) {
	rp := newTestRP(t)
	real := newSoftAuthenticator(t)
	u, _ := NewUser("u-1", "li.fang", "李芳", nil)
	_, sess, _ := rp.BeginRegistration(u)
	cred, err := rp.FinishRegistration(u, *sess, req(real.attestationResponse(t, ChallengeOf(sess), testOrigin)))
	if err != nil {
		t.Fatal(err)
	}
	cred.Account = "li.fang"
	u2, _ := NewUser("u-1", "li.fang", "李芳", []store.WebauthnCredential{cred})
	_, lsess, _ := rp.BeginLogin(u2)

	// 攻击者用自己的密钥、但冒用真实 credentialID
	attacker := newSoftAuthenticator(t)
	attacker.credID = real.credID
	_, _, err = rp.FinishLogin(u2, *lsess, req(attacker.assertionResponse(t, ChallengeOf(lsess), testOrigin)))
	if err == nil {
		t.Fatal("错误签名密钥必须被拒")
	}
}

// 未配置 RP ID/Origin 时 New 返回 nil（上层据此回落 legacy 路径）。
func TestNewDisabledWhenUnconfigured(t *testing.T) {
	for _, c := range [][2]string{{"", ""}, {"localhost", ""}, {"", testOrigin}, {"  ", "  "}} {
		rp, err := New(c[0], c[1], "x")
		if err != nil || rp != nil {
			t.Fatalf("未配置应返回 (nil,nil): rpid=%q origin=%q rp=%v err=%v", c[0], c[1], rp, err)
		}
	}
}
