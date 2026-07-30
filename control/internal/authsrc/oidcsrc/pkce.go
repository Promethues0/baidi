package oidcsrc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// b64raw 是 OIDC/JWS 全场景唯一合法的 base64 变体：URL 安全字母表 + **无填充**。
//
// ★ 整个包里凡是 base64 都必须走它，一处用错就是一类静默失败：
//   - code_challenge 带了 '='：IdP 一律回 invalid_grant，错误描述通常只有
//     "PKCE verification failed" 甚至干脆是空的，完全指不到「多了个等号」这件事上，
//     排查时几乎必然先去怀疑 verifier 存串、会话绑定、时钟，最后才想到编码。
//   - JWS 段带了 '='：验签直接失败，同样毫无指向性。
var b64raw = base64.RawURLEncoding

// randString 生成 n 字节熵的 base64url 随机串。
func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败在现代系统上等同于系统级故障，绝不能退化成弱随机。
		// state/nonce/verifier 三者的安全性**全部**建立在不可预测上：
		// state 可预测 = 登录 CSRF 可行；nonce 可预测 = ID Token 可重放；
		// verifier 可预测 = PKCE 形同虚设。所以这里只能把错误抛出去。
		return "", fmt.Errorf("生成随机数失败：%w", err)
	}
	return b64raw.EncodeToString(b), nil
}

// NewCodeVerifier 生成 PKCE code_verifier（32 字节熵 → 43 字符，正好是 RFC 7636 的下限）。
//
// 调用方必须把它与**本次会话**绑定（存在服务端会话里，不要塞进 cookie 明文），
// 回调时原样传给 Exchange。verifier 若被第三方拿到，PKCE 的全部意义就没了。
func NewCodeVerifier() (string, error) { return randString(32) }

// NewState 生成 state（防登录 CSRF）。见 Provider.AuthURL 上的说明：
// **必须**由调用方在回调时比对，本包无从代劳（它不持有会话）。
func NewState() (string, error) { return randString(16) }

// NewNonce 生成 nonce（防 ID Token 重放）。同样必须与会话绑定并在 Exchange 时回传。
func NewNonce() (string, error) { return randString(16) }

// CodeChallengeS256 由 verifier 推导 S256 挑战：base64url(sha256(verifier))，**不带填充**。
//
// ★ 注意是对 verifier 的 **ASCII 字节**取哈希，不是先把 verifier 解成二进制再哈希。
// RFC 7636 的原文是 BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))；"先解码再哈希"
// 这个想当然的写法在自测里一路通过（两边都是自己算的），一接真 IdP 就全线 invalid_grant。
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64raw.EncodeToString(sum[:])
}

// validCodeVerifier 按 RFC 7636 校验 verifier 字符集与长度（43~128，unreserved 字符集）。
//
// 提前校验是为了把「调用方传了个空串/传了个 UUID 带横杠以外的字符」变成本地的明确错误，
// 而不是变成 IdP 那句毫无信息量的 invalid_grant。
func validCodeVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~'
		if !ok {
			return false
		}
	}
	return true
}
