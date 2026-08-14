// Package totp 是 RFC 6238 TOTP 的自研实现（wave7 行动 4：FR-AUTH-03/12/16）。
//
// 为什么自研而不引库：算法本体是 RFC 4226 的一个 HMAC-SHA1 截断 + RFC 6238 的
// 时间计数器，纯标准库百来行写完，且有官方测试向量可以钉死正确性——与 IKEv2
// 自研同一条理由（协议小、向量全）；与 LDAP 刻意不自研（互通面大）方向相反。
//
// 参数钉死为业界事实标准：SHA1 / 6 位 / 30 秒步长。Google Authenticator、
// 微软 Authenticator、1Password 等对 otpauth URI 里的 algorithm/digits/period
// 参数支持参差不齐（部分实现直接忽略），钉死默认值反而是互通性最好的选择。
// SHA1 在 HMAC 用法下不受碰撞攻击影响（HMAC 的安全性不依赖压缩函数抗碰撞）。
//
// ★防重放不在本包：Verify 返回命中的时间计数器，"同一计数器的码只能用一次"
// 由调用方（api 层）用持久化的 last_counter 保证——本包是纯函数，没有状态。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Period 时间步长（秒）。
	Period = 30
	// Digits 验证码位数。
	Digits = 6
	// Skew 允许的时钟漂移步数（前后各 1 步 = ±30s）。
	// 更宽的窗口线性放大在线猜测面；更窄则手机时钟稍偏就登不进。1 是业界通值。
	Skew = 1
	// secretLen 密钥字节数（160 位，RFC 4226 推荐的最小值即 160 位）。
	secretLen = 20
)

// b32 无填充大写 base32——authenticator App 的密钥输入框普遍不认 '='。
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret 生成一把新密钥（base32 编码，无填充）。
func GenerateSecret() (string, error) {
	raw := make([]byte, secretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return b32.EncodeToString(raw), nil
}

// decodeSecret 解出密钥原文。宽容大小写与空格/短横（手输密钥的常见形态），
// 但不宽容其他错误——解不出就是配置坏了，静默容错只会把错误推迟到永远对不上码。
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(secret))
	raw, err := b32.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("totp: 密钥不是有效的 base32：%w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("totp: 密钥为空")
	}
	return raw, nil
}

// hotpCode RFC 4226 HOTP：HMAC-SHA1(key, counter) → 动态截断 → 取模。
// digits 参数化只为让 RFC 6238 附录 B 的 8 位官方向量测得到，公开 API 恒 6 位。
func hotpCode(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// counterAt 时刻 t 对应的时间计数器。
func counterAt(t time.Time) uint64 { return uint64(t.Unix() / Period) }

// Code 时刻 t 的验证码（注册确认页回显核对、测试用）。
func Code(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hotpCode(key, counterAt(t), Digits), nil
}

// Verify 校验验证码，允许 ±Skew 步时钟漂移。
// 命中时返回 (命中的计数器, true)——调用方必须用它做防重放
// （只接受 counter > 已用过的最大 counter，见 store.ConsumeTotpCounter）。
func Verify(secret, code string, t time.Time) (uint64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false
	}
	center := counterAt(t)
	for d := -Skew; d <= Skew; d++ {
		c := int64(center) + int64(d)
		if c < 0 {
			continue
		}
		want := hotpCode(key, uint64(c), Digits)
		// hmac.Equal 常数时间比较：验证码只有 10^6 个，别再送出一个时间侧信道。
		if hmac.Equal([]byte(want), []byte(code)) {
			return uint64(c), true
		}
	}
	return 0, false
}

// ProvisioningURI 生成 otpauth:// 注册 URI（authenticator App 扫码/点击导入用）。
// label 形如 issuer:account；issuer 参数重复携带是 Google 格式的兼容要求。
func ProvisioningURI(issuer, account, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(Period))
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + q.Encode()
}
