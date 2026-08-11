package webproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CookieName 会话 Cookie 名。它总是与 Path=/app/<资源id>/ 一起下发，
// 所以同一个浏览器打开多个应用时会有多份同名、不同 Path 的 Cookie，
// 浏览器按路径各送各的——这正是我们要的隔离。
const CookieName = "baidi_web"

var b64 = base64.RawURLEncoding

// Session 一条网关本地 Web 会话。
//
// ★它**不是身份凭据**：只有这台网关认它（本地随机密钥签），控制面从不接受它，
// 也换不到任何别的东西。它回答的唯一问题是"这个浏览器刚才出示过谁的、开哪个资源的票"。
type Session struct {
	User string `json:"u"`
	Role string `json:"r"`
	// Res 绑定的资源 id。逐请求比对 URL 前缀里的资源 id——Cookie 的 Path 属性
	// 已经让浏览器不会把它送到别的应用去，这一条是**服务端**的同一道判定：
	// 攻击者手工构造请求头时不受浏览器 Path 规则约束。两道缺一不可。
	Res string `json:"s"`
	Exp int64  `json:"e"` // 过期 Unix 秒
}

// NewSessionKey 生成本机 Cookie 签名密钥（32 字节）。
//
// ★每次启动重新生成、不落盘、不与任何人共享：网关重启即所有 Web 会话失效
// （用户回门户点一下重开）。这是刻意的——持久化它等于给"本机会话状态"
// 攒出一个跨重启的凭据，而它一旦泄露就能冒充任意账号访问任意已授权资源。
func NewSessionKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Seal 把会话编成 Cookie 值：<payload>.<mac>，均为 base64url。
func Seal(key []byte, s Session) string {
	body, _ := json.Marshal(s)
	p := b64.EncodeToString(body)
	return p + "." + b64.EncodeToString(macOf(key, p))
}

// Open 解出并校验会话（签名 + 有效期）。任何一步不过一律返回错误——
// 这里没有"部分可信"的中间态。
func Open(key []byte, tok string) (Session, error) {
	p, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return Session{}, errors.New("会话 Cookie 格式非法")
	}
	raw, err := b64.DecodeString(sig)
	if err != nil {
		return Session{}, errors.New("会话 Cookie 签名非法")
	}
	// 常量时间比较：Cookie 是攻击者完全可控的输入，逐字节短路比较可被计时区分。
	if !hmac.Equal(raw, macOf(key, p)) {
		return Session{}, errors.New("会话 Cookie 签名不匹配")
	}
	body, err := b64.DecodeString(p)
	if err != nil {
		return Session{}, errors.New("会话 Cookie 载荷非法")
	}
	var s Session
	if err := json.Unmarshal(body, &s); err != nil {
		return Session{}, errors.New("会话 Cookie 载荷无法解析")
	}
	if s.User == "" || s.Res == "" {
		return Session{}, errors.New("会话 Cookie 缺账号或资源绑定")
	}
	if s.Exp <= time.Now().Unix() {
		return Session{}, fmt.Errorf("会话已过期（%s）", time.Unix(s.Exp, 0).Format("15:04:05"))
	}
	return s, nil
}

func macOf(key []byte, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// AppPrefix 某资源在 L7 上的路径前缀（恒以 / 收尾，直接用作 Cookie 的 Path）。
func AppPrefix(res string) string { return "/app/" + res + "/" }

// SplitAppPath 从请求路径里拆出资源 id 与转给后端的剩余路径。
// "/app/oa/x/y" → ("oa", "/x/y")；"/app/oa" → ("oa", "/")。
// 不是 /app/ 开头、资源 id 非法、或 id 为空时 ok=false。
func SplitAppPath(p string) (res, rest string, ok bool) {
	const pre = "/app/"
	if !strings.HasPrefix(p, pre) {
		return "", "", false
	}
	tail := p[len(pre):]
	res, rest, cut := strings.Cut(tail, "/")
	if !ValidResourceID(res) {
		return "", "", false
	}
	if !cut {
		return res, "/", true
	}
	return res, "/" + rest, true
}
