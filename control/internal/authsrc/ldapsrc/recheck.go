package ldapsrc

// 外部账号状态回验（wave7 行动 3）：按 entryDN 直查目录条目，
// 把「AD 禁了号，白帝的 8h 会话还活着」这个持续验证的洞压到回验周期。

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/authsrc"
	"github.com/go-ldap/ldap/v3"
)

// adNeverExpires accountExpires 的两个"永不过期"哨兵值（0 与 int64 最大值）。
const adNeverExpires = int64(0x7FFFFFFFFFFFFFFF)

// CheckAccount 实现 authsrc.StatusChecker：Base=DN、scope=base 的单条目直查。
//
// 判据（只认目录**明确说了**的证据，见接口注释的方向说明）：
//   - 搜索回 noSuchObject(32) → StateGone；
//   - AD：userAccountControl 含 ACCOUNTDISABLE(0x2) → StateDisabled，
//     accountExpires 已过 → StateExpired；
//   - 通用 LDAP 没有标准的"禁用"属性——条目在即 active（能回验的只有存在性；
//     这不是妥协出来的宽松，是协议里真没有那个语义，装懂比不懂更糟）。
//   - 拨号/绑定/其它错误 → 包裹 ErrSourceUnavailable，调用方不得据此动手。
func (p *Provider) CheckAccount(ctx context.Context, subject string) (authsrc.AccountState, error) {
	dn := strings.TrimSpace(subject)
	if dn == "" {
		return "", fmt.Errorf("ldapsrc: 回验 subject 为空: %w", authsrc.ErrNotConfigured)
	}
	conn, err := p.dial(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	if err := p.bindService(conn); err != nil {
		return "", err
	}
	req := ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, p.timeLimitSeconds(), false,
		"(objectClass=*)",
		[]string{"userAccountControl", "accountExpires"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return authsrc.StateGone, nil
		}
		return "", fmt.Errorf("ldapsrc: 回验搜索失败: %v: %w", err, authsrc.ErrSourceUnavailable)
	}
	if len(res.Entries) == 0 {
		// 部分目录对不可见条目回空集而不是 32：同样只能解读成"不存在"。
		return authsrc.StateGone, nil
	}
	e := res.Entries[0]
	return classifyAccountEntry(
		e.GetAttributeValue("userAccountControl"),
		e.GetAttributeValue("accountExpires"),
		time.Now(),
	), nil
}

// classifyAccountEntry 按 AD 的两个状态属性判定（纯函数，供单测直击边界）。
//
//   - uac 空（通用 LDAP 没有该属性）→ active：存在性就是通用目录能给的全部证据；
//   - uac 解析不了 → active 并由调用方日志留痕——解析失败是我们的问题不是账号的问题，
//     据此禁号等于把一次格式差异放大成用户断连（方向同"源不可用不得动手"）；
//   - accountExpires：AD FILETIME（1601-01-01 起 100ns 计），0 与 int64 最大值=永不过期。
func classifyAccountEntry(uac, accountExpires string, now time.Time) authsrc.AccountState {
	if v := strings.TrimSpace(uac); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n&0x2 != 0 {
			return authsrc.StateDisabled
		}
	}
	if v := strings.TrimSpace(accountExpires); v != "" {
		if ft, err := strconv.ParseInt(v, 10, 64); err == nil && ft != 0 && ft != adNeverExpires {
			// FILETIME → Unix：先除以 10^7 换成秒，再减 1601→1970 的 11644473600 秒。
			if ft/10_000_000-11644473600 < now.Unix() {
				return authsrc.StateExpired
			}
		}
	}
	return authsrc.StateActive
}
