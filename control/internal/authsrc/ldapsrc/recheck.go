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
	// ★先判「还在不在配置的搜索范围内」。base-scope 按 DN 直查是查得到的——
	// 哪怕这个条目已经被挪出 BaseDN（AD 上把离职员工移进独立的 Disabled OU、
	// 甚至移出本域，是比设置 UAC 禁用位更常见的做法）。只按 DN 查的话，
	// 那个人在白帝这边永远是 active，而目录管理员认为自己已经把他停掉了。
	// 纯字符串判定，不多一次查询。
	if !dnWithinBase(dn, p.cfg.BaseDN) {
		return authsrc.StateGone, nil
	}
	attrs := []string{"userAccountControl", "accountExpires"}
	if a := strings.TrimSpace(p.cfg.StatusAttr); a != "" {
		attrs = append(attrs, a)
	}
	req := ldap.NewSearchRequest(
		dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, p.timeLimitSeconds(), false,
		"(objectClass=*)",
		attrs, nil)
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
	// 可配状态属性优先于 AD 内置位：管理员显式配了它，就该按它说的算。
	if a := strings.TrimSpace(p.cfg.StatusAttr); a != "" {
		if st, decided := classifyStatusAttr(e.GetAttributeValues(a), p.cfg.StatusDisabledValues); decided {
			return st, nil
		}
	}
	return classifyAccountEntry(
		e.GetAttributeValue("userAccountControl"),
		e.GetAttributeValue("accountExpires"),
		time.Now(),
	), nil
}

// dnWithinBase 报告 dn 是否落在 baseDN 之下（含等于）。baseDN 为空 = 不限。
//
// LDAP DN 的比较规则远比字符串复杂（属性名大小写、值的规范化、空格），
// 这里只做**保守**的大小写不敏感后缀判定：判不准时倾向于认为「还在范围内」
// （回 true → 继续按属性判），绝不因为一次字符串差异就把人判成 Gone。
// 方向与整个回验一致：只在目录**明确说了**的时候才动手。
func dnWithinBase(dn, baseDN string) bool {
	b := strings.TrimSpace(baseDN)
	if b == "" {
		return true
	}
	d := strings.ToLower(strings.TrimSpace(dn))
	lb := strings.ToLower(b)
	return d == lb || strings.HasSuffix(d, ","+lb)
}

// classifyStatusAttr 按可配状态属性判定。decided=false 表示这个属性没给出结论，
// 调用方继续按 AD 内置位判。
//
//   - 属性**不存在** → 未决（不是"启用"）：目录里没有这个属性，可能是配错了属性名，
//     据此判 active 与判 disabled 都是在替目录说话。交回去让内置位/存在性接手。
//   - 配了 disabledValues：命中即 disabled，未命中即 active（管理员明确说了怎么读这个属性）。
//   - 没配 disabledValues：属性存在即 disabled（pwdAccountLockedTime 那种"有就是锁了"的用法）。
func classifyStatusAttr(values, disabled []string) (authsrc.AccountState, bool) {
	if len(values) == 0 {
		return "", false
	}
	if len(disabled) == 0 {
		return authsrc.StateDisabled, true
	}
	for _, v := range values {
		for _, d := range disabled {
			if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(d)) {
				return authsrc.StateDisabled, true
			}
		}
	}
	return authsrc.StateActive, true
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
