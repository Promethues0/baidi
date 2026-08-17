package ldapsrc

// 外部账号状态回验：判定纯函数直击边界 + gldap 真服务端走一遍协议。

import (
	"testing"
	"time"

	"baidi.dev/control/internal/authsrc"
	"errors"
)

var checkNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

// FILETIME 换算辅助：Unix 秒 → AD accountExpires。
func filetime(unix int64) string {
	return "9223372036854775807"[:0] + itoa((unix+11644473600)*10_000_000)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestClassifyAccountEntry(t *testing.T) {
	cases := []struct {
		name, uac, expires string
		want               authsrc.AccountState
	}{
		{"正常账号（AD 常见 512）", "512", "", authsrc.StateActive},
		{"禁用位（514 = 512|2）", "514", "", authsrc.StateDisabled},
		{"禁用位组合（66050 含 0x2）", "66050", "", authsrc.StateDisabled},
		{"已过期（昨天）", "512", filetime(checkNow.Add(-24 * time.Hour).Unix()), authsrc.StateExpired},
		{"未过期（明天）", "512", filetime(checkNow.Add(24 * time.Hour).Unix()), authsrc.StateActive},
		{"accountExpires=0 永不过期", "512", "0", authsrc.StateActive},
		{"accountExpires=int64max 永不过期", "512", "9223372036854775807", authsrc.StateActive},
		// ★通用 LDAP 没有 uac：存在即 active——协议里真没有"禁用"语义，装懂比不懂糟。
		{"通用 LDAP（无属性）", "", "", authsrc.StateActive},
		// ★解析不了不猜：据此禁号等于把格式差异放大成用户断连。
		{"uac 是垃圾", "not-a-number", "", authsrc.StateActive},
		// 禁用优先于过期（都成立时报更明确的那个）。
		{"禁用且过期", "514", filetime(checkNow.Add(-24 * time.Hour).Unix()), authsrc.StateDisabled},
	}
	for _, c := range cases {
		if got := classifyAccountEntry(c.uac, c.expires, checkNow); got != c.want {
			t.Errorf("%s: 得 %s 期望 %s", c.name, got, c.want)
		}
	}
}

// 真协议：直查 DN → active / disabled / gone；源不可用必须是错误而不是任何状态。
func TestCheckAccountAgainstRealServer(t *testing.T) {
	disabledDN := "uid=off,ou=people,dc=corp,dc=example"
	d := stdDir(t, func(o *dirOpts) {
		attrs := personAttrs("off", "Off User", "off@corp.example")
		attrs["userAccountControl"] = []string{"514"}
		o.entries = append(o.entries, dirEntry{DN: disabledDN, Attrs: attrs, Pass: "x"})
	})
	p := newProvider(t, cfgFor(d))

	if st, err := p.CheckAccount(ctx(t), aliceDN); err != nil || st != authsrc.StateActive {
		t.Fatalf("正常账号应 active，实得 %s / %v", st, err)
	}
	if st, err := p.CheckAccount(ctx(t), disabledDN); err != nil || st != authsrc.StateDisabled {
		t.Fatalf("uac=514 应 disabled，实得 %s / %v", st, err)
	}
	// 条目不存在（在已知 base 下）→ gone。
	if st, err := p.CheckAccount(ctx(t), "uid=ghost,ou=people,dc=corp,dc=example"); err != nil || st != authsrc.StateGone {
		t.Fatalf("不存在的条目应 gone，实得 %s / %v", st, err)
	}
	// base 都不认识 → 服务端回 noSuchObject → 同样 gone。
	if st, err := p.CheckAccount(ctx(t), "uid=x,dc=other,dc=example"); err != nil || st != authsrc.StateGone {
		t.Fatalf("未知 base 应 gone，实得 %s / %v", st, err)
	}

	// ★源不可用：连不上必须回 ErrSourceUnavailable 包裹的错误——调用方据此**不动手**。
	// 把它错报成 gone 的实现会在 AD 停机时把全部外部账号禁光。
	bad := cfgFor(d)
	bad.Port = freePort(t) // 无人监听的端口
	p2 := newProvider(t, bad)
	if st, err := p2.CheckAccount(ctx(t), aliceDN); err == nil || !errors.Is(err, authsrc.ErrSourceUnavailable) {
		t.Fatalf("源不可用必须报错且可识别，实得 %s / %v", st, err)
	}
}

// ── wave8 行动 11：可配状态属性 + 搜索范围判定 ──
//
// 被修的坏形态：回验只认 AD 的 userAccountControl 位。通用 LDAP **协议里根本没有
// "禁用"这个语义**，各家用各家的属性——于是 OpenLDAP/IDTrust 部署下回验只剩
// 「条目被删除」一种触发条件。HR 在目录里停用离职员工后，该账号的会话、敲门令牌、
// 隧道继续有效到自然过期，回验循环每轮都判 active、不留任何痕迹。

func TestClassifyStatusAttr(t *testing.T) {
	cases := []struct {
		name     string
		values   []string
		disabled []string
		want     authsrc.AccountState
		decided  bool
	}{
		// 属性不存在 → 未决。★不是 active：可能只是属性名配错了，
		// 据此判 active 与判 disabled 都是在替目录说话。
		{"属性不存在", nil, []string{"FALSE"}, "", false},
		{"IDTrust accountEnable=FALSE", []string{"FALSE"}, []string{"FALSE"}, authsrc.StateDisabled, true},
		{"IDTrust accountEnable=TRUE", []string{"TRUE"}, []string{"FALSE"}, authsrc.StateActive, true},
		{"大小写不敏感", []string{"false"}, []string{"FALSE"}, authsrc.StateDisabled, true},
		{"389DS nsAccountLock=true", []string{"true"}, []string{"true"}, authsrc.StateDisabled, true},
		{"多值命中其一", []string{"ok", "LOCKED"}, []string{"locked"}, authsrc.StateDisabled, true},
		// 只配属性名不配值：属性存在即禁用（pwdAccountLockedTime 那种用法）。
		{"存在即锁", []string{"20260101000000Z"}, nil, authsrc.StateDisabled, true},
		{"存在即锁-属性缺席", nil, nil, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, decided := classifyStatusAttr(c.values, c.disabled)
			if decided != c.decided || got != c.want {
				t.Fatalf("得到 (%q,%v)，期望 (%q,%v)", got, decided, c.want, c.decided)
			}
		})
	}
}

// TestDNWithinBase 条目被挪出 BaseDN = 判 Gone。
//
// ★AD 上把离职员工移进独立的 Disabled OU、甚至移出本域，是比设置 UAC 禁用位
// **更常见**的做法。只按 DN base-scope 直查是查得到的——那个人在白帝这边
// 永远是 active，而目录管理员认为自己已经把他停掉了。
func TestDNWithinBase(t *testing.T) {
	base := "OU=People,DC=corp,DC=example"
	cases := []struct {
		dn   string
		want bool
	}{
		{"CN=li,OU=People,DC=corp,DC=example", true},
		{"CN=li,OU=Dev,OU=People,DC=corp,DC=example", true},
		{"ou=people,dc=corp,dc=example", true},           // 大小写不敏感 + 等于自身
		{"CN=li,OU=Disabled,DC=corp,DC=example", false},  // 移出 People
		{"CN=li,OU=People,DC=other,DC=example", false},   // 移出本域
		{"CN=li,OU=NotPeople,DC=corp,DC=example", false}, // 前缀相似但不是子树
		{" CN=li,OU=People,DC=corp,DC=example ", true},   // 两侧空白
	}
	for _, c := range cases {
		if got := dnWithinBase(c.dn, base); got != c.want {
			t.Errorf("dnWithinBase(%q) = %v，期望 %v", c.dn, got, c.want)
		}
	}

	// ★分隔逗号不能省。少了它就成了裸后缀比对：某个 RDN 的**属性名**尾巴恰好
	// 与 BaseDN 首段拼上时会被误判成子树。下面这条 DN 的组件是
	// CN=li / OUdc=corp / DC=example，父链是 DC=example，**不在**
	// DC=corp,DC=example 之下；而不带逗号的 HasSuffix 会判成 true——
	// 一个本该判 Gone 的账号就此永远 active。
	if dnWithinBase("CN=li,OUdc=corp,DC=example", "DC=corp,DC=example") {
		t.Error("裸后缀比对把非子树判成了子树：分隔逗号被省了")
	}
	// ★BaseDN 为空 = 不限。判不准时倾向「还在范围内」，绝不因一次字符串差异
	// 就把人判成 Gone——方向与整个回验一致：只在目录明确说了的时候才动手。
	if !dnWithinBase("CN=x,DC=anything", "") {
		t.Error("BaseDN 为空时不该判出范围")
	}
}
