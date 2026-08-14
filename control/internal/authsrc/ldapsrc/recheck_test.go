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
