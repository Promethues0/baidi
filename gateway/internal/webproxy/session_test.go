package webproxy

import (
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewSessionKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := testKey(t)
	in := Session{User: "zhangsan", Role: "user", Res: "oa", Exp: time.Now().Add(time.Minute).Unix()}
	got, err := Open(k, Seal(k, in))
	if err != nil {
		t.Fatalf("往返应成功: %v", err)
	}
	if got != in {
		t.Fatalf("往返后内容变了: %+v vs %+v", got, in)
	}
}

// 篡改任一段、换一把密钥、过期——三条都必须拒。会话 Cookie 是攻击者
// 完全可控的输入，任何"部分可信"都等于可伪造。
func TestOpenRejectsTamperedOrExpired(t *testing.T) {
	k := testKey(t)
	good := Seal(k, Session{User: "u", Role: "user", Res: "oa", Exp: time.Now().Add(time.Minute).Unix()})
	payload, sig, _ := strings.Cut(good, ".")

	cases := map[string]string{
		"改载荷":       "eyJ1IjoiYWRtaW4iLCJyIjoiYWRtaW4iLCJzIjoib2EiLCJlIjo5OTk5OTk5OTk5fQ." + sig,
		"改签名":       payload + ".AAAA",
		"少一段":       payload,
		"空串":        "",
		"载荷非base64": "!!!." + sig,
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(k, tok); err == nil {
				t.Fatalf("%s 必须被拒", name)
			}
		})
	}
	if _, err := Open(testKey(t), good); err == nil {
		t.Fatal("换一把密钥必须验不过（网关重启即所有 Web 会话失效）")
	}
	expired := Seal(k, Session{User: "u", Role: "user", Res: "oa", Exp: time.Now().Add(-time.Second).Unix()})
	if _, err := Open(k, expired); err == nil {
		t.Fatal("过期会话必须被拒")
	}
}

func TestSplitAppPath(t *testing.T) {
	cases := []struct {
		in       string
		res, out string
		ok       bool
	}{
		{"/app/oa/", "oa", "/", true},
		{"/app/oa", "oa", "/", true},
		{"/app/oa/x/y?z", "oa", "/x/y?z", true},
		{"/app//x", "", "", false},
		{"/app/", "", "", false},
		{"/appoa/x", "", "", false},
		{"/static/a.css", "", "", false},
		// 带路径分隔/分号的 id 会把 Cookie 的 Path 属性串到别处去，一律拒
		{"/app/../etc/x", "", "", false},
		{"/app/a;b/x", "", "", false},
	}
	for _, c := range cases {
		res, out, ok := SplitAppPath(c.in)
		if ok != c.ok || (ok && (res != c.res || out != c.out)) {
			t.Fatalf("%q → (%q,%q,%v)，期望 (%q,%q,%v)", c.in, res, out, ok, c.res, c.out, c.ok)
		}
	}
}

func TestValidResourceID(t *testing.T) {
	for _, ok := range []string{"oa", "finance-01", "a_b.c", strings.Repeat("a", 64)} {
		if !ValidResourceID(ok) {
			t.Fatalf("%q 应合法", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a b", "a;b", "a%2f", strings.Repeat("a", 65)} {
		if ValidResourceID(bad) {
			t.Fatalf("%q 应非法（它会污染 URL 前缀与 Cookie Path）", bad)
		}
	}
}
