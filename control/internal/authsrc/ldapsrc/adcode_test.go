package ldapsrc

import "testing"

func TestDecodeADBindFailure(t *testing.T) {
	const adDisabled = "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 533, v2580"
	const adLocked = "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 775, v2580"
	const adExpired = "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 532, v2580"
	const adWrongPw = "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v2580"

	cases := []struct {
		name       string
		in         string
		wantCode   string
		wantReason string
	}{
		{"账号被禁用", adDisabled, "533", "账号已被禁用"},
		{"账号被锁定", adLocked, "775", "账号已被锁定"},
		{"口令已过期", adExpired, "532", "口令已过期"},
		{"口令错误", adWrongPw, "52e", "口令错误"},
		{"大写十六进制也要认", "AcceptSecurityContext error, DATA 52E, v2580", "52e", "口令错误"},
		{"未收录的码：解出来但没有解释", "AcceptSecurityContext error, data 9999, v1", "9999", ""},
		{"通用 LDAP 的诊断串里没有 data 码", "Invalid Credentials", "", ""},
		{"空串", "", "", ""},
		// ★ DSID-0C0903A9 / v2580 是同一条诊断串里的噪声，绝不能被当成 data 码抓走：
		// 抓错了会把"账号被禁用"解释成别的状态，比不解释更误导人。
		{"不能把 DSID / v2580 当成 data 码", "LdapErr: DSID-0C0903A9, v2580", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, reason := decodeADBindFailure(c.in)
			if code != c.wantCode || reason != c.wantReason {
				t.Fatalf("decodeADBindFailure(%q) = (%q, %q)，期望 (%q, %q)", c.in, code, reason, c.wantCode, c.wantReason)
			}
		})
	}
}
