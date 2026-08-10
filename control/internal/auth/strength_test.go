package auth

import "testing"

func TestPasswordWeakness(t *testing.T) {
	cases := []struct {
		name, account, pw string
		wantWeak          bool
	}{
		{"演示口令", "admin", "baidi@123", true},
		{"常见弱口令", "zhang.wei", "Password123", true}, // 小写化后命中弱口令表
		{"含账号名", "zhang.wei", "Zhangwei#2026", true},
		{"太短", "li.fang", "Ab#3xk9", true},
		{"字符种类不足", "li.fang", "abcdkxmqrt", true},
		{"连续字符", "li.fang", "abcdefghij", true},
		{"三类且够长", "li.fang", "Kx9#mqrtvz", false},
		{"长口令句免字符类别", "li.fang", "correcthorsebatterystaple", false},
		{"空口令", "li.fang", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			weak, reason := PasswordWeakness(c.account, c.pw)
			if weak != c.wantWeak {
				t.Fatalf("PasswordWeakness(%q,%q)=%v(%s), want %v", c.account, c.pw, weak, reason, c.wantWeak)
			}
			if weak && reason == "" {
				t.Fatal("判弱必须给出原因（原因要能写进审计与前端提示）")
			}
			want := PwStrong
			if c.wantWeak {
				want = PwWeak
			}
			if got := PasswordStrength(c.account, c.pw); got != want {
				t.Fatalf("PasswordStrength=%s want %s", got, want)
			}
		})
	}
}

// 账号过短时不做包含判定：两三个字母的子串会把无关口令误判成"含账号名"。
func TestAccountCoreTooShort(t *testing.T) {
	if weak, reason := PasswordWeakness("ab", "Kx9#mqrtvz"); weak {
		t.Fatalf("短账号不应触发包含判定：%s", reason)
	}
}
