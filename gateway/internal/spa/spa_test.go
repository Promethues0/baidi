package spa

import (
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/auth"
)

func TestDenyUser(t *testing.T) {
	al := NewAllowlist()
	until := time.Now().Add(time.Hour)

	if !al.DenyUser("li.fang", until) {
		t.Fatal("首次封禁应返回 true（新封禁）")
	}
	if al.DenyUser("li.fang", until) {
		t.Fatal("同一截止时间重复封禁应返回 false（幂等，避免轮询重复执行处置）")
	}
	if !al.UserDenied("li.fang") {
		t.Fatal("封禁期内 UserDenied 应为 true")
	}
	if al.UserDenied("ext.zhou") {
		t.Fatal("未封禁用户 UserDenied 应为 false")
	}

	// 延长封禁视作新动作（控制台可再次 kick 续封）
	if !al.DenyUser("li.fang", until.Add(time.Minute)) {
		t.Fatal("延长封禁截止应返回 true")
	}
}

func TestDenyUserExpiry(t *testing.T) {
	al := NewAllowlist()
	if al.DenyUser("li.fang", time.Now().Add(-time.Second)) {
		t.Fatal("已过期的封禁不应生效")
	}
	if al.UserDenied("li.fang") {
		t.Fatal("过期封禁 UserDenied 应为 false")
	}

	// 生效后过期 → 懒清理恢复可用
	al.DenyUser("ext.zhou", time.Now().Add(20*time.Millisecond))
	if !al.UserDenied("ext.zhou") {
		t.Fatal("封禁期内应为 true")
	}
	time.Sleep(30 * time.Millisecond)
	if al.UserDenied("ext.zhou") {
		t.Fatal("封禁到期后应自动失效")
	}
}

func TestDenyNormalized(t *testing.T) {
	al := NewAllowlist()
	al.DenyUser("li.fang", time.Now().Add(time.Hour))

	// 换大小写/加空格重登不得绕过封禁
	for _, variant := range []string{"Li.Fang", "LI.FANG", " li.fang ", "li.fang"} {
		if !al.UserDenied(variant) {
			t.Fatalf("变体 %q 应命中封禁（规范化匹配）", variant)
		}
		if al.Allow("10.0.0.9", variant, "user", time.Minute) {
			t.Fatalf("变体 %q 敲门应被封禁拒绝（Allow 返回 false）", variant)
		}
	}

	// 撤窗按规范化匹配：以变体形态登记的放行窗口也应被撤销
	al2 := NewAllowlist()
	al2.deny = map[string]time.Time{} // 无封禁，直接放行
	al2.Allow("10.0.0.1", "Li.Fang ", "user", time.Minute)
	if ips := al2.RevokeUser("li.fang"); len(ips) != 1 {
		t.Fatalf("规范化撤窗应命中变体登记的窗口，实际 %v", ips)
	}
}

func TestRevokeUser(t *testing.T) {
	al := NewAllowlist()
	al.Allow("10.0.0.1", "li.fang", "user", time.Minute)
	al.Allow("10.0.0.2", "li.fang", "user", time.Minute)
	al.Allow("10.0.0.3", "ext.zhou", "user", time.Minute)

	ips := al.RevokeUser("li.fang")
	if len(ips) != 2 {
		t.Fatalf("应撤销 li.fang 的 2 个放行窗口，实际 %v", ips)
	}
	if _, _, ok := al.Allowed("10.0.0.1"); ok {
		t.Fatal("撤销后 10.0.0.1 不应再在放行窗口内")
	}
	if _, _, ok := al.Allowed("10.0.0.2"); ok {
		t.Fatal("撤销后 10.0.0.2 不应再在放行窗口内")
	}
	if _, _, ok := al.Allowed("10.0.0.3"); !ok {
		t.Fatal("其他用户的放行窗口不应被殃及")
	}
	if got := al.RevokeUser("li.fang"); len(got) != 0 {
		t.Fatalf("重复撤销应为空，实际 %v", got)
	}
}

// ★用途闸的**敲门这一侧**：七层 Web 代理的访问票据（use=web）绝不能敲开门。
// 另一侧（L7 路径拒 use=knock）由 webproxy 包的用例守着——两条必须成对存在，
// 少任一侧，一张票就能同时开两条入场路径，而两条路径的闸完全不同
// （敲门那条有终端合规/设备准入，L7 那条没有）。
//
// 生产里它还有一层密码学隔离（两条路径各装一把公钥，web 票据在 SPA 侧连签名都验不过），
// 这里单测的是语义闸本身：即便有朝一日两把公钥被误装成同一把，它也必须拦住。
func TestCheckKnockRejectsWebTicket(t *testing.T) {
	now := time.Now()
	web := auth.Claims{Sub: "u", Role: "user", Name: "u", Jti: "j", Use: auth.UseWeb, Res: "oa",
		Iat: now.Unix(), Exp: now.Add(60 * time.Second).Unix()}
	if err := checkKnock(web, true, 5*time.Minute); err == nil {
		t.Fatal("★Web 访问票据必须敲不开门")
	} else if !strings.Contains(err.Error(), "非敲门令牌") {
		t.Fatalf("应因用途不符被拒，得: %v", err)
	}
	// 对照组：同样的信封、同样的寿命，只把 use 换成 knock 就该通过——
	// 证明上面那条拒绝确实来自用途闸，而不是别的字段不合格。
	knock := web
	knock.Use, knock.Res = auth.UseKnock, ""
	if err := checkKnock(knock, true, 5*time.Minute); err != nil {
		t.Fatalf("对照组敲门令牌应通过: %v", err)
	}
}
