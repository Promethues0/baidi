package auth

import "testing"

// 口令哈希：同一口令两次哈希结果不同（含盐），但都能被 VerifyPassword 验过；错误口令验不过。
func TestHashAndVerifyPassword(t *testing.T) {
	h1, err := HashPassword("baidi@123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h2, _ := HashPassword("baidi@123")
	if h1 == h2 {
		t.Fatal("两次哈希应因随机盐而不同")
	}
	if h1 == "baidi@123" {
		t.Fatal("哈希不得等于明文")
	}
	if !VerifyPassword(h1, "baidi@123") {
		t.Fatal("正确口令应验过")
	}
	if VerifyPassword(h1, "wrong") {
		t.Fatal("错误口令不应验过")
	}
}

// 空哈希（历史遗留/未设密码）永远验不过——fail-closed，不得把"没密码"当"任意密码通过"。
func TestVerifyPasswordEmptyHashRejects(t *testing.T) {
	if VerifyPassword("", "anything") {
		t.Fatal("空哈希不应验过任何口令")
	}
	if VerifyPassword("not-a-bcrypt-hash", "anything") {
		t.Fatal("非法哈希不应验过")
	}
}
