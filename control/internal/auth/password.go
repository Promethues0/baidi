package auth

import "golang.org/x/crypto/bcrypt"

// HashPassword 用 bcrypt（含随机盐，无 CGO）对明文口令做单向哈希，供落库。
func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword 校验明文口令是否匹配存储的 bcrypt 哈希。
// 空哈希或非法哈希一律返回 false（fail-closed）——绝不把"未设密码"当作"任意密码通过"。
func VerifyPassword(hash, plain string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
