package auth

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// 初始口令生成（FR-POLICY-08 的配套）。
//
// ★为什么需要它：建号/建管理员/CSV 导入三条路径此前在口令留空时回落成一个**编译进
// 二进制的公开常量**（`baidi@123`），控制台的占位符还当面写着「留空则用默认 baidi@123」。
// 于是"新账号在本人首登之前持有一把公开口令"被做成了产品的推荐路径——`MustChangePw`
// 只保证「谁先登谁改」，拦不住知道账号刚建好的人抢先登进去。
//
// 但把留空直接拒掉也不对：用户目录的 CSV 导出**不含口令**（也不该含），硬拒会让
// 「导出 → 迁到另一套 → 导入」这条路整段走不通，而那正是批量导入存在的理由。
//
// 所以留空 = 服务端**逐个账号**生成一把随机强口令，并在回执里把它交还给管理员去分发。
// 三条性质缺一不可：逐个账号（不是一批共用一把）、真随机（crypto/rand）、
// 且**必须自己过一遍 PasswordWeakness**——生成器与校验器分家的话，迟早出现
// "系统自己生成的口令被系统自己拒收"，而那是个没人看得懂的 500。

const (
	initialPwLen   = 14
	pwLower        = "abcdefghijkmnopqrstuvwxyz" // 去掉 l
	pwUpper        = "ABCDEFGHJKLMNPQRSTUVWXYZ"  // 去掉 I、O
	pwDigit        = "23456789"                  // 去掉 0、1
	pwSymbol       = "!@#$%^&*-_=+"
	initialPwTries = 32
)

// GenerateInitialPassword 生成一把随机初始口令，保证 PasswordWeakness(account, pw) 判为强。
//
// 字符表刻意去掉了 l/I/1/O/0 —— 初始口令是要被人**抄写或口头转达**的，
// 形近字符会变成一次"口令明明是对的却登不进去"的支持请求。
//
// 返回 error 只在 crypto/rand 不可用时发生；调用方必须 fail-closed（绝不回落到常量口令）。
func GenerateInitialPassword(account string) (string, error) {
	all := pwLower + pwUpper + pwDigit + pwSymbol
	for try := 0; try < initialPwTries; try++ {
		// 先各取一个，保证四类齐全（classes>=3 是硬要求，随机抽样偶尔会缺类）。
		buf := []byte{}
		for _, set := range []string{pwLower, pwUpper, pwDigit, pwSymbol} {
			c, err := pickOne(set)
			if err != nil {
				return "", err
			}
			buf = append(buf, c)
		}
		for len(buf) < initialPwLen {
			c, err := pickOne(all)
			if err != nil {
				return "", err
			}
			buf = append(buf, c)
		}
		if err := shuffle(buf); err != nil {
			return "", err
		}
		pw := string(buf)
		// ★自检：与写入闸共用同一个判据。这里若判弱就重抽，而不是放行——
		// 生成器和校验器各说各话时，症状是建号偶发 400 且无人复现得了。
		if weak, _ := PasswordWeakness(account, pw); !weak {
			return pw, nil
		}
	}
	// 32 次都没抽出合规口令，说明判据与生成器已经不自洽了（例如有人给
	// PasswordWeakness 加了一条新规则却没更新字符表）。fail-closed，别硬发一把。
	return "", errInitialPwExhausted
}

type initialPwErr string

func (e initialPwErr) Error() string { return string(e) }

const errInitialPwExhausted = initialPwErr(
	"随机初始口令生成失败：连续 32 次都被强度判据判为弱口令，说明生成器与 PasswordWeakness 已不自洽")

func pickOne(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}

func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := n.Int64()
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

// InitialPasswordNote 回执里附给管理员的一句话。集中一处，免得三个入口说三种话。
func InitialPasswordNote() string {
	return "这是系统生成的一次性初始口令，只在本次回执里出现一次，请立即转交本人；" +
		"该账号已被置为首次登录必须改密。"
}

// MaskAccountForLog 记日志时用的账号脱敏（初始口令绝不入日志，账号可以）。
func MaskAccountForLog(account string) string {
	a := strings.TrimSpace(account)
	if len([]rune(a)) <= 2 {
		return a
	}
	r := []rune(a)
	return string(r[:1]) + strings.Repeat("*", len(r)-2) + string(r[len(r)-1:])
}
