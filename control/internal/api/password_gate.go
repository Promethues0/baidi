package api

import (
	"net/http"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
)

// 口令复杂度闸（FR-POLICY-08）。
//
// ★为什么要单独收一处：改造前 `auth.PasswordWeakness` 在全仓只有**一个**非测试消费方
// ——自助改密（api.go 的 handlePasswordChange）。而口令能被写进库的地方有五处，
// 另外四处（建普通用户 / 管理员重置口令 / 建管理员 / CSV 批量导入）一律只查 `len(pw) < 6`，
// 于是判定器算得好好的、中文原因也备好了，弱口令照样原样落库并回 200。
//
// 后果不是"少了一道提示"：
//   - 管理员在建号页把口令设成 `baidi@123`（命中内置弱口令表）→ 接口回 201、
//     用户目录里那行 `pw_strength` 老老实实标着 weak，而没有任何一处拦过它；
//   - `BAIDI_SEED_MUST_CHANGE` 只保证"谁先登谁改"，拦不住在首登之前就有人拿这把口令登进去；
//   - CSV 批量导入是最坏的一条：一次几百个账号共用同一把弱口令，且这条路径连
//     `pw_strength` 都要靠 buildImportUser 现算，页面上看不出这批人有什么不同。
//
// 判据只有一处（`auth.PasswordWeakness`），与 `users.pw_strength` 落库用的
// `auth.PasswordStrength` 同源——两者若各写一份，迟早出现"存进去是强、拦的时候按弱"。
//
// ★这里刻意**不**读认证策略里的 weakPwd 开关：那条规则的语义是「弱口令账号登录时抬一次
// 二次认证」，是登录期的加强项；而本闸是写入期的准入线，两者不同层。把准入线做成可配开关，
// 等于允许管理员把它关掉——那正是本仓反复批过的"给安全闸装一个可关的旋钮"。

// passwordTooWeakMsg 统一的拒绝文案。与自助改密那条逐字同款——同一件事在两个入口
// 说两种话，用户会以为是两条不同的规则。
func passwordTooWeakMsg(why string) string {
	return "口令强度不足：" + why +
		"。要求：至少 10 位且含大写/小写/数字/符号中的三类；或 16 位以上的长口令"
}

// weakPasswordReason 口令不合规时返回中文原因，合规返回空串。
// 供没有 http.ResponseWriter 可写的调用方（CSV 逐行导入的 fail 回执）使用。
func weakPasswordReason(account, pw string) string {
	if weak, why := auth.PasswordWeakness(account, pw); weak {
		return passwordTooWeakMsg(why)
	}
	return ""
}

// requireStrongPassword 不合规时写好 400 应答并返回 false。
//
// account 参与判定：口令里含账号名是最常见的可猜形态，而这四条写口恰恰都知道账号名
// （自助改密那条用的是令牌里的 Sub，同理）。
func requireStrongPassword(w http.ResponseWriter, account, pw string) bool {
	if why := weakPasswordReason(account, pw); why != "" {
		httpx.Error(w, http.StatusBadRequest, why)
		return false
	}
	return true
}
