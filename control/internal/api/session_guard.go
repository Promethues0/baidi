package api

import (
	"net/http"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// 会话有效性闸（wave11 行动 4）。
//
// ★这道闸补的是控制面上最后一处「处置了但没生效」：`auth.Middleware` 只验签名与用途
// 白名单、不查任何库；`AdminRoleFor` 的 SQL 只筛 `role='admin'` 不筛 `status`；
// `requireUser` 更是纯令牌判定。于是禁用 / 锁定 / 强制下线 / 闲置自动锁定四条处置，
// 对已签发的 8h 令牌全部无效——**数据面当场断了，管理 API 却还开着**。
//
// 判据两条，缺一不可：
//   - `accountBlocked(status)`：账号此刻是不是被禁用/锁定（与登录、敲门共用同一个判据函数，
//     不另写一份——两份判据迟早在"这人还能不能进"上给出两个答案）；
//   - `Claims.Iat < TokensValidAfter`：这张令牌是不是在最后一次处置之前签发的。
//     强制下线不改 status（用户还能重新登录），只有这一条拦得住他手里那张旧令牌。
//
// ★读不到一律 **fail-closed 403 并落审计**，与「读不到角色一律 fail-closed」逐字同口径。
// 方向理由：读不到时放行等于"库一抖，所有已撤销的令牌全部复活"，而那一刻没有任何信号。

// sessionRevokedMsg 统一文案。三处（管理端 / 用户端 / 审计）说同一句话。
const sessionRevokedMsg = "登录状态已失效（账号被禁用、锁定或已被强制下线），请重新登录"

// checkSessionValid 用一份已取到的 Credential 判断该令牌是否仍然有效。
//
// 拆成纯函数是为了让判定可测：取数在 handler 里、判定在这里，
// 与 risk.Evaluate / alerting.Evaluate 同一条分工纪律。
func checkSessionValid(c auth.Claims, cred store.Credential) (ok bool, why string) {
	if accountBlocked(cred.Status) {
		return false, "账号已" + statusZh[cred.Status]
	}
	// Iat 为 0 = 旧版签发的令牌不带 iat。此时**不能**判成"早于任何下限"——
	// 那会让升级瞬间全体在线用户掉线；也不能判成"永远有效"——那会让处置对这批令牌
	// 永久无效。取中间：仅当账号从未被处置过（下限为 0）时放行，一旦有过处置就拒。
	// 这批令牌最长 8h 内自然过期，窗口是有界的。
	// ★比较用 <= 而不是 <：这一列是**秒**粒度，写 < 的话「与处置发生在同一秒内签发」
	// 的令牌会整个逃过注销。生产里那是一个一秒宽的窗口（强制下线之后客户端立刻重登
	// 恰好落在同一秒），测试里则是必现——处置紧跟着造令牌。
	// 代价是同一秒内的一次重新登录会拿到一张当场失效的令牌，下一秒重试即可，窗口有界；
	// 反过来的代价是"踢了但没踢掉"，而那正是这条修复要消灭的东西。
	if cred.TokensValidAfter > 0 && c.Iat <= cred.TokensValidAfter {
		return false, "该登录会话已被注销"
	}
	return true, ""
}

// guardSession 取数 + 判定 + 写应答。返回 false 表示已经写过应答，调用方直接 return。
func (s *Server) guardSession(w http.ResponseWriter, r *http.Request, c auth.Claims) bool {
	cred, found, err := s.store.Credential(r.Context(), c.Sub)
	if err != nil {
		// fail-closed：库读不到时放行 = 一次抖动让全部已撤销令牌复活，且无任何信号。
		s.audit(r, "security", "会话有效性判不出来（目录读取失败），已拒绝："+c.Sub, "deny")
		httpx.Error(w, http.StatusForbidden, "无法确认登录状态是否仍然有效，请重新登录")
		return false
	}
	if !found {
		// 账号已被删除，而令牌还在手上。删除是 License 席位的释放路径，
		// 留着这张令牌等于"人删了，权限还在"。
		s.audit(r, "security", "令牌主体已不存在，已拒绝："+c.Sub, "deny")
		httpx.Error(w, http.StatusForbidden, sessionRevokedMsg)
		return false
	}
	if ok, why := checkSessionValid(c, cred); !ok {
		s.audit(r, "security", "拒绝已失效的登录会话："+c.Sub+"（"+why+"）访问 "+
			r.Method+" "+r.URL.Path, "deny")
		httpx.Error(w, http.StatusForbidden, sessionRevokedMsg+"（"+why+"）")
		return false
	}
	return true
}
