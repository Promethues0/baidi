package api

// 闲置账号治理（wave7 行动 8②：FR-MON-19/20）。
//
// 识别（GET）读 = 任意管理员现算角色；批量锁定（POST）写 = PermSecurity，
// 且目标是管理员时逐个抬到 PermAdmins（与单个置状态的 guardAdminTarget 同一道闸，
// 批量不是绕过分权的后门）；最后一名超管由 store.SetUserStatus 的防自锁拦截。
//
// ★批量锁定复用单个置状态的全部语义：同一个 SetUserStatus（带防自锁事务）、
// 同一条数据面联动（入封禁表 → 网关轮询撤窗断隧道）、逐账号落审计。
// 「批量」只是循环，不是一条绕开任何守卫的快速通道。

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// idleStore SQLiteStore 的闲置识别能力（Memory 种子模式没有——闲置判据 last_login
// 是真实数据域，演示数据里的"最后登录"本来就是编的，不值得为它出一份假清单）。
type idleStore interface {
	IdleAccounts(ctx context.Context, thresholdDays int) ([]store.IdleAccount, error)
}

// idleDaysParam 解析阈值参数（默认 90 天，夹到 [7, 3650]——低于 7 天的"闲置"
// 会把请了个年假的人扫进来，那不是治理是误伤）。
func idleDaysParam(r *http.Request) int {
	d, err := strconv.Atoi(r.URL.Query().Get("days"))
	if err != nil || d == 0 {
		return 90
	}
	if d < 7 {
		return 7
	}
	if d > 3650 {
		return 3650
	}
	return d
}

// handleIdleAccounts GET /api/v1/users/idle?days=N——闲置账号清单（读，任意管理员）。
func (s *Server) handleIdleAccounts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	is, ok := s.store.(idleStore)
	if !ok {
		// 内存种子模式：如实说没有判据，不出一份编造的清单。
		httpx.JSON(w, http.StatusOK, map[string]any{"days": idleDaysParam(r), "accounts": []store.IdleAccount{}, "note": "当前后端无登录记录数据，无法判定闲置"})
		return
	}
	days := idleDaysParam(r)
	accounts, err := is.IdleAccounts(r.Context(), days)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "闲置账号清单读取失败")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"days": days, "accounts": accounts})
}

// handleIdleLock POST /api/v1/users/idle/lock {ids:[...]}——批量锁定闲置账号。
// 逐账号执行、逐账号回报：部分失败不该让整批悄悄回滚（管理员要的是"哪些没锁上、为什么"）。
func (s *Server) handleIdleLock(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var b struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&b); err != nil || len(b.IDs) == 0 {
		httpx.Error(w, http.StatusBadRequest, "ids 不能为空")
		return
	}
	if len(b.IDs) > 500 {
		httpx.Error(w, http.StatusBadRequest, "单批最多 500 个账号")
		return
	}
	// 管理员目标的权限抬升只判一次（判据与 guardAdminTarget 相同），逐目标应用。
	callerRole, roleOK := s.currentAdminRoleQuiet(r)

	type skipped struct {
		ID      string `json:"id"`
		Account string `json:"account,omitempty"`
		Reason  string `json:"reason"`
	}
	locked := []string{}
	skips := []skipped{}
	for _, id := range b.IDs {
		target, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool { return du.ID == id })
		if err != nil {
			skips = append(skips, skipped{ID: id, Reason: "目录读取失败"})
			continue
		}
		if !found {
			skips = append(skips, skipped{ID: id, Reason: "账号不存在"})
			continue
		}
		if target.Status != "active" {
			skips = append(skips, skipped{ID: id, Account: target.Account, Reason: "当前状态为「" + statusZh[target.Status] + "」，无需锁定"})
			continue
		}
		if target.Role == "admin" && (!roleOK || !callerRole.Allows(store.PermAdmins)) {
			// 与 guardAdminTarget 同一道闸：批量不是安全管理员锁掉审计/系统管理员的后门。
			s.audit(r, "security", "拒绝越权：批量锁定跳过管理员账号「"+target.Account+"」（需要权限 "+store.PermAdmins+"）", "deny")
			skips = append(skips, skipped{ID: id, Account: target.Account, Reason: "目标是管理员，需要「管理员与角色管理」权限"})
			continue
		}
		if err := s.writer.SetUserStatus(r.Context(), id, "locked"); err != nil {
			// 防自锁（最后一名超管）等领域错误：如实回报，不中断整批。
			skips = append(skips, skipped{ID: id, Account: target.Account, Reason: err.Error()})
			continue
		}
		// 数据面联动与单个置状态完全一致：入封禁表，网关下一轮策略即撤窗断隧道。
		key := normUser(target.Account)
		s.mu.Lock()
		s.revoked[key] = revokeInfo{Reason: "账号已锁定（闲置治理）", Until: time.Now().Add(kickBanTTL).Unix(), Display: target.Account}
		s.mu.Unlock()
		s.audit(r, "admin", "闲置治理：锁定账号「"+target.Account+"」（数据面撤窗断隧道）", "ok")
		locked = append(locked, target.Account)
	}
	s.audit(r, "admin", "闲置账号批量锁定完成："+strconv.Itoa(len(locked))+" 个已锁定、"+strconv.Itoa(len(skips))+" 个跳过", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "locked": locked, "skipped": skips})
}

// currentAdminRoleQuiet 取当前管理员角色但不写响应（批量路径逐项判定用；
// currentAdminRole 会直接把 403 写进 w，批量里那等于第一个管理员目标就中断整批）。
func (s *Server) currentAdminRoleQuiet(r *http.Request) (store.AdminRole, bool) {
	c, ok := auth.FromContext(r.Context())
	if !ok || c.Role != "admin" {
		return store.AdminRole{}, false
	}
	role, found, err := s.store.AdminRoleFor(r.Context(), c.Sub)
	if err != nil || !found {
		return store.AdminRole{}, false
	}
	return role, true
}
