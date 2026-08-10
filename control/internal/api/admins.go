package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 管理员分级分权 / 三权分立（PRD ch15.1）的**执行方**与管理端点 ──
//
// 此前控制面的权限模型只有 admin|user 两级：任何管理员都能改用户、改策略、读全量审计，
// 而系统管理页用五张编造的管理组卡片把这一页撑成"三权分立已就绪"的样子。
// 现在角色落 admin_roles 表、归属落 users.admin_role，**判定点就是下面的 requirePerm**。

// requirePerm 按权限键校验当前管理员。requireAdmin 之上再加一道，两者都过才放行。
//
// 三条刻意的取舍：
//   - **角色现算不进令牌**：写进 8h 会话令牌的话，一次降权要等到令牌过期才生效，
//     而分级分权的全部价值就在于"改了立刻算数"。
//   - **fail-closed**：角色读不出来（库抖动）或账号没有角色（升级异常/角色被删）
//     一律 403，绝不"查不到就当有权"。回填 backfillAdminRoles 保证升级那一刻
//     既有管理员不会落进这个分支。
//   - **越权尝试落审计**：category=security、verdict=deny，措辞只记事实
//     （谁、以什么角色、访问什么、缺哪个权限键）。
func (s *Server) requirePerm(w http.ResponseWriter, r *http.Request, perm string) bool {
	if !s.requireAdmin(w, r) {
		return false
	}
	c, _ := auth.FromContext(r.Context())
	role, ok, err := s.store.AdminRoleFor(r.Context(), c.Sub)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load admin role")
		return false
	}
	if !ok {
		s.audit(r, "security", "拒绝越权："+c.Sub+" 未分配管理员角色，访问 "+r.Method+" "+r.URL.Path, "deny")
		httpx.Error(w, http.StatusForbidden, "当前账号未分配管理员角色，请联系超级管理员")
		return false
	}
	if !role.Allows(perm) {
		s.audit(r, "security", "拒绝越权："+c.Sub+"（角色「"+role.Name+"」）访问 "+
			r.Method+" "+r.URL.Path+" 需要权限 "+perm, "deny")
		httpx.Error(w, http.StatusForbidden, "角色「"+role.Name+"」无权执行该操作（需要权限："+perm+"）")
		return false
	}
	return true
}

// adminStoreErr 把管理员分权的领域错误映射成 HTTP 应答。
// 防自锁必须回 409 + 原因：回 500 只会让管理员反复重试同一个注定失败的操作。
func adminStoreErr(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, store.ErrLastRootAdmin), errors.Is(err, store.ErrAdminRoleInUse),
		errors.Is(err, store.ErrAdminRoleBuiltin):
		httpx.Error(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrAdminRoleNotFound):
		httpx.Error(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrUnknownAccount), errors.Is(err, store.ErrAdminRolePerm),
		errors.Is(err, store.ErrNotAdminAccount):
		httpx.Error(w, http.StatusBadRequest, err.Error())
	default:
		httpx.Error(w, http.StatusInternalServerError, fallback)
	}
}

// handleSystem 系统管理页：角色（三权分立）+ 管理员账号 + 集群状态。
//
// 读放给任意管理员（审计管理员要能监督其余角色的权限分布），**写**一律 PermAdmins。
func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	b, err := s.store.System(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load system")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

// handleSaveAdminRole 新建/修改自定义角色（PermAdmins）。内置四角色拒改。
func (s *Server) handleSaveAdminRole(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermAdmins) {
		return
	}
	var body struct {
		Key   string   `json:"key"`
		Name  string   `json:"name"`
		Perms []string `json:"perms"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体格式错误")
		return
	}
	saved, err := s.writer.SaveAdminRole(r.Context(),
		store.AdminRole{Key: body.Key, Name: body.Name, Perms: body.Perms})
	if err != nil {
		adminStoreErr(w, err, "failed to save admin role")
		return
	}
	s.audit(r, "admin", "保存自定义管理员角色「"+saved.Name+"」("+saved.Key+"，权限 "+
		strings.Join(saved.Perms, "/")+")", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "role": saved})
}

// handleDeleteAdminRole 删除自定义角色（PermAdmins）。内置拒删、有成员拒删。
func (s *Server) handleDeleteAdminRole(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermAdmins) {
		return
	}
	key := r.PathValue("key")
	if err := s.writer.DeleteAdminRole(r.Context(), key); err != nil {
		s.audit(r, "admin", "删除管理员角色 "+key+" 被拒："+err.Error(), "fail")
		adminStoreErr(w, err, "failed to delete admin role")
		return
	}
	s.audit(r, "admin", "删除自定义管理员角色 "+key, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "key": key})
}

// handleCreateAdmin 新建管理员 / 把已有账号提升为管理员（PermAdmins）。
//
// account 已存在 → 只改角色（不动口令、不动组织）；不存在 → 建号并置首登改密。
// 建号路径**不复用** POST /api/v1/users：那条路属 PermSecurity，若能顺带指定
// role=admin，安全管理员一次请求就能给自己造一个超管（见 handleCreateUser 里的收口）。
func (s *Server) handleCreateAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermAdmins) {
		return
	}
	var body struct {
		Account  string `json:"account"`
		Name     string `json:"name"`
		RoleKey  string `json:"roleKey"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil ||
		strings.TrimSpace(body.Account) == "" || strings.TrimSpace(body.RoleKey) == "" {
		httpx.Error(w, http.StatusBadRequest, "账号与角色不能为空")
		return
	}
	account := strings.TrimSpace(body.Account)
	existing, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool {
		return normUser(du.Account) == normUser(account)
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user directory")
		return
	}
	if found {
		if err := s.writer.SetAdminRole(r.Context(), existing.Account, body.RoleKey); err != nil {
			adminStoreErr(w, err, "failed to assign admin role")
			return
		}
		s.audit(r, "admin", "将账号「"+existing.Account+"」提升为管理员，角色 "+body.RoleKey, "ok")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "account": existing.Account, "roleKey": body.RoleKey})
		return
	}
	// 角色必须先存在再建号——否则会落下一个"是管理员但角色悬空"的账号，
	// 它在 requirePerm 里 fail-closed 什么都做不了，而列表上看起来一切正常。
	roles, err := s.store.AdminRoles(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load admin roles")
		return
	}
	valid := false
	for _, rr := range roles {
		if rr.Key == strings.ToLower(strings.TrimSpace(body.RoleKey)) {
			valid = true
		}
	}
	if !valid {
		adminStoreErr(w, store.ErrAdminRoleNotFound, "")
		return
	}
	pw := body.Password
	if pw == "" {
		pw = seedInitialPassword
	}
	if len(pw) < 6 {
		httpx.Error(w, http.StatusBadRequest, "初始口令至少 6 位")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = account
	}
	created, err := s.writer.CreateUser(r.Context(), store.DirUser{
		Name: name, Account: account, Status: "active", Risk: "none",
		Role: "admin", AdminRole: strings.ToLower(strings.TrimSpace(body.RoleKey)),
		PassHash: hash, PwStrength: auth.PasswordStrength(account, pw), MustChangePw: true,
	})
	if err != nil {
		adminStoreErr(w, err, "failed to create admin")
		return
	}
	s.audit(r, "admin", "新建管理员「"+created.Name+"」("+created.Account+"，角色 "+
		body.RoleKey+")，已置首登改密", "ok")
	httpx.JSON(w, http.StatusCreated, map[string]any{"ok": true, "account": created.Account, "roleKey": body.RoleKey})
}

// handleSetAdminRole 改派管理员角色（PermAdmins）。降走最后一名超管时 409。
func (s *Server) handleSetAdminRole(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermAdmins) {
		return
	}
	account := r.PathValue("account")
	var body struct {
		RoleKey string `json:"roleKey"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil ||
		strings.TrimSpace(body.RoleKey) == "" {
		httpx.Error(w, http.StatusBadRequest, "roleKey 不能为空")
		return
	}
	if err := s.writer.SetAdminRole(r.Context(), account, body.RoleKey); err != nil {
		s.audit(r, "admin", "改派管理员「"+account+"」角色为 "+body.RoleKey+" 被拒："+err.Error(), "fail")
		adminStoreErr(w, err, "failed to set admin role")
		return
	}
	s.audit(r, "admin", "改派管理员「"+account+"」角色为 "+body.RoleKey, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "account": account, "roleKey": body.RoleKey})
}

// handleRemoveAdmin 撤销管理员身份，降为普通用户（PermAdmins）。最后一名超管 409。
//
// 刻意不删账号：删号会让审计里的历史行为人对不上任何一个现存账号。
func (s *Server) handleRemoveAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermAdmins) {
		return
	}
	account := r.PathValue("account")
	if err := s.writer.RemoveAdmin(r.Context(), account); err != nil {
		s.audit(r, "admin", "撤销管理员「"+account+"」被拒："+err.Error(), "fail")
		adminStoreErr(w, err, "failed to remove admin")
		return
	}
	s.audit(r, "admin", "撤销「"+account+"」的管理员身份（降为普通用户，角色已清空）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "account": account})
}
