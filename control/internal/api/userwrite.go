package api

// 用户目录的改与删（PRD FR-USER-02「本地新建与修改」、FR-USER-15 席位释放）。
//
// 两条端点此前都不存在，而它们的缺席各自引出一条死路——理由写在
// store/userwrite.go 的文件头；这里只管入口的守卫与回执。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// userWriter 目录改删能力（Memory 种子模式没有——那份目录本来就是编的）。
type userWriter interface {
	UpdateUserProfile(ctx context.Context, id string, p store.UserProfilePatch) (store.DirUser, error)
	UserDeleteBlastRadius(ctx context.Context, id string) (store.UserDeleteBlast, error)
	DeleteUser(ctx context.Context, id string) error
}

// handleUpdateUser PUT /api/v1/users/{id}（PermSecurity，与建号同权）。
//
// ★只收 name / email 两项。account 不可改（它是令牌主体 JWT Sub，也是 JIT 授予、
// 封禁名单、posture 报告、用户组成员、认证源绑定的关联键——改它等于把这些关系
// 整段挂空，而那些表里没有一处会报错）；role / adminRole 一律不看（否则这就是
// 一条绕开 POST /admins 的提权路，同 handleCreateUser 的收口）。
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	uw, ok := s.writer.(userWriter)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前后端不支持修改用户资料")
		return
	}
	id := r.PathValue("id")
	target, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool { return du.ID == id })
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "用户不存在")
		return
	}
	// 目标是管理员时抬到 admins 权：改管理员的显示名会改变审计里"是谁做的"那一栏
	// 的呈现，与重置口令同一道收口。
	if !s.guardAdminTarget(w, r, target, "修改用户资料") {
		return
	}
	var body struct {
		Name    *string `json:"name"`
		Email   *string `json:"email"`
		Account *string `json:"account"` // 只为把它显式拒掉，不做任何事
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体格式不正确")
		return
	}
	// ★显式拒绝而不是静默忽略：静默忽略会让调用方以为改成了（接口回 200、
	// 响应体里 account 还是旧值，很容易被读成"回显滞后"）。
	if body.Account != nil && *body.Account != target.Account {
		httpx.Error(w, http.StatusBadRequest,
			"账号名不可修改：它是令牌主体，也是 JIT 授予 / 封禁名单 / 终端报告 / 用户组成员 / 认证源绑定的关联键，"+
				"改它会让这些关系整段挂空且不报错。需要换账号名请新建账号并迁移授权。")
		return
	}
	if body.Name == nil && body.Email == nil {
		httpx.Error(w, http.StatusBadRequest, "没有要修改的字段（可改：姓名 name、邮箱 email）")
		return
	}
	updated, err := uw.UpdateUserProfile(r.Context(), id, store.UserProfilePatch{Name: body.Name, Email: body.Email})
	switch {
	case errors.Is(err, store.ErrUserNotFound):
		httpx.Error(w, http.StatusNotFound, "用户不存在（可能已被删除）")
		return
	case err != nil:
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "admin", "修改用户资料「"+target.Account+"」："+profileDiffZh(target, updated), "ok")
	// ★回执必须与 GET /users 是**同一个形状**：不补这一步的话，PUT 回的是库里那份
	//   原始行（online/risk/device/ip 还是建号那天的冻结值），而列表里是现算过的。
	//   前端拿它回填抽屉，页面上就会出现「刚改完这个人突然又在线了、还带着一台
	//   从没上报过的终端」——同一个对象两种形状是最难查的一类不一致。
	rows := []store.DirUser{updated}
	s.enrichDirUsers(r.Context(), rows)
	httpx.JSON(w, http.StatusOK, rows[0])
}

// profileDiffZh 把改动写成人话进审计——只写「已修改」的审计等于没记。
func profileDiffZh(before, after store.DirUser) string {
	parts := []string{}
	if before.Name != after.Name {
		parts = append(parts, "姓名 "+pickStr(before.Name, "（空）")+" → "+pickStr(after.Name, "（空）"))
	}
	if before.Email != after.Email {
		parts = append(parts, "邮箱 "+pickStr(before.Email, "（空）")+" → "+pickStr(after.Email, "（空）"))
	}
	if len(parts) == 0 {
		return "无实际变化"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "；" + p
	}
	return out
}

// handleDeleteUser DELETE /api/v1/users/{id}（PermSecurity，与建号同权）。
//
// ★这是 License 席位的**唯一**释放路径：`license.go` 的注释、席位满时的 409 文案、
// 闲置治理弹窗的说明，三处都把管理员指向「删除闲置账号释放席位」，而在此之前
// 全仓没有任何删除账号的端点（`grep -rn DeleteUser` 只命中 DeleteUserGroup）。
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	uw, ok := s.writer.(userWriter)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前后端不支持删除用户")
		return
	}
	id := r.PathValue("id")
	target, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool { return du.ID == id })
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "用户不存在（可能已被删除）")
		return
	}
	// 删管理员须 admins 权（与重置口令、置状态同一道闸）——删掉一名审计管理员
	// 与禁用他同样是削弱制衡，且更彻底。
	if !s.guardAdminTarget(w, r, target, "删除账号") {
		return
	}
	// ★影响面**删之前**算，删之后就查不到了（同 handleDeleteResource / handleDeleteApp）。
	blast, _ := uw.UserDeleteBlastRadius(r.Context(), id)

	switch err := uw.DeleteUser(r.Context(), id); {
	case errors.Is(err, store.ErrUserNotFound):
		httpx.Error(w, http.StatusNotFound, "用户不存在（可能已被删除）")
		return
	case errors.Is(err, store.ErrLastRootAdmin):
		httpx.Error(w, http.StatusConflict,
			"这是最后一名可登录的超级管理员，删除后将没有任何人能进入管理台。请先新建一名超管。")
		return
	case err != nil:
		httpx.Error(w, http.StatusInternalServerError, "删除失败")
		return
	}
	// 被删的账号同时从内存封禁表里摘掉：它已经不存在了，留着只会让那条
	// 撤销记录在网关策略里永远续期（而 blockedAccounts 的目录并入已经不含他）。
	s.mu.Lock()
	delete(s.revoked, normUser(target.Account))
	s.mu.Unlock()

	s.audit(r, "admin", "删除账号「"+target.Name+"」("+target.Account+")；"+blast.Note(), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "account": target.Account,
		"note": blast.Note(), "resources": blast.Resources,
		"grants": blast.Grants, "devices": blast.Devices,
		"groupRefs": blast.GroupRefs, "mfa": blast.MFA,
		"seatsFreed": 1,
	})
}

// handleUserDeletePreview GET /api/v1/users/{id}/delete-preview（读，任意管理员现算角色）。
// 页面在弹确认框之前先问一次影响面——让人**在点之前**就看见会牵动什么。
func (s *Server) handleUserDeletePreview(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	uw, ok := s.writer.(userWriter)
	if !ok {
		httpx.JSON(w, http.StatusOK, map[string]any{"note": "当前后端不支持删除用户"})
		return
	}
	blast, err := uw.UserDeleteBlastRadius(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrUserNotFound) {
		httpx.Error(w, http.StatusNotFound, "用户不存在")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "影响面读取失败")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"account": blast.Account, "name": blast.Name, "note": blast.Note(),
		"resources": blast.Resources, "grants": blast.Grants,
		"devices": blast.Devices, "groupRefs": blast.GroupRefs, "mfa": blast.MFA,
		"seats": strconv.Itoa(1),
	})
}
