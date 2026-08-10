package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 组织与用户组管理（PRD ch6 FR-USER）。全部 admin，写操作落审计。──

// orgStoreErr 把 store 层的领域错误映射成人能看懂的 HTTP 应答。
// 删除守卫（有子部门 / 有成员）必须回 409 + 原因：回 500 的话管理员只会
// 反复重试，而真正该做的是先把人和子部门挪走。
func orgStoreErr(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, store.ErrOrgHasChildren), errors.Is(err, store.ErrOrgHasMembers),
		errors.Is(err, store.ErrGroupExists), errors.Is(err, store.ErrGroupDerived),
		errors.Is(err, store.ErrOrgInAuthPolicy), errors.Is(err, store.ErrGroupInAuthPolicy):
		httpx.Error(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrOrgCycle), errors.Is(err, store.ErrUnknownAccount):
		httpx.Error(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, store.ErrOrgNotFound), errors.Is(err, store.ErrGroupNotFound):
		httpx.Error(w, http.StatusNotFound, err.Error())
	default:
		httpx.Error(w, http.StatusInternalServerError, fallback)
	}
}

// handleOrgs 组织单元清单（扁平，带 parentId/path/sort 与直属成员数）。
// 展示树在 GET /api/v1/users 的 orgTree 里（那份带子树合计人数）。
func (s *Server) handleOrgs(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	orgs, err := s.store.OrgUnits(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load org units")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"orgs": orgs})
}

// handleSaveOrg 新增/修改组织单元（admin）。id 为空即新建。
func (s *Server) handleSaveOrg(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var o store.Org
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&o); err != nil || o.Name == "" {
		httpx.Error(w, http.StatusBadRequest, "组织名称不能为空")
		return
	}
	create := o.ID == ""
	saved, err := s.writer.SaveOrgUnit(r.Context(), o)
	if err != nil {
		orgStoreErr(w, err, "failed to save org unit")
		return
	}
	verb := "修改"
	if create {
		verb = "新建"
	}
	s.audit(r, "admin", verb+"组织「"+saved.Name+"」("+saved.ID+"，路径 "+saved.Path+")", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "org": saved})
}

// handleDeleteOrg 删除组织单元（admin）。有子部门或有成员时 409 拒删。
func (s *Server) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	if err := s.writer.DeleteOrgUnit(r.Context(), id); err != nil {
		// 审计只记已发生的事实：拒删也是一次发生过的事，但结果是 fail。
		s.audit(r, "admin", "删除组织 "+id+" 被拒："+err.Error(), "fail")
		orgStoreErr(w, err, "failed to delete org unit")
		return
	}
	s.audit(r, "admin", "删除组织 "+id, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// groupView 一个用户组 + 它当前的成员账号（角色组的成员是派生出来的）。
type groupView struct {
	store.UserGroup
	Members []string `json:"memberAccounts"`
}

// handleGroups 用户组清单（含成员账号，便于就地编辑成员）。
func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	gs, err := s.store.UserGroups(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user groups")
		return
	}
	out := make([]groupView, 0, len(gs))
	for _, g := range gs {
		mem, err := s.store.GroupMembers(r.Context(), g.ID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to load group members")
			return
		}
		out = append(out, groupView{UserGroup: g, Members: mem})
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"groups": out})
}

// handleSaveGroup 新增/修改用户组（admin）。
func (s *Server) handleSaveGroup(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var g store.UserGroup
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&g); err != nil || g.Name == "" {
		httpx.Error(w, http.StatusBadRequest, "用户组名称不能为空")
		return
	}
	if g.Kind == "" {
		g.Kind = store.GroupKindStatic
	}
	if !store.ValidGroupKind(g.Kind) {
		httpx.Error(w, http.StatusBadRequest, "kind 须为 static（显式成员）或 role（按用户角色派生）")
		return
	}
	create := g.ID == ""
	saved, err := s.writer.SaveUserGroup(r.Context(), g)
	if err != nil {
		orgStoreErr(w, err, "failed to save user group")
		return
	}
	verb := "修改"
	if create {
		verb = "新建"
	}
	s.audit(r, "admin", verb+"用户组「"+saved.Name+"」("+saved.ID+"，类型 "+saved.Kind+")", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "group": saved})
}

// handleDeleteGroup 删除用户组（admin），成员关系一并清除。
func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	if err := s.writer.DeleteUserGroup(r.Context(), id); err != nil {
		orgStoreErr(w, err, "failed to delete user group")
		return
	}
	s.audit(r, "admin", "删除用户组 "+id+"（成员关系一并清除）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleSetGroupMembers 全量覆写一个 static 组的成员（admin）。
func (s *Server) handleSetGroupMembers(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Accounts []string `json:"accounts"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "accounts 须为账号数组")
		return
	}
	if err := s.writer.SetGroupMembers(r.Context(), id, body.Accounts); err != nil {
		orgStoreErr(w, err, "failed to set group members")
		return
	}
	mem, err := s.store.GroupMembers(r.Context(), id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load group members")
		return
	}
	s.audit(r, "admin", "设置用户组 "+id+" 的成员，共 "+strconv.Itoa(len(mem))+" 人", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "memberAccounts": mem})
}

// handleSetUserMembership 改某用户的组织归属与所属用户组（admin）。
// orgId 传空串 = 清空归属；groups 省略则不动组关系（区别于传空数组 = 清空）。
func (s *Server) handleSetUserMembership(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		OrgID  *string   `json:"orgId"`
		Groups *[]string `json:"groups"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体须为 {orgId?, groups?}")
		return
	}
	u, found, err := s.lookupDirUser(r.Context(), func(du store.DirUser) bool { return du.ID == id })
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "用户不存在")
		return
	}
	if body.OrgID != nil {
		if err := s.writer.SetUserOrg(r.Context(), id, *body.OrgID); err != nil {
			orgStoreErr(w, err, "failed to set user org")
			return
		}
		s.audit(r, "admin", "用户「"+u.Name+"」("+u.Account+") 组织归属改为 "+pickStr(*body.OrgID, "（无归属）"), "ok")
	}
	if body.Groups != nil {
		if err := s.writer.SetUserGroups(r.Context(), u.Account, *body.Groups); err != nil {
			orgStoreErr(w, err, "failed to set user groups")
			return
		}
		s.audit(r, "admin", "用户「"+u.Name+"」("+u.Account+") 所属用户组更新为 "+
			strconv.Itoa(len(*body.Groups))+" 个", "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

func pickStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
