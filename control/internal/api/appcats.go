package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 应用分类字典 REST（业务管理 → 应用管理页内维护）──
//
// 分类此前是编译进二进制的两个常量，管理员既加不了也改不了；这一组端点是它变成
// 真实数据之后的唯一维护入口。读=任意管理员（角色现算），写=PermSecurity——
// 与 POST /api/v1/apps 同一权：分类是应用的归属维度，能改分类就是在改应用管理面。

// appCatErr 把 store 的领域错误映射成人能看懂的应答。
// 删除守卫必须回 409 + 数量：回 500 的话管理员只会反复重试，而真正该做的是先挪应用。
func appCatErr(w http.ResponseWriter, err error, fallback string) {
	var inUse store.ErrAppCategoryInUse
	switch {
	case errors.As(err, &inUse):
		httpx.Error(w, http.StatusConflict, inUse.Error())
	case errors.Is(err, store.ErrAppCategoryExists), errors.Is(err, store.ErrAppCategoryBuiltin):
		httpx.Error(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrAppCategoryNotFound):
		httpx.Error(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrAppCategoryKey), errors.Is(err, store.ErrAppCategoryLabel):
		httpx.Error(w, http.StatusBadRequest, err.Error())
	default:
		httpx.Error(w, http.StatusInternalServerError, fallback)
	}
}

// handleAppCategories 分类字典清单（含各分类下的应用数）。
func (s *Server) handleAppCategories(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	cats, err := s.store.AppCategories(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load app categories")
		return
	}
	if cats == nil {
		cats = []store.AppCategoryDef{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"categories": cats})
}

// handleCreateAppCategory 新建自定义分类（PermSecurity）。
// 只收 key 与 label：sort 由 store 排到末尾，builtin 恒 false（见 CreateAppCategory）。
func (s *Server) handleCreateAppCategory(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var body struct {
		Key   string `json:"key"`
		Label string `json:"label"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid app category payload")
		return
	}
	created, err := s.writer.CreateAppCategory(r.Context(), store.AppCategoryDef{Key: body.Key, Label: body.Label})
	if err != nil {
		appCatErr(w, err, "failed to create app category")
		return
	}
	s.audit(r, "admin", "新建应用分类「"+created.Label+"」("+created.Key+")", "ok")
	httpx.JSON(w, http.StatusCreated, map[string]any{"ok": true, "category": created})
}

// handleUpdateAppCategory 改分类的名称与排序（PermSecurity）。内置分类同样可改。
// key 不可改：它是主键、且被 apps.category 按值引用，改它等于把一批应用悬空。
func (s *Server) handleUpdateAppCategory(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	key := r.PathValue("key")
	var body struct {
		Label string `json:"label"`
		Sort  int    `json:"sort"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid app category payload")
		return
	}
	before, after, err := s.writer.UpdateAppCategory(r.Context(), key, body.Label, body.Sort)
	if err != nil {
		appCatErr(w, err, "failed to update app category")
		return
	}
	// 审计只记已发生的事实，并且要能看出改前改后——「修改了分类 x」这种措辞
	// 在事后复盘时说明不了任何问题。
	msg := "修改应用分类 " + after.Key + "：名称「" + before.Label + "」→「" + after.Label + "」"
	if before.Sort != after.Sort {
		msg += "，排序 " + strconv.Itoa(before.Sort) + "→" + strconv.Itoa(after.Sort)
	}
	s.audit(r, "admin", msg, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "category": after})
}

// handleDeleteAppCategory 删除自定义分类（PermSecurity）。
// 内置拒删、分类下有应用拒删——两种拒绝都落一条 fail 审计（拒删也是发生过的事）。
func (s *Server) handleDeleteAppCategory(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	key := r.PathValue("key")
	if err := s.writer.DeleteAppCategory(r.Context(), key); err != nil {
		s.audit(r, "admin", "删除应用分类 "+key+" 被拒："+err.Error(), "fail")
		appCatErr(w, err, "failed to delete app category")
		return
	}
	s.audit(r, "admin", "删除应用分类 "+key, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "key": key})
}
