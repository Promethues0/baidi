package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── 认证源接入 · 管理端点（全部 requireAdmin）──
//
//	GET    /api/v1/authsrc            列表（不含任何凭据原文）
//	POST   /api/v1/authsrc            新增 / 修改
//	DELETE /api/v1/authsrc/{id}       删除（连同凭据与身份绑定）
//	PUT    /api/v1/authsrc/{id}/secret  设置凭据（只写不读）
//	POST   /api/v1/authsrc/{id}/probe   连通性自检（控制台「测试连接」按钮）
//
// ★这一页此前是**纯内存种子**：6 条硬编码认证源，连「总部 AD 域 1160 用户」
// 这个数字都是凭空写的，「接入认证源 / 同步」按钮背后没有任何东西。

// authSrcWriter 是本文件需要的写能力（与 login_authsrc.go 的读接口分开，
// 让"能改配置"和"能读密文"是两组不同的能力）。
type authSrcWriter interface {
	authSourceStore
	AuthSourceByID(ctx context.Context, id string) (store.AuthSourceRec, bool, error)
	SaveAuthSource(ctx context.Context, rec store.AuthSourceRec) (store.AuthSourceRec, error)
	DeleteAuthSource(ctx context.Context, id string) error
	SaveAuthSourceSecret(ctx context.Context, sec store.AuthSourceSecret) error
}

func (s *Server) authSrcWriter(w http.ResponseWriter) (authSrcWriter, bool) {
	aw, ok := s.store.(authSrcWriter)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储实现不支持认证源")
		return nil, false
	}
	return aw, true
}

// handleAuthSources 认证源清单。
//
// ★响应里**永远不含**凭据原文，只有 hasSecret + 指纹前 8 位——
// 指纹的用途是让管理员核对"两端配的是不是同一把"，回显原文没有任何操作价值
// （配错了重设即可），只有泄露面。与 IPSec PSK 同款姿态。
func (s *Server) handleAuthSources(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	recs, err := aw.AuthSources(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth sources")
		return
	}
	// 顺带告诉前端哪些类型是真的实现了——控制台据此把未实现的选项置灰，
	// 而不是让它们看起来可选。
	supported := []string{}
	for _, k := range []authsrc.Kind{authsrc.KindLocal, authsrc.KindLDAP, authsrc.KindAD, authsrc.KindOIDC} {
		supported = append(supported, string(k))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"sources": recs, "supportedKinds": supported})
}

// handleSaveAuthSource 新增 / 修改认证源。
func (s *Server) handleSaveAuthSource(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	var b struct {
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		Kind     string          `json:"kind"`
		Enabled  bool            `json:"enabled"`
		Priority int             `json:"priority"`
		Config   json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || strings.TrimSpace(b.Name) == "" {
		httpx.Error(w, http.StatusBadRequest, "name 必填")
		return
	}
	kind := authsrc.Kind(strings.TrimSpace(b.Kind))
	if !kind.Supported() {
		// ★装载期明确拒绝，而不是存下来再在登录时静默失败。
		// 「界面上能选、后端静默不生效」是本项目反复吃亏的形态。
		httpx.Error(w, http.StatusBadRequest,
			"认证源类型 "+b.Kind+" 本版本未实现（当前支持：local / ldap / ad / oidc）")
		return
	}
	if kind == authsrc.KindLocal && b.ID != "local" {
		httpx.Error(w, http.StatusBadRequest, "本地目录是内置认证源，不能再新建一条")
		return
	}
	cfg := "{}"
	if len(b.Config) > 0 {
		cfg = string(b.Config)
	}
	rec, err := aw.SaveAuthSource(r.Context(), store.AuthSourceRec{
		ID: b.ID, Name: b.Name, Kind: string(kind), Enabled: b.Enabled, Priority: b.Priority, Config: cfg,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save auth source")
		return
	}
	// ★保存即校验：配置写错了要当场知道，而不是等到有人登录不上才发现。
	// 构造失败不拒绝保存（管理员可能正分几步填），但把原因带回去。
	var warn string
	if kind != authsrc.KindLocal {
		if _, berr := s.buildProvider(r.Context(), rec); berr != nil {
			warn = "配置已保存，但当前还不可用：" + berr.Error()
		}
	}
	s.audit(r, "admin", "保存认证源「"+rec.Name+"」（"+rec.Kind+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "source": rec, "warning": warn})
}

func (s *Server) handleDeleteAuthSource(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := aw.DeleteAuthSource(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	// ★删除会连同身份绑定一起清掉，所以要在审计里说清楚——
	// 那些外部用户下次登录会被重新建号，运维需要知道这是预期行为。
	s.audit(r, "admin", "删除认证源 "+id+"（连同其身份绑定）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleSetAuthSourceSecret 设置认证源凭据（LDAP bind 口令 / OIDC client_secret）。
//
// **只写不读**：没有任何端点能把它读回去。
func (s *Server) handleSetAuthSourceSecret(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	rec, found, err := aw.AuthSourceByID(r.Context(), id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth source")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "认证源不存在")
		return
	}
	var b struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if strings.TrimSpace(b.Secret) == "" {
		// ★空凭据必须拒绝。LDAP 里"有 DN + 空口令"会被许多目录当成**匿名 bind
		// 并返回成功**，于是"以为在用服务账号搜索、实际是匿名"——症状是部分用户
		// 查不到，而 bind 日志显示成功。宁可不让存。
		httpx.Error(w, http.StatusBadRequest, "凭据不能为空（空口令在 LDAP 上会退化成匿名 bind 并"+
			"看起来成功，这是经典的认证绕过）")
		return
	}
	box, err := secret.Default()
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "凭据主密钥不可用："+err.Error())
		return
	}
	// AAD 绑认证源 id：把某一行密文剪贴到另一条源上会直接解不开。
	nonce, cipher, err := box.Seal(rec.ID, []byte(b.Secret))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "凭据加密失败")
		return
	}
	fp := box.Fingerprint([]byte(b.Secret))[:8]
	if err := aw.SaveAuthSourceSecret(r.Context(), store.AuthSourceSecret{
		SourceID: rec.ID, Nonce: nonce, Cipher: cipher, Fingerprint: fp,
	}); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save secret")
		return
	}
	s.audit(r, "admin", "更新认证源「"+rec.Name+"」的凭据", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true,
		// 指纹供两端核对，绝不回显原文。
		"fingerprint": fp,
	})
}

// handleProbeAuthSource 连通性自检（控制台「测试连接」按钮的后端）。
//
// ★这个按钮此前是纯装饰。现在它真的去连目录 / 拉发现文档，
// 并把**真实**失败原因回给管理员——「配置写错了」和「网络不通」在这里能分开。
func (s *Server) handleProbeAuthSource(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	aw, ok := s.authSrcWriter(w)
	if !ok {
		return
	}
	rec, found, err := aw.AuthSourceByID(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load auth source")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "认证源不存在")
		return
	}
	if authsrc.Kind(rec.Kind) == authsrc.KindLocal {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "detail": "本地目录（SQLite）始终可用"})
		return
	}

	// 自检要有上界：目录不可达时 TCP 连接可能吊很久，让管理员盯着一个转圈的按钮
	// 等 30 秒毫无意义，也会占着一个 handler。
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	prov, err := s.buildProvider(ctx, rec)
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": err.Error()})
		return
	}
	type prober interface{ Probe(context.Context) error }
	p, okp := prov.(prober)
	if !okp {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": "该类型不支持连通性自检"})
		return
	}
	start := time.Now()
	if err := p.Probe(ctx); err != nil {
		s.audit(r, "admin", "测试认证源「"+rec.Name+"」连通性失败", "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": err.Error()})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "detail": "连接正常", "elapsedMs": time.Since(start).Milliseconds(),
	})
}
