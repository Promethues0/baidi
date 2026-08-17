package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 外部身份准入闸（wave8 行动 10，FR-AUTH-22 / FR-USER-13/14）──
//
// 改造前：外部认证源认证通过 = 立刻建一个 `role=user, status=active` 的本地账号，
// 没有任何开关、白名单或审批，建号本身也不落审计。为什么这是个洞（自动建号的外部
// 账号落进「外部目录」单元，其父是第一个顶层组织 = 种子里的根，而组织授权含全部
// 后代 → 授权给根组织即刻覆盖全部自动建号的外部账号），见 store/extadmit.go 头部。
//
// 这里是**判定与编排**；数据模型与两道闸的时机纪律在 store 侧。

// extAdmitStore 取 store 的准入登记能力；未实现（纯 Memory）时返回 nil。
func (s *Server) extAdmitStore() store.ExtAdmitStore {
	if as, ok := s.store.(store.ExtAdmitStore); ok {
		return as
	}
	return nil
}

// admitVerdict 一次准入判定的结论。
type admitVerdict struct {
	// Allowed 放行（可以建号 / 可以继续登录）。
	Allowed bool
	// Reason 不放行的原因（回给用户与审计；措辞只说已发生的事实）。
	Reason string
	// Pending 已登记待批准入单（Allowed=false 时才有意义）。
	Pending bool
	// NewTicket 这次真的新建了一条待批单（调用方据此决定要不要落审计——
	// 每次登录都记一条会把审计冲成噪声）。
	NewTicket bool
	// ApprovalID 关联的审批单 id（Pending 时非空，回给用户便于报给管理员）。
	ApprovalID string
}

// admitExternal 判定一个刚认证通过的外部身份能不能进来。
//
// ★调用时机：**认证通过之后、BindExternalUser 之前**。放在建号之后就晚了——
// 账号已经存在、已经落进组织树、已经被组织授权覆盖到了。
//
// bound 表示这个 subject 在白帝**已有账号**（UserBySubject 命中）。
func (s *Server) admitExternal(ctx context.Context, rec store.AuthSourceRec,
	id authsrc.Identity, bound bool) admitVerdict {

	cfg := admitCfgOf(rec)

	// ── 闸一：域/组白名单，**每次登录都判** ──
	// 目录侧把人移出允许组之后，下一次登录就该被拒。只在首次判的话，
	// 「从组里移除」这个动作对已建号的人永远不生效。
	if ok, why := cfg.filter().Allow(id.Email, id.Groups); !ok {
		return admitVerdict{Reason: why}
	}

	// ── 闸二：审批，**只在首次建号时判** ──
	// 已经批过（= 已有账号）的人不必每次再批一遍，否则老用户每天都要管理员点一次。
	if bound {
		return admitVerdict{Allowed: true}
	}
	if store.NormalizeAdmitPolicy(cfg.AdmitPolicy) == store.AdmitAuto {
		return admitVerdict{Allowed: true}
	}

	as := s.extAdmitStore()
	if as == nil {
		// ★配了 approval 却没有落库能力：拒绝而不是放行。
		// 这道闸的语义是"默认禁止"，判不了就不该进——与其余 fail-closed 同向。
		slog.Error("认证源配置了准入审批，但当前存储后端不支持准入登记：一律拒绝",
			"源", rec.Name, "id", rec.ID)
		return admitVerdict{Reason: "该认证源要求管理员批准准入，但当前存储后端不支持准入登记，无法受理"}
	}
	adm, created, err := as.RequestExtAdmission(ctx, store.ExtAdmission{
		SourceID: rec.ID, SourceName: rec.Name, Subject: id.Subject,
		Username: id.Username, DisplayName: id.DisplayName, Email: id.Email, Groups: id.Groups,
	})
	if err != nil {
		slog.Error("准入登记失败", "源", rec.Name, "subject", id.Subject, "err", err.Error())
		return admitVerdict{Reason: "准入登记失败，请稍后重试或联系管理员"}
	}
	switch adm.Status {
	case store.AdmitApproved:
		// 管理员批过了：放行，本次登录建号。
		return admitVerdict{Allowed: true}
	case store.AdmitRejected:
		why := "该账号的准入申请已被管理员拒绝"
		if strings.TrimSpace(adm.Reason) != "" {
			why += "：" + adm.Reason
		}
		return admitVerdict{Reason: why, ApprovalID: adm.ApprovalID}
	}
	return admitVerdict{
		Reason:  "该账号尚未获准接入白帝，已提交准入申请，请联系管理员批准（申请单 " + adm.ApprovalID + "）",
		Pending: true, NewTicket: created, ApprovalID: adm.ApprovalID,
	}
}

// admitCfgOf 从一条认证源配置里取准入设置。
//
// ★解析失败回**空配置**（= auto + 不限）而不是拒绝：这个函数在登录热路径上，
// 一条脏配置不该把整个源的用户全挡在门外。配置的合法性由保存入口把关
// （handleSaveAuthSource 校验 admitPolicy 枚举），这里是最后一道兜底。
func admitCfgOf(rec store.AuthSourceRec) admitConfigDTO {
	var c struct {
		admitConfigDTO
	}
	if err := json.Unmarshal([]byte(rec.Config), &c); err != nil {
		slog.Warn("认证源配置解析失败，准入设置按默认（自动建号、不限域/组）处理",
			"源", rec.Name, "id", rec.ID, "err", err.Error())
		return admitConfigDTO{}
	}
	return c.admitConfigDTO
}

// mergeAdmitCfg 把清洗后的准入设置写回配置 JSON（其余字段原样保留）。
//
// ★用 map 原样保留其余键，而不是解成 DTO 再序列化：DTO 一旦漏声明某个字段，
// 那次保存就会把它从库里抹掉——「改了 A 设置，B 设置莫名其妙没了」，
// 而两边都不报错。
func mergeAdmitCfg(cfg, policy string, domains, groups []string) (string, error) {
	m := map[string]any{}
	if err := json.Unmarshal([]byte(cfg), &m); err != nil {
		return "", err
	}
	m["admitPolicy"] = store.NormalizeAdmitPolicy(policy)
	m["allowedDomains"] = domains
	m["allowedGroups"] = groups
	out, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// auditAdmitDenied 落一条准入拒绝审计。
//
// ★这是本行动补上的另一半：改造前**建号本身都不落审计**，更不用说拒绝。
// 「谁在什么时候被挡在门外、为什么」是外部目录接入之后最需要回答的问题。
func (s *Server) auditAdmitDenied(r *http.Request, rec store.AuthSourceRec, id authsrc.Identity, v admitVerdict) {
	verdict := "deny"
	what := "拒绝外部身份接入"
	if v.Pending {
		// 待批不是拒绝，是"还没批"——审计里必须分得开，否则管理员会以为
		// 有人在被系统挡，而实际上是在等他自己动手。
		verdict, what = "fail", "外部身份等待准入批准"
	}
	s.auditAs(r, orElse(id.Username, id.Subject), "auth", fmt.Sprintf(
		"%s：认证源「%s」认证通过，但%s（subject %s）", what, rec.Name, v.Reason, shortSubject(id.Subject)), verdict)
}

// auditExtUserCreated 落一条外部账号建号审计。
//
// 改造前建号完全不留痕：一个外部账号什么时候出现在 users 表里、由哪个源带进来，
// 事后无从追查。这条在**每次真的建了号**时记（已存在的绑定不记，见调用点）。
func (s *Server) auditExtUserCreated(r *http.Request, rec store.AuthSourceRec, id authsrc.Identity, account string) {
	s.auditAs(r, account, "admin", fmt.Sprintf(
		"外部认证源自动建号：账号 %s 由认证源「%s」带入（subject %s，用户名 %s）。"+
			"该账号 role=user、无本地口令；组织归属为「外部目录」——"+
			"注意授权给上级组织会覆盖它（组织授权含全部后代）",
		account, rec.Name, shortSubject(id.Subject), orElse(id.Username, "—")), "ok")
}

// shortSubject subject 的可读短形（entryDN 可能很长；它不是秘密，截断只为可读）。
func shortSubject(sub string) string {
	if len(sub) <= 48 {
		return sub
	}
	return sub[:48] + "…"
}

// ── 审批端点：外部准入 ──

// handlePendingExtAdmissions GET /api/v1/authsrc/admissions（PermSecurity）：待批准入清单。
//
// 权限归 PermSecurity 而不是 PermSystem：这是"谁能进来"的判断，与认证源、
// 策略、资源授权同属安全管理员职责。
func (s *Server) handlePendingExtAdmissions(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	as := s.extAdmitStore()
	if as == nil {
		httpx.JSON(w, http.StatusOK, map[string]any{"admissions": []store.ExtAdmission{}})
		return
	}
	list, err := as.PendingExtAdmissions(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "读取待批准入失败")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"admissions": list})
}

// handleDecideExtAdmission POST /api/v1/authsrc/admissions/{id}/decide（PermSecurity）。
//
// ★批准**不建号**：只把登记置为 approved，账号在该用户下次登录时才建。
// 这样建号用的是登录那一刻的真实身份（组/邮箱/显示名可能已变），
// 而不是申请时的快照；也避免了"批了一批人、其中一半再也没登录过"留下一堆空账号。
func (s *Server) handleDecideExtAdmission(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	as := s.extAdmitStore()
	if as == nil {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储后端不支持准入登记")
		return
	}
	var body struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body)
	if body.Decision != store.AdmitApproved && body.Decision != store.AdmitRejected {
		httpx.Error(w, http.StatusBadRequest, "decision 取值须为 approved|rejected")
		return
	}
	adm, err := as.DecideExtAdmission(r.Context(), r.PathValue("id"), body.Decision, body.Reason, actorOf(r))
	switch {
	case errors.Is(err, store.ErrApprovalNotFound):
		httpx.Error(w, http.StatusNotFound, "准入申请单不存在")
		return
	case errors.Is(err, store.ErrApprovalDecided):
		httpx.Error(w, http.StatusConflict, "该准入申请已处置，不能重复处置")
		return
	case err != nil:
		httpx.Error(w, http.StatusInternalServerError, "处置准入申请失败")
		return
	}
	zh := "批准"
	verdict := "ok"
	if adm.Status == store.AdmitRejected {
		zh, verdict = "拒绝", "deny"
	}
	// 措辞只说已发生的事实：批准的是"准入资格"，账号要等他下次登录才建。
	s.audit(r, "security", fmt.Sprintf(
		"%s外部身份准入：认证源「%s」的 %s（subject %s）。%s",
		zh, adm.SourceName, orElse(adm.Username, "—"), shortSubject(adm.Subject),
		map[bool]string{true: "该身份下次登录时才会建号", false: "该身份此后登录一律被拒"}[adm.Status == store.AdmitApproved],
	), verdict)
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "admission": adm})
}
