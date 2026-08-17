package store

import (
	"context"
	"errors"
	"strings"
)

// ── 外部身份准入闸（wave8 行动 10，PRD FR-AUTH-22 / FR-USER-13/14）──
//
// 改造前：外部认证源认证通过 = 立刻 `BindExternalUser` 建一个
// `role=user, status=active` 的本地账号，**没有任何开关、白名单或审批**，
// 建号本身也不落审计。
//
// 为什么这是个洞而不只是"少个功能"：自动建号的外部账号会落进「外部目录」组织单元，
// 而它的父是**第一个顶层组织**（种子里就是根 `root`），`OrgAccounts` 又是含全部
// 后代的展平——于是管理员把任一资源授权给根组织（「全员可访问 OA」这种最自然的操作），
// 即刻覆盖全部自动建号的外部账号。
//
// 失败场景是完整的一条链：接入公司 AD 或 IdP 后，AD 森林里**任意**能过 `userFilter`
// 的条目（服务账号、承包商、刚被 HR 建的号）或 IdP 里任意能完成一次授权码流的账号，
// 首登即自动获得白帝账号 + 门户会话 + OA 访问权——全程无审批、无告警、无审计。
//
// ★两道闸的**判定时机刻意不同**，这是本文件最容易写错的地方：
//   - **过滤闸（域/组白名单）每次登录都判**：目录侧把人移出允许组之后，下一次登录
//     就该被拒。只在首次判的话，「从组里移除」这个动作对已建号的人永远不生效。
//   - **审批闸只在首次建号时判**：已经批过的账号不必每次再批一遍。
//
// 反过来写（过滤只判首次 / 审批每次都判）的症状分别是"移出组了还能进"和
// "老用户每天都要管理员批一次"，前者是安全漏洞，后者是可用性事故。

// 外部身份准入策略（认证源配置项 admitPolicy）。
const (
	// AdmitAuto 认证通过即自动建号。**改造前的行为**，为向后兼容保留为默认值——
	// 但它是 PRD 明确要求可关闭的那一档，控制台上必须当面写清它意味着什么。
	AdmitAuto = "auto"
	// AdmitApproval 首次登录只登记一条待批准入单，管理员批准后下次登录才建号。
	AdmitApproval = "approval"
)

// ValidAdmitPolicy 报告准入策略取值是否合法。空串视为 AdmitAuto（存量配置）。
func ValidAdmitPolicy(p string) bool {
	switch strings.TrimSpace(p) {
	case "", AdmitAuto, AdmitApproval:
		return true
	}
	return false
}

// NormalizeAdmitPolicy 归一准入策略；空串/未知一律回 AdmitAuto。
//
// ★未知值回 auto 而不是 approval，是**向后兼容**的选择：存量库里的配置没有这一项，
// 若把未知当 approval，升级那一刻全体外部用户会被挡在门外且没人知道为什么。
// 入口有 ValidAdmitPolicy 把关，非法值进不了库。
func NormalizeAdmitPolicy(p string) string {
	if strings.TrimSpace(p) == AdmitApproval {
		return AdmitApproval
	}
	return AdmitAuto
}

// 准入单状态。
const (
	AdmitPending  = "pending"
	AdmitApproved = "approved"
	AdmitRejected = "rejected"
)

// ExtAdmission 一条外部身份的准入登记。
//
// ★它是**独立的表**而不是往 `approvals` 里塞：那张表的列是设备形状的
// （usr/device/fingerprint），把源名塞进 device、subject 塞进 fingerprint
// 会让列名说谎，而下一个读这张表的人没有任何提示。
// 管理员那一侧仍然只有一个审批收件箱——`approvals` 里同步生成一条 kind=extuser 的单子，
// 两者按 approval_id 关联（见 RequestExtAdmission）。
type ExtAdmission struct {
	SourceID string `json:"sourceId"`
	// SourceName 冗余存一份源名：审批页要显示"这个人来自哪个目录"，
	// 而认证源可能在批准前被改名甚至删掉。
	SourceName string `json:"sourceName"`
	// Subject 认证源侧的权威标识（OIDC sub / LDAP entryDN）。与 SourceID 一起是主键。
	Subject     string   `json:"subject"`
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Email       string   `json:"email"`
	Groups      []string `json:"groups"`
	Status      string   `json:"status"` // pending | approved | rejected
	// ApprovalID 关联的审批单 id（管理员在审批页看到的那条）。
	ApprovalID string `json:"approvalId"`
	CreatedAt  string `json:"createdAt"`
	DecidedAt  string `json:"decidedAt,omitempty"`
	DecidedBy  string `json:"decidedBy,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Admitted 报告这条登记是否已批准（可以建号）。
func (a ExtAdmission) Admitted() bool { return a.Status == AdmitApproved }

// ErrAdmitPending 该外部身份的准入单还在等管理员批准。
var ErrAdmitPending = errors.New("外部身份等待管理员批准准入")

// ErrAdmitRejected 该外部身份的准入被管理员拒绝过。
var ErrAdmitRejected = errors.New("外部身份的准入申请已被拒绝")

// ExtAdmitStore 外部身份准入登记的读写。
//
// 与 AuthSourceStore 分开一个接口：这几个方法只被登录链路与审批 handler 调用，
// 挂到大接口上等于让每个 handler 都够得着"批准某人进来"。
type ExtAdmitStore interface {
	// ExtAdmission 按 (源, subject) 查准入登记。
	ExtAdmission(ctx context.Context, sourceID, subject string) (ExtAdmission, bool, error)
	// RequestExtAdmission 登记一条待批准入（幂等：同 (源,subject) 已有登记则原样返回）。
	// created=true 表示这次真的新建了一条（调用方据此决定要不要落审计——
	// 每次登录都记一条会把审计冲成噪声，与 auditDeviceObserved 同一条理由）。
	RequestExtAdmission(ctx context.Context, a ExtAdmission) (ExtAdmission, bool, error)
	// DecideExtAdmission 按审批单 id 批准/拒绝一条准入。
	DecideExtAdmission(ctx context.Context, approvalID, decision, reason, by string) (ExtAdmission, error)
	// PendingExtAdmissions 待批准入清单（审批页用）。
	PendingExtAdmissions(ctx context.Context) ([]ExtAdmission, error)
}

// ── 域 / 组白名单（每次登录都判）──

// AdmitFilter 外部身份的准入过滤条件（认证源配置项）。空 = 不限。
type AdmitFilter struct {
	// Domains 允许的邮箱域（不带 @，大小写不敏感）。
	// ★对 OIDC 尤其要紧：一个允许任意 Google 账号完成授权码流的 IdP 配置，
	// 没有域白名单就等于对全互联网开放。
	Domains []string
	// Groups 允许的组（LDAP 的 GroupAttr / OIDC 的 groups claim，大小写不敏感）。
	Groups []string
}

// Empty 报告过滤条件是否为空（不限）。
func (f AdmitFilter) Empty() bool { return len(f.Domains) == 0 && len(f.Groups) == 0 }

// Allow 判定一个外部身份是否通过过滤。返回 (是否放行, 不放行的原因)。
//
// ★语义是**「配了就必须命中」**：域与组两项各自独立，配了哪项就必须过哪项，
// 两项都配则两项都要过（AND）。用 OR 的话，加一条组白名单反而会放宽域白名单——
// 管理员"再加一道限制"的动作变成了放松，这种反直觉的组合迟早出事。
//
// 判不了的情况一律**拒绝**（配了域白名单但身份没带邮箱 → 拒）：这是准入闸，
// fail-closed 是唯一正确的方向。
func (f AdmitFilter) Allow(email string, groups []string) (bool, string) {
	if len(f.Domains) > 0 {
		at := strings.LastIndex(email, "@")
		if at < 0 {
			return false, "认证源未返回邮箱，无法核对邮箱域白名单（准入闸 fail-closed）"
		}
		dom := strings.ToLower(strings.TrimSpace(email[at+1:]))
		if !containsFold(f.Domains, dom) {
			return false, "邮箱域 " + dom + " 不在该认证源的允许域白名单内"
		}
	}
	if len(f.Groups) > 0 {
		hit := ""
		for _, g := range groups {
			if containsFold(f.Groups, strings.TrimSpace(g)) {
				hit = g
				break
			}
		}
		if hit == "" {
			return false, "该账号不属于任何允许的组（认证源已配置组白名单）"
		}
	}
	return true, ""
}

// containsFold 大小写不敏感的成员判定（两侧都 TrimSpace）。
func containsFold(list []string, v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, x := range list {
		if strings.ToLower(strings.TrimSpace(x)) == v {
			return true
		}
	}
	return false
}

// NormalizeAdmitList 清洗白名单：去空、去重、trim。**不做小写归一**——
// 原样留着管理员填的形态供页面回显，比对时由 containsFold 大小写不敏感处理。
func NormalizeAdmitList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		k := strings.ToLower(v)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}
