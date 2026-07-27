package store

import (
	"context"
	"errors"
)

// ── JIT 即时访问申请 / 时限授予（Just-in-Time Access）──
// 与烛龙无关，从 Teleport Access Requests 取形：终端用户对高敏资源自助申请 →
// 管理员审批 → 审批通过瞬时产生一条带 expires_at 的授予 → 数据面按授予临时放行 →
// 到期读时失效。方向与既有「撤销/封禁」相反：这是「临时授予」。
//
// 授予是带 expires_at 的一等实体（独立落库，可撤销/倒计时/跨重启保序），
// 但对网关的下发形态走「handleGatewayPolicy 出口 merge 进 resources[].AllowUsers」——
// 网关零改动，判定权全在控制面。

// 授予时长边界（分钟）。上限与会话令牌 tokenTTL(8h) 对齐——JIT 不该比一次登录还长。
const (
	MinGrantTTL = 15
	MaxGrantTTL = 480
)

// ClampGrantTTL 把授予时长钳到 [MinGrantTTL, MaxGrantTTL]，杜绝 ttl<=0（出生即过期）
// 与超大 ttl（等同永久授权、违背 JIT 立意）。api 层 create/decide 两路都经此。
func ClampGrantTTL(m int) int {
	if m < MinGrantTTL {
		return MinGrantTTL
	}
	if m > MaxGrantTTL {
		return MaxGrantTTL
	}
	return m
}

var (
	// ErrDuplicateRequest 同 (账号,资源) 已有待审批申请或未到期授予，拒绝重复提交（防连点堆叠 → 双授予）。
	ErrDuplicateRequest = errors.New("已有待审批申请或有效授予")
	// ErrRequestDecided 申请单已被处置（并发二次审批的守卫命中 0 行时返回），调用方回 409。
	ErrRequestDecided = errors.New("申请已处置")
	// ErrSelfApprove 审批人即申请人，职责分离(SoD)最低闸拒绝——防 admin 自申请自批准。
	ErrSelfApprove = errors.New("不能审批自己提交的申请")
	// ErrGrantInactive 授予不存在或已非 active（撤销/到期），无可撤销。
	ErrGrantInactive = errors.New("授予不存在或已失效")
)

// AccessRequest 一条 JIT 访问申请（终端用户对高敏资源的自助申请单）。
type AccessRequest struct {
	ID           string          `json:"id"`
	User         string          `json:"user"`         // 申请人规范化账号
	ResourceID   string          `json:"resourceId"`   // 关联 resources.id（由磁贴 app.resource_id 解析而来）
	ResourceName string          `json:"resourceName"` // 冗余展示
	Reason       string          `json:"reason"`
	TTLMinutes   int             `json:"ttlMinutes"`
	Status       string          `json:"status"` // pending | approved | rejected
	Timeline     []ApprovalEvent `json:"timeline"`
	SubmittedAt  string          `json:"submittedAt"`
	DecidedAt    string          `json:"decidedAt"`
	DecideReason string          `json:"decideReason"`
	DecidedBy    string          `json:"decidedBy"` // 审批 admin
	GrantID      string          `json:"grantId"`   // 审批通过回填的 jit_grants.id
}

// JitGrant 一条时限访问授予（审批通过瞬时创建，到期读时失效；跨 control 重启保序，故落 SQLite）。
type JitGrant struct {
	ID           string `json:"id"`
	User         string `json:"user"`       // 被授予人规范化账号
	ResourceID   string `json:"resourceId"` // 关联 resources.id
	ResourceName string `json:"resourceName"`
	RequestID    string `json:"requestId"` // 来源 access_requests.id
	Reason       string `json:"reason"`
	GrantedBy    string `json:"grantedBy"`
	GrantedAt    int64  `json:"grantedAt"` // unix 秒
	ExpiresAt    int64  `json:"expiresAt"` // unix 秒（TTL 到期闸；now>=expiresAt 即失效）
	Status       string `json:"status"`    // active | revoked | expired
	RevokedAt    int64  `json:"revokedAt"`
	RevokeReason string `json:"revokeReason"`
}

// ── Memory 空实现（真实数据域：无种子，只有 SQLite 覆盖版承载真实数据）──

func (m *Memory) AccessRequests(context.Context) ([]AccessRequest, error) {
	return []AccessRequest{}, nil
}
func (m *Memory) AccessRequestsFor(context.Context, string) ([]AccessRequest, error) {
	return []AccessRequest{}, nil
}
func (m *Memory) JitGrants(context.Context) ([]JitGrant, error)    { return []JitGrant{}, nil }
func (m *Memory) ActiveGrants(context.Context) ([]JitGrant, error) { return []JitGrant{}, nil }
func (m *Memory) ActiveGrantsFor(context.Context, string) ([]JitGrant, error) {
	return []JitGrant{}, nil
}
