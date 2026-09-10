package store

import (
	"context"
	"strings"
	"time"
)

// 会话令牌注销（wave11 行动 4，FR-SYSCFG-09 / FR-SYSCFG-11 / FR-MON-13）。
//
// ★为什么需要它：控制面的入站中间件 `auth.Middleware` 只验签名与用途白名单，
// 不查任何库、没有吊销表；`AdminRoleFor` 的 SQL 只筛 `u.role='admin'` **不筛 `u.status`**；
// `requireUser` 更是纯令牌判定。于是四条处置——禁用、锁定、强制下线、闲置自动锁定——
// 对**已经签发出去**的令牌全部无效：
//
//	管理员账号被盗后的标准处置就是点「禁用」。点完之后控制台显示已禁用、审计也记了
//	一条，而攻击者手里那张 8h 令牌在最长八小时里仍是完整管理员：改资源策略、批 JIT、
//	读全量在线会话与用户目录，写操作照过 requirePerm。
//
// 数据面那一侧本来就有执行方（entryGates 查 accountBlocked、撤销通道下发到网关），
// 所以这个洞的形状很隐蔽：**隧道当场断了，管理 API 却还开着**。
//
// ★三条设计约束（写在这里，免得下一个人"顺手优化"）：
//
//  1. **判据落库，不放内存**。`api.Server.revoked` 那张表是内存的，进程重启即失，
//     方向是 fail-open。而这条判据必须活过重启。
//  2. **不做成通用 JWT 吊销表**。按 jti 存黑名单要求每个请求都查一次库并随令牌数增长，
//     会把控制面变成同步瓶颈；按账号存一个时间下限是 O(1) 且与既有的按账号取数合并。
//  3. **不做成全局值**（例如一个 settings 键 "所有令牌在此之后才有效"）。那样任何一次
//     针对某个人的处置都会把**全体管理员**一起踢下线，而现场看起来像是系统崩了。
type revokeWriter interface {
	RevokeUserSessions(ctx context.Context, account string, at time.Time) error
}

// RevokeUserSessions 把该账号的会话令牌下限推到 at：签发时刻早于 at 的令牌一律失效。
//
// **只往前推，不倒退**（`MAX(既有值, at)`）：倒退会让一次「禁用 → 恢复 → 再禁用」的
// 中间态把前一次处置的效力抹掉。恢复账号**不清这个值**——那会让攻击者手里那张旧令牌
// 在账号解禁的同一刻复活；解除的正确方式只有一次完整的重新登录（新令牌的 iat 自然更大）。
func (s *SQLiteStore) RevokeUserSessions(ctx context.Context, account string, at time.Time) error {
	key := strings.ToLower(strings.TrimSpace(account))
	if key == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET tokens_valid_after = MAX(COALESCE(tokens_valid_after,0), ?)
		  WHERE lower(trim(account))=?`, at.Unix(), key)
	return err
}

// RevokeUserSessions Memory 后端不承载真实处置（没有 users 表的写侧），空实现。
// ★注意这不是"忘了实现"：Memory 是未起后端时控制台降级演示用的，那条路径上
// 不存在"已签发的令牌"这个概念。真实现只有 SQLiteStore 一份。
func (m *Memory) RevokeUserSessions(_ context.Context, _ string, _ time.Time) error { return nil }
