package store

import "context"

// 用户台账导出（wave7 行动 14 · 导出半边）。
//
// ★为什么单独一个结构体而不是复用 DirUser：DirUser 带着 PassHash / PwStrength /
// MustChangePw 三个**判定材料**字段。它们在 JSON 上靠 `json:"-"` 挡住，而 CSV 是
// 手写的列清单——挡不住任何东西，全靠写的人记得。既然导出是"把整份人员台账打成
// 一个文件带走"，那就让类型本身不持有那些字段：想在 CSV 里泄露口令哈希，得先改
// 这个结构体，而不是顺手多写一列。
//
// 落选字段与理由（都不是漏了）：
//   - pass_hash：一份能拿去离线爆破的哈希清单比明文清单更危险——它看起来"已脱敏"，
//     于是会被当成可以外发的东西。
//   - pw_strength：既是判定材料（认证策略的弱密码规则读它），也是一张"先打哪个账号"
//     的排序表。台账盘点不需要它。
//   - online / device / ip：users 表的这三列只在建号那一刻写过，登录登出都不更新
//     （见 store.Directory 的注释）。导出它们等于把一个冻结在建库时刻的值
//     写进一份叫"资产盘点"的文件里，比不导出更糟。
//   - auth（"密码+短信"）：建号时填的自由文本，不是权威的二次认证状态
//     （真实状态在 totp_secrets / webauthn_credentials 两张表）。
type UserExportRow struct {
	Account string
	Name    string
	// Org 组织显示名（org_units.name 优先，回落 users.org 那个展示遗物）；
	// OrgID 是可回填进导入文件的稳定键——同名部门可以存在于树的不同分支，
	// 只导名字的话，导出→改→导入这一圈会在同名处静默挑错部门。
	Org   string
	OrgID string
	// Groups 用户组**名**（含角色派生组）。导入侧只接受 static 组，派生组照实导出
	// 但导不回去——它由用户角色决定，不是可写的归属。
	Groups []string
	Status string // active | locked | disabled | idle
	Role   string // admin | user（权威鉴权角色）
	// AdminRole 三权分立的管理员角色 key。DirUser 上它是 `json:"-"`，**那是为了挡住
	// 写入方向**（从 POST /users 的请求体里塞一个 admin_role 进来 = 一次请求提权），
	// 不是因为它是秘密：系统页的管理员清单本来就展示它。台账盘点里"谁持有哪一权"
	// 恰恰是最该看清的一列。
	AdminRole string
	Email     string
	LastLogin string
	CreatedAt string
}

// UserExporter 流式导出用户台账的能力（只有 SQLiteStore 实现；Memory 种子无台账可盘）。
//
// ★逐行回调而不是返回 []UserExportRow：导出的调用方是一个 HTTP 附件响应，
// 整表进内存只为了立刻逐行写出去，没有任何收益——而用户数是随部署规模长的。
type UserExporter interface {
	ExportUsers(ctx context.Context, fn func(UserExportRow) error) error
}
