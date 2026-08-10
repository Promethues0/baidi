package store

// ── 登录防爆破锁定（PRD ch5 FR-MON-17/18 + ch20 NFR-SEC-06）──
//
// 滑动窗失败计数在内存（internal/lockout.Guard），丢了顶多重数几次；
// 锁定记录必须落库（login_lockouts 表）——重启不丢锁定，否则重启就是攻击者的解锁按钮。

// 锁定维度：账号 / 源 IP。
const (
	LockKindAccount = "account"
	LockKindIP      = "ip"
)

// Lockout 一条生效中的登录防爆破锁定。
// Key 的口径：account 维度存规范化账号（normUser，锁定对目录中不存在的账号同样生效——
// 这也是「锁定响应不泄露账号是否存在」的前提）；ip 维度存 clientIP 判定后的源 IP。
type Lockout struct {
	Kind      string `json:"kind"`      // account | ip
	Key       string `json:"key"`       // 规范化账号 / 源 IP
	Until     int64  `json:"until"`     // 锁定截止 Unix 秒
	Reason    string `json:"reason"`    // 触发事实（如「10 分钟内连续 5 次登录失败」）
	CreatedAt string `json:"createdAt"` // 触发时刻（展示用）
}
