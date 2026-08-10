package store

import "context"

// ── 审计日志外送（PRD ch16 + ch21.6）──
//
// # 为什么是「队列表」而不是「audit_log 上加一列 forwarded」
//
// 两条路都能做，但加列那条有一个必须自己处理的坑：补列迁移只加列不填值，
// 既有行的 forwarded 永久为 NULL，读侧一旦把 NULL 当"未外送"，
// **开启外送的那一刻就会把 180 天历史整段重发**（对面 SIEM 收到一夜之间几十万条
// 时间戳全是历史的记录，且没人能立刻说清是入侵还是 bug）。
// 加列必须配一次性回填把既有行标成已处理——而这正是本项目栽过的那类回填。
//
// 独立队列表把这件事变成结构性成立的：**队列只在审计落库那一刻写入**，
// 历史行从来不进队列，于是"不重发历史"不需要任何回填、也不可能被下一个改代码的人破坏。
// 代价是多一张表；收益是少一个只在升级时暴露、且暴露即事故的失效模式。
//
// # 多目标：一条审计 × 一个启用中的出口 = 一行队列
//
// 按目标分行而不是共用一行，是为了让每个出口的重试与退避互不影响。
// 共用一行的话，一个挂掉的出口会把另一个正常出口的进度也卡住
// （因为"这一行发完了没有"取决于最慢的那个）。

// AuditForwardTarget 一个审计外送出口。
//
// ★凭据（HTTP 出口的 Authorization 头值）**不在这个结构体里**：
// 它走 audit_forward_secrets 独立表加密落盘，只写不读（同 notify / authsrc / ipsec）。
type AuditForwardTarget struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`    // syslog | http
	Enabled bool   `json:"enabled"` // 管理意图：关掉即不再入队、也不再发送
	// Config 该类型的非敏感配置 JSON（主机/端口/TLS/CA/URL…）。
	// 敏感项一律不在这里——放进来就等于绕开了上面那道分表。
	Config string `json:"config"`

	// HasSecret / SecretFingerprint 是只写不读语义下的唯一回显。
	HasSecret         bool   `json:"hasSecret"`
	SecretFingerprint string `json:"secretFingerprint,omitempty"`

	// StartAuditID 建立该出口时 audit_log 的最大 id。
	//
	// ★它存在的唯一理由是**把"历史不会补发"这件事说出来**：管理员配好外送后，
	// SIEM 里只会出现这个 id 之后产生的审计。不显式告诉他的话，"新装的 SIEM 里
	// 为什么没有上个月的日志"会被当成外送坏了，进而有人去手工"补一遍"。
	StartAuditID int64 `json:"startAuditId"`

	// ── 上次发送结果。★只由**真正发出那一次**写入（api 层的 pump / 测试按钮），
	// 保存配置、翻转开关都不许碰它（与 notify_channels 的 last_* 同一条纪律）。
	LastStatus string `json:"lastStatus,omitempty"` // ok | fail（空 = 从未发过）
	LastDetail string `json:"lastDetail,omitempty"`
	LastAt     int64  `json:"lastAt,omitempty"`   // 上一次尝试（无论成败）
	LastOKAt   int64  `json:"lastOkAt,omitempty"` // 上一次**成功**
	// Dropped 队列满时被丢弃的审计条数（累计，落库）。
	// ★丢弃必须能被看见：这个数字就是「我没在 SIEM 里看到那条」与
	// 「压根没发生过那件事」之间唯一的分辨依据。
	Dropped int64 `json:"dropped"`

	// Queued 当前积压条数。**读时现算**（COUNT 队列表），不落列——
	// 落列就要在每次入队/出队维护它，而计数器写漏一次就永远对不上，
	// 且对不上的方向通常是"显示 0、其实堆着"。
	Queued int `json:"queued"`

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// AuditForwardSecret 一条加密落盘的出口凭据（AES-256-GCM，AAD 绑 target id）。
type AuditForwardSecret struct {
	TargetID string
	Nonce    []byte
	Cipher   []byte
	// Fingerprint 凭据的截断哈希（前 8 位），由写入方算好存进来——
	// 读列表时解密算指纹会在一条人人可读的路径上引入解密调用，与"只写不读"自相矛盾。
	Fingerprint string
}

// AuditForwardItem 队列里的一条待外送记录。
type AuditForwardItem struct {
	ID       int64
	TargetID string
	// Entry 就是要送出去的那条审计（与 /audit 列表、CSV 导出同一个结构体）。
	Entry AuditEntry
	// Attempts 已失败次数（决定退避档位）。
	Attempts int
}

// 外送结果取值（与 notify 同口径，控制台共用一套上色）。
const (
	AuditForwardOK   = "ok"
	AuditForwardFail = "fail"
)

// DefaultForwardQueueMax 每个出口的队列上界（条）。
//
// 2 万条 ≈ 一台中等负载控制面几天的审计量，足够扛住一次周末的 SIEM 停机；
// 再大就该考虑"是不是根本没人在看那台收集器了"。上界必须有：
// 没有上界的话，一个连不上的出口会让 SQLite 无声地涨到把磁盘写满，
// 而磁盘写满会让**审计本身**落不了库——为了不丢外送反而丢了审计，方向完全反了。
const DefaultForwardQueueMax = 20000

// AuditForwardStore 审计外送的读写。
//
// ★与 NotifyStore 同款考虑：「读凭据密文」这种只该被一两个调用点用到的能力
// 收在独立接口里，不挂到人人可得的 Writer 上；也因此它**不进 Store 接口**——
// Store 的每个方法都得有 Memory 演示实现，而外送出口没有"演示数据"这回事
// （编一条假的 SIEM 地址比空着更坏：看起来审计已经外送了）。
type AuditForwardStore interface {
	AuditForwardTargets(ctx context.Context) ([]AuditForwardTarget, error)
	AuditForwardTargetByID(ctx context.Context, id string) (AuditForwardTarget, bool, error)
	SaveAuditForwardTarget(ctx context.Context, rec AuditForwardTarget) (AuditForwardTarget, error)
	DeleteAuditForwardTarget(ctx context.Context, id string) error
	SaveAuditForwardSecret(ctx context.Context, sec AuditForwardSecret) error
	// AuditForwardSecret 取凭据密文。★调用点必须极少：只有"构造 Forwarder"这一处。
	AuditForwardSecret(ctx context.Context, id string) (AuditForwardSecret, bool, error)

	// ClaimAuditForwardBatch 取一批到期可发的记录（按队列 id 升序 = 审计落库序）。
	// 顺序是硬要求：seq 乱序到达会让 SIEM 侧的链校验白做。
	ClaimAuditForwardBatch(ctx context.Context, targetID string, now int64, limit int) ([]AuditForwardItem, error)
	// AckAuditForwardBatch 整批出队（**只在真的发送成功之后**调用）。
	AckAuditForwardBatch(ctx context.Context, ids []int64) error
	// RetryAuditForwardBatch 整批留队 + 计次 + 推迟到 nextAt 再试。绝不丢。
	RetryAuditForwardBatch(ctx context.Context, ids []int64, nextAt int64, detail string) error
	// RecordAuditForwardResult 记一次**已经发生**的发送结果。只有真发过的路径能调它。
	RecordAuditForwardResult(ctx context.Context, id, status, detail string, at int64) error
	// ResetAuditForwardBackoff 把某出口队列里所有记录的退避清零，返回受影响条数。
	// 消费方是「立即投递」：SIEM 修好之后，不该让管理员干等最长 15 分钟的退避。
	// 它**只动 next_at**，不动 attempts（重试次数是事实，不该被一次手动操作抹掉）。
	ResetAuditForwardBackoff(ctx context.Context, targetID string) (int64, error)
	// AuditForwardQueueMax 返回当前生效的队列上界（展示值必须来自入队时真正在用的那份）。
	AuditForwardQueueMax() int
}
