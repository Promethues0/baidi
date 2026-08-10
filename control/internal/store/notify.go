package store

import "context"

// ── 消息通道落库（PRD ch15.2）──
//
// 配置与凭据**物理分表**，与 auth_source_secrets / ipsec_secrets 同一条推理：
// 让「某天有人写了 SELECT * 拼通道清单」或忘加 requirePerm 时，泄露需要显式写代码，
// 而不是默认发生。

// NotifyChannel 一条消息通道配置。
//
// ★凭据（SMTP 口令、webhook 头里的 token）**不在这个结构体里**：
// 它们走 notify_channel_secrets 独立表加密落盘，只写不读。
//
// ★刻意**没有**「订阅哪些事件」这一列。加了它就必须有一个真读它的过滤器，
// 而本轮的事件只有两类（爆破锁定 / 终端判 block）——一个只有两个取值的过滤开关
// 是典型的 config-only。何况方向上「漏发」远比「多发」危险：一条没送到的告警
// 不会在任何页面上留下痕迹。等事件种类真的多到需要分流时再加，同时补上消费方。
type NotifyChannel struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`    // smtp | webhook | sms
	Enabled bool   `json:"enabled"` // 管理意图：关掉即不参与派发
	// Config 该类型的非敏感配置 JSON（主机/端口/URL/收件人…）。
	// 敏感项一律不在这里——放进来就等于绕开了上面那道分表。
	Config string `json:"config"`

	// HasSecret / SecretFingerprint 是只写不读语义下的唯一回显。
	HasSecret         bool   `json:"hasSecret"`
	SecretFingerprint string `json:"secretFingerprint,omitempty"`

	// ── 上次发送结果。★只由**真正发出那一次**写入（api.sendVia），
	// 保存配置、翻转开关都不许碰它。展示值必须来自数据面真正在用的那份：
	// 拿"配置校验通过"冒充"发送成功"，页面就会在邮件根本发不出去时长期显示绿色。
	LastStatus string `json:"lastStatus,omitempty"` // ok | fail（空 = 从未发过）
	LastDetail string `json:"lastDetail,omitempty"` // 真实的失败原因 / 成功摘要
	LastEvent  string `json:"lastEvent,omitempty"`  // 触发那一次发送的事件键
	LastAt     int64  `json:"lastAt,omitempty"`     // Unix 秒

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// NotifyChannelSecret 一条加密落盘的通道凭据（AES-256-GCM，AAD 绑 channel id）。
type NotifyChannelSecret struct {
	ChannelID string
	Nonce     []byte
	Cipher    []byte
	// Fingerprint 凭据的截断哈希（前 8 位），**由写入方算好存进来**——
	// 与 AuthSourceSecret 同款：读列表时解密算指纹会在一条人人可读的路径上
	// 引入解密调用，与「只写不读」自相矛盾。
	Fingerprint string
}

// NotifyStore 消息通道的读写。
//
// ★与 AuthSourceStore / IpsecStore 同款考虑：「读凭据密文」这种只该被
// 一两个调用点用到的能力收在独立接口里，不挂到人人可得的 Writer 上。
// 也因此它**不进 Store 接口**——Store 的每个方法都得有 Memory 演示实现，
// 而消息通道没有"演示数据"这回事（编一条假的 SMTP 配置比空着更坏）。
type NotifyStore interface {
	NotifyChannels(ctx context.Context) ([]NotifyChannel, error)
	NotifyChannelByID(ctx context.Context, id string) (NotifyChannel, bool, error)
	SaveNotifyChannel(ctx context.Context, rec NotifyChannel) (NotifyChannel, error)
	DeleteNotifyChannel(ctx context.Context, id string) error
	// SaveNotifyChannelSecret 写入（或替换）凭据密文。
	SaveNotifyChannelSecret(ctx context.Context, sec NotifyChannelSecret) error
	// NotifyChannelSecret 取凭据密文。★调用点必须极少：只有"构造 Channel"这一处。
	NotifyChannelSecret(ctx context.Context, id string) (NotifyChannelSecret, bool, error)
	// RecordNotifySend 记一次**已经发生**的发送结果。只有真发过的路径能调它。
	RecordNotifySend(ctx context.Context, id, status, detail, event string, at int64) error
}

// 发送结果取值。
const (
	NotifySendOK   = "ok"
	NotifySendFail = "fail"
)
