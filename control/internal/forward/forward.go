// Package forward 是审计日志的**外送出口**：把控制面已经落库的审计记录，
// 原样送到组织自己的 syslog / SIEM 上。
//
// # 为什么要有这一层（PRD ch16 + ch21.6）
//
// 改造前白帝的审计**只落库、没有任何外发出口**：全部证据留在被审计方自己的机器上。
// 这在合规语境下是个结构性问题——持库文件写权限的人同时是被审计对象时，
// 「事后不可抵赖」就只剩 HMAC 链这一道，而链本身也在同一个文件里：
// 整库替换（连同 audit-hmac.key）之后 verify 依然全绿。
//
// 外送把链**搬到另一台机器上**，这才是本功能真正的价值：
// 每条外送记录都带 seq 与 mac，外部 SIEM 侧可以独立重算与比对，
// 发现「控制面这边的第 N 条和我这边收到的第 N 条不是同一条」。
// 因此 seq/mac 不是可选字段，缺了它外送就退化成"日志复制"。
//
// # 两种出口的诚实边界
//
//   - syslog  真实现。RFC 5424 报文 + RFC 6587 帧，走 **TCP**，可选 TLS。
//     **刻意不做 UDP**：审计日志用 UDP 会在网络抖动/接收端忙时静默丢包，
//     而"丢了"这件事两端都看不见——这正是本项目反复吃亏的失效形态。
//     TLS 路径**没有**跳过证书校验的开关：外送内容是全量审计（账号、源 IP、
//     管理动作），一个"临时关掉校验"的开关在生产上一定会被永久打开。
//     证书对不上就换 CA / 填 serverName，这两条路都在配置里给了。
//   - http    真实现。POST 一批 JSON 记录到任意 URL（Elastic/Loki/自建收集器都能接）。
//     凭据放自定义头，加密落库、只写不读。
//
// # 不做的事
//
//   - 不做 UDP syslog（见上）。
//   - 不做 syslog 的 mTLS 客户端证书：需要私钥落库，而当前的 secret 盒只存一段口令；
//     真要双向认证请在前面放一跳（stunnel / 边车），别在这里做半套。
//   - 不做本地缓冲文件：队列在 SQLite 里（audit_forward_queue），与审计同一个存储，
//     多一份存储介质就多一处会写满的地方。
package forward

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"baidi.dev/control/internal/store"
)

// Kind 外送出口类型。落库用字符串，加类型不动 schema。
type Kind string

const (
	// KindSyslog RFC 5424 syslog over TCP（可选 TLS）。
	KindSyslog Kind = "syslog"
	// KindHTTP 通用 HTTP JSON 出口（SIEM / ELK / 自建收集器）。
	KindHTTP Kind = "http"
)

// Supported 报告某类型是否已真实实现。API 层据此在保存时拒绝未实现的类型，
// 控制台据此置灰——「界面上能选、后端静默不生效」是本项目最贵的一类缺陷。
func (k Kind) Supported() bool {
	switch k {
	case KindSyslog, KindHTTP:
		return true
	}
	return false
}

// Record 外送的一条审计记录。
//
// ★这是**类型别名**而不是另立一个 DTO，是本包最要紧的一行代码：
// 外送、`GET /api/v1/audit` 列表、CSV 导出三个出口必须是同一份字段。
// 各自定义结构体的话，下一次给审计加字段时一定只改其中一两处，
// 于是同一条审计在三个出口长得不一样——而"哪个出口是准的"没人说得清。
type Record = store.AuditEntry

// Forwarder 一个可发送的外送出口。实现必须是**并发安全**的
// （测试按钮与后台 pump 可能同时用同一条配置）。
type Forwarder interface {
	// Send 发送一批记录。**要么整批成功、要么整批失败**：
	// 部分成功会让队列没法安全地只删掉成功那几条，进而破坏 seq 的连续性——
	// 而连续性正是外部 SIEM 侧能验真的前提。
	Send(ctx context.Context, batch []Record) error
	// Target 返回实际拨过去的地址（展示 / 诊断用，绝不含凭据）。
	Target() string
}

var (
	// ErrNotConfigured 配置缺失/非法。这是"这项没填对"，不是"对面连不上"——
	// 两者在控制台上该显示成完全不同的话。
	ErrNotConfigured = errors.New("forward: 外送出口未配置完整")
	// ErrSendFailed 对端拒绝或链路失败。
	ErrSendFailed = errors.New("forward: 外送失败")
)

// ── 退避 ──

// backoffSteps 发送失败后的重试间隔阶梯（按已尝试次数取）。
//
// ★第一档刻意短（5s）：最常见的失败是接收端重启，几秒后就恢复；
// 最后一档封顶 15min 而不是无限翻倍——审计外送积压半小时以上就该有人去看了，
// 退避退到几小时一次只会让恢复后的追赶变得更慢。
var backoffSteps = []time.Duration{
	5 * time.Second, 15 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute,
}

// Backoff 返回第 attempts 次失败之后应等待多久再试（attempts 从 1 起）。
// 超出阶梯长度一律取最后一档（封顶，不再翻倍）。
func Backoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > len(backoffSteps) {
		attempts = len(backoffSteps)
	}
	return backoffSteps[attempts-1]
}

// ── 共用小工具 ──

// oneLine 把一段文本压成单行。
//
// ★两条出口都要用：syslog 的 LF 帧会被裸换行撕成两条消息（后半截变成一条
// 谁也解析不出的垃圾记录，而前半截看起来完全正常）；HTTP 那条是为了错误信息
// 进审计表时不撕坏 CSV。审计字段本来就是单行文本，这里是防御性的第二道。
func oneLine(s string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\x00", " ").Replace(s))
}

// truncRunes 按**字符**（不是字节）截断，避免把一个 UTF-8 汉字切成半个。
func truncRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// certPoolFromPEM 用给定 PEM 构造**只含这一把**的根证书池。
//
// 与 notify 同一条推理：填了自定义 CA 就只信这一把。"系统池 ∪ 私有 CA" 反而更宽——
// 任一公共 CA 误签一张你的 SIEM 证书都能骗过校验，而外送内容是全量审计。
func certPoolFromPEM(pemStr string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemStr)) {
		return nil, fmt.Errorf("forward: CA 证书不是有效的 PEM: %w", ErrNotConfigured)
	}
	return pool, nil
}
