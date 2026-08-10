// Package notify 是控制面的**消息通道**：把一条已经发生的事实（账号被爆破锁定、
// 终端被判不合规）送到管理员看得见的地方。
//
// # 为什么要有这一层
//
// PRD ch15.2 的邮件/短信/推送三条通道此前在白帝里**一条都没有**——grep smtp/sms/webhook
// 零命中。它不是锦上添花：第 5 章的「告警邮件通知」整章都压在它上面，没有它，
// 所有「已告警」的说法都只是在页面上画了个红点。
//
// # 三种类型的诚实边界
//
//   - smtp    真实现。标准库 net/smtp + crypto/tls，支持 implicit TLS 与 STARTTLS，
//     支持匿名 / PLAIN / LOGIN 认证。
//   - webhook 真实现。POST JSON 到配置的 URL，凭据放自定义头，非 2xx 即失败。
//   - sms     **它就是 webhook**，不是任何一家短信网关的协议实现。
//
// 最后一条要说透。国内短信网关（阿里云/腾讯云/华为云/移动云…）各家的签名算法、
// 模板参数、错误码完全不同，且都要真实账号才能验证。在这里塞一个"看起来像在发短信"
// 的假实现，会让管理员配完之后以为自己有了短信告警——而真出事那天一条都收不到，
// 且**没有任何报错**（这正是本项目反复吃亏的形态）。
//
// 所以这里选的是「诚实的通用适配」：短信通道本质上就是把消息 POST 给用户自己搭的
// 那个对接网关的小服务，载荷里给出 mobiles + text。它在 UI 上必须如实标注为
// 「webhook 适配」，不许写成「已支持阿里云短信」。
//
// 另一条可选路是照 authsrc.Kind.Supported() 那样直接拒绝保存 sms 类型。之所以没选它：
// webhook 适配是**真能把短信发出去**的（用户自己那一跳是真的），而 RADIUS 那三类
// 连一跳都没有。有真实消费价值就实现，没有就拒绝——这条线不动摇。
package notify

import (
	"context"
	"errors"
	"strings"
)

// Kind 消息通道类型。落库用字符串，加类型不动 schema。
type Kind string

const (
	// KindSMTP 邮件（net/smtp + TLS）。
	KindSMTP Kind = "smtp"
	// KindWebhook 通用 HTTP webhook（POST JSON）。
	KindWebhook Kind = "webhook"
	// KindSMS 短信——**实现上就是一次 webhook 调用**，见包注释。
	KindSMS Kind = "sms"
)

// Supported 报告某类型是否已真实实现。API 层据此在保存时拒绝未实现的类型，
// 控制台据此置灰——「界面上能选、后端静默不生效」是本项目最贵的一类缺陷。
func (k Kind) Supported() bool {
	switch k {
	case KindSMTP, KindWebhook, KindSMS:
		return true
	}
	return false
}

// Channel 一条可发送的消息通道。
//
// to 的语义由具体实现决定：SMTP 是收件邮箱，SMS 是手机号，Webhook 只是原样放进载荷。
// 实现必须是**并发安全**的（同一条通道可能被测试按钮与后台派发同时用）。
type Channel interface {
	Send(ctx context.Context, to []string, subject, body string) error
}

var (
	// ErrNotConfigured 配置缺失/非法。这是"这项没填对"，不是"对面连不上"——
	// 两者在控制台上该显示成完全不同的话。
	ErrNotConfigured = errors.New("notify: 通道未配置完整")
	// ErrNoRecipients 没有收件人。**不当成功处理**：静默丢弃一条告警比发送失败更坏，
	// 因为失败会留痕，静默丢弃不会。
	ErrNoRecipients = errors.New("notify: 未配置收件人")
	// ErrSendFailed 对端拒绝或链路失败。
	ErrSendFailed = errors.New("notify: 发送失败")
)

// hasCRLF 报告字符串是否含裸 CR/LF。
//
// ★这是头注入的判据，两条通道都要用：邮件头里塞一个 "\r\nBcc: attacker@x" 就能
// 把每一条告警抄送出去；HTTP 头里塞 CRLF 是经典的响应拆分。收件人来自管理员配置，
// 而"管理员配置"在被拖库改写之后就不再可信，所以在**发送那一刻**校验，不只在保存时。
func hasCRLF(s string) bool { return strings.ContainsAny(s, "\r\n") }

// trimAll 去掉首尾空白并剔除空项（收件人清单几乎总带着复制粘贴来的空行）。
func trimAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
