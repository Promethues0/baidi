package notify

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func baseCfg(d *fakeSMTPD) SMTPConfig {
	host, port := d.addr()
	return SMTPConfig{
		Host: host, Port: port,
		// 证书签的是 localhost，连的是 127.0.0.1——用 ServerName 对齐，
		// 而不是开 InsecureSkipVerify（那会把证书校验这段代码路径整个跳过）。
		ServerName: "localhost",
		CACert:     d.caPEM,
		From:       "baidi@corp.example",
		FromName:   "白帝控制中心",
		Timeout:    10 * time.Second,
	}
}

// decodeBody 从收到的报文里取出 base64 正文并解码，顺带返回头部。
func decodeBody(t *testing.T, raw string) (headers, body string) {
	t.Helper()
	i := strings.Index(raw, "\r\n\r\n")
	if i < 0 {
		t.Fatalf("报文没有头/体分隔：%q", raw)
	}
	headers = raw[:i]
	enc := strings.ReplaceAll(strings.TrimSpace(raw[i+4:]), "\r\n", "")
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("正文不是合法 base64（中文正文必须做传输编码）：%v", err)
	}
	return headers, string(dec)
}

// STARTTLS 主流程：真协议往返 + PLAIN 认证 + 中文主题按 RFC 2047 编码。
func TestSMTP_StartTLS真实往返(t *testing.T) {
	d := newFakeSMTPD(t, smtpdOpts{advertiseSTARTTLS: true, advertiseAuth: true,
		wantUser: "alarm@corp", wantPass: "s3cr3t"})
	cfg := baseCfg(d)
	cfg.TLS = SMTPTLSStartTLS
	cfg.Auth = SMTPAuthPlain
	cfg.Username, cfg.Password = "alarm@corp", "s3cr3t"

	ch, err := NewSMTP(cfg)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if err := ch.Send(context.Background(),
		[]string{"soc@corp.example", " ", "ops@corp.example"}, "【白帝】登录防爆破锁定", "账号 li.fang 已锁定"); err != nil {
		t.Fatalf("发送应成功: %v", err)
	}

	_, mails, auths := d.snapshot()
	if len(mails) != 1 {
		t.Fatalf("应收到 1 封信，实得 %d", len(mails))
	}
	m := mails[0]
	if !m.OverTLS {
		t.Fatal("★DATA 是在明文连接上落地的——STARTTLS 没有真正生效")
	}
	if m.From != "baidi@corp.example" {
		t.Errorf("信封发件人 = %q", m.From)
	}
	// 空白收件人被剔除（复制粘贴来的空行是常态），其余原样投递。
	if len(m.Rcpt) != 2 || m.Rcpt[0] != "soc@corp.example" || m.Rcpt[1] != "ops@corp.example" {
		t.Errorf("收件人 = %v", m.Rcpt)
	}
	if len(auths) != 1 || auths[0] != "PLAIN" {
		t.Errorf("认证机制 = %v，期望一次 PLAIN", auths)
	}
	headers, body := decodeBody(t, m.Data)
	if !strings.Contains(headers, "Subject: =?UTF-8?") {
		t.Errorf("中文主题必须做 RFC 2047 编码，实得头部：%q", headers)
	}
	if strings.Contains(headers, "【白帝】") {
		t.Errorf("主题以裸 UTF-8 进了头部（多数 MTA 会打成乱码）：%q", headers)
	}
	if body != "账号 li.fang 已锁定" {
		t.Errorf("正文 = %q", body)
	}
}

// ★对照组：服务端不支持 STARTTLS 时**必须失败**，且不得发出任何 AUTH/MAIL/DATA。
//
// 这条与 ldapsrc 的「StartTLS 协商失败不得降级明文」是同一条纪律：
// 降级不只是让这封告警被看见，AUTH 会跟着明文发出去——SMTP 账号一旦泄露，
// 攻击者就有了一个能以本组织名义发信的身份。
func TestSMTP_服务端不支持StartTLS时必须拒绝而不是降级明文(t *testing.T) {
	d := newFakeSMTPD(t, smtpdOpts{advertiseSTARTTLS: false, advertiseAuth: true,
		wantUser: "alarm@corp", wantPass: "s3cr3t"})
	cfg := baseCfg(d)
	cfg.TLS = SMTPTLSStartTLS
	cfg.Auth = SMTPAuthPlain
	cfg.Username, cfg.Password = "alarm@corp", "s3cr3t"

	ch, err := NewSMTP(cfg)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	err = ch.Send(context.Background(), []string{"soc@corp.example"}, "主题", "正文")
	if err == nil {
		t.Fatal("★STARTTLS 不可用时仍然发送成功，说明降级成了明文")
	}
	if !errors.Is(err, ErrSendFailed) {
		t.Errorf("错误应归类为发送失败: %v", err)
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("错误信息应指出是 STARTTLS 不可用: %v", err)
	}
	_, mails, auths := d.snapshot()
	if len(mails) != 0 {
		t.Errorf("★降级后仍投递了 %d 封信", len(mails))
	}
	if len(auths) != 0 {
		t.Errorf("★口令在明文连接上发出去了：%v", auths)
	}
	for _, v := range []string{"AUTH", "MAIL", "RCPT", "DATA"} {
		if d.sawVerb(v) {
			t.Errorf("★STARTTLS 失败后仍发出了 %s 命令", v)
		}
	}
}

// implicit TLS（465）整条连接直接加密。
func TestSMTP_ImplicitTLS(t *testing.T) {
	d := newFakeSMTPD(t, smtpdOpts{implicitTLS: true, advertiseAuth: true,
		wantUser: "u", wantPass: "p"})
	cfg := baseCfg(d)
	cfg.TLS = SMTPTLSImplicit
	cfg.Auth = SMTPAuthPlain
	cfg.Username, cfg.Password = "u", "p"
	ch, err := NewSMTP(cfg)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if err := ch.Send(context.Background(), []string{"soc@corp.example"}, "s", "b"); err != nil {
		t.Fatalf("发送应成功: %v", err)
	}
	_, mails, _ := d.snapshot()
	if len(mails) != 1 || !mails[0].OverTLS {
		t.Fatalf("implicit TLS 下应收到 1 封加密投递的信，实得 %+v", mails)
	}
}

// AUTH LOGIN（Exchange / 部分国产网关只认它）真回合往返。
func TestSMTP_AuthLogin(t *testing.T) {
	d := newFakeSMTPD(t, smtpdOpts{advertiseSTARTTLS: true, advertiseAuth: true,
		wantUser: "svc-alarm", wantPass: "pw-01"})
	cfg := baseCfg(d)
	cfg.TLS = SMTPTLSStartTLS
	cfg.Auth = SMTPAuthLogin
	cfg.Username, cfg.Password = "svc-alarm", "pw-01"
	ch, err := NewSMTP(cfg)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if err := ch.Send(context.Background(), []string{"soc@corp.example"}, "s", "b"); err != nil {
		t.Fatalf("LOGIN 认证应成功: %v", err)
	}
	_, mails, auths := d.snapshot()
	if len(auths) != 1 || auths[0] != "LOGIN" {
		t.Fatalf("应完成一次 LOGIN 认证，实得 %v", auths)
	}
	if len(mails) != 1 {
		t.Fatalf("应收到 1 封信")
	}
}

// 匿名中继（内网按 IP 放行）：不配认证也能发。
func TestSMTP_匿名中继(t *testing.T) {
	d := newFakeSMTPD(t, smtpdOpts{advertiseSTARTTLS: true})
	cfg := baseCfg(d)
	cfg.TLS = SMTPTLSStartTLS
	cfg.Auth = SMTPAuthNone
	ch, err := NewSMTP(cfg)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if err := ch.Send(context.Background(), []string{"soc@corp.example"}, "s", "b"); err != nil {
		t.Fatalf("匿名发送应成功: %v", err)
	}
	if d.sawVerb("AUTH") {
		t.Error("认证方式为 none 却发了 AUTH")
	}
}

// 明文传输 + 认证：**构造期**就要拒绝，不能等到发送时才发现口令要明文出门。
func TestSMTP_明文传输下不允许配置认证(t *testing.T) {
	cfg := SMTPConfig{Host: "127.0.0.1", Port: 25, TLS: SMTPTLSPlaintext,
		Auth: SMTPAuthPlain, Username: "u", Password: "p", From: "a@b.c"}
	_, err := NewSMTP(cfg)
	if err == nil {
		t.Fatal("★明文 + AUTH 被接受了：SMTP 账号口令会明文过网线")
	}
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("应归类为配置错误: %v", err)
	}
}

func TestSMTP_配置校验(t *testing.T) {
	cases := []struct {
		name string
		cfg  SMTPConfig
	}{
		{"缺主机", SMTPConfig{From: "a@b.c"}},
		{"缺发件人", SMTPConfig{Host: "h"}},
		{"未知传输方式", SMTPConfig{Host: "h", From: "a@b.c", TLS: "quic"}},
		{"未知认证方式", SMTPConfig{Host: "h", From: "a@b.c", Auth: "ntlm"}},
		{"认证缺口令", SMTPConfig{Host: "h", From: "a@b.c", Auth: SMTPAuthPlain, Username: "u"}},
		{"发件人含换行", SMTPConfig{Host: "h", From: "a@b.c\r\nBcc: x@y.z"}},
		{"CA 不是 PEM", SMTPConfig{Host: "h", From: "a@b.c", CACert: "not-a-pem"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewSMTP(c.cfg); err == nil {
				t.Fatal("应拒绝该配置")
			} else if !errors.Is(err, ErrNotConfigured) {
				t.Errorf("应归类为配置错误: %v", err)
			}
		})
	}
}

// 收件人为空必须报错，绝不当成"发成功了"——静默丢弃一条告警没有任何痕迹。
func TestSMTP_收件人为空报错(t *testing.T) {
	d := newFakeSMTPD(t, smtpdOpts{advertiseSTARTTLS: true})
	cfg := baseCfg(d)
	cfg.TLS = SMTPTLSStartTLS
	ch, _ := NewSMTP(cfg)
	if err := ch.Send(context.Background(), []string{"", "   "}, "s", "b"); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("应报「无收件人」，实得 %v", err)
	}
	if d.sawVerb("MAIL") {
		t.Error("没有收件人时不该建立投递")
	}
}

// 收件人里塞 CRLF = 邮件头注入（"\r\nBcc: attacker@x" 把每条告警抄送出去）。
func TestSMTP_收件人换行符被拒(t *testing.T) {
	d := newFakeSMTPD(t, smtpdOpts{advertiseSTARTTLS: true})
	cfg := baseCfg(d)
	cfg.TLS = SMTPTLSStartTLS
	ch, _ := NewSMTP(cfg)
	err := ch.Send(context.Background(), []string{"ok@corp.example\r\nBcc: attacker@evil.example"}, "s", "b")
	if err == nil {
		t.Fatal("★收件人里的 CRLF 没被拦，邮件头可被注入")
	}
	if d.sawVerb("MAIL") {
		t.Error("校验应在建连投递之前完成")
	}
}

// 连不上 MTA 必须如实报错并归类为发送失败——「发不出去」与「发成功了」
// 在通道页上是绿灯与红灯的区别，混成一个值这一页就没有用了。
func TestSMTP_连不上时如实报错(t *testing.T) {
	d := newFakeSMTPD(t, smtpdOpts{advertiseSTARTTLS: true})
	cfg := baseCfg(d)
	cfg.TLS = SMTPTLSStartTLS
	cfg.Port = 1 // 必然连不上
	cfg.Timeout = 2 * time.Second
	ch, err := NewSMTP(cfg)
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	if err := ch.Send(context.Background(), []string{"a@b.c"}, "s", "b"); err == nil {
		t.Fatal("连不上时必须报错")
	} else if !errors.Is(err, ErrSendFailed) {
		t.Errorf("应归类为发送失败: %v", err)
	}
}
