package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/notify"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── 消息通道 · 管理端点（PRD ch15.2，全部 requirePerm(PermSystem)）──
//
//	GET    /api/v1/notify/channels             列表（不含任何凭据原文）
//	POST   /api/v1/notify/channels             新增 / 修改
//	DELETE /api/v1/notify/channels/{id}        删除（连同凭据）
//	PUT    /api/v1/notify/channels/{id}/secret 设置凭据（只写不读）
//	POST   /api/v1/notify/channels/{id}/test   真发一条测试消息
//
// ★归 system 那一权而不是 security：消息通道是"控制面往外拨号"的运维配置，
// 与网关证书 / 组网 / 对象库同类。给 security 的话，安全管理员能把告警改投到
// 自己的邮箱——「定策略的人顺手关掉看自己痕迹的通道」正是三权分立要拦的形态。
//
// ★读端点同样走 requirePerm（而不是 requireAdmin）：一是权限要现算不能只信令牌里的
// role，二是通道配置里有 SMTP 主机名、内网 webhook 地址这类内网拓扑信息。

type notifyStore interface {
	NotifyChannels(ctx context.Context) ([]store.NotifyChannel, error)
	NotifyChannelByID(ctx context.Context, id string) (store.NotifyChannel, bool, error)
	SaveNotifyChannel(ctx context.Context, rec store.NotifyChannel) (store.NotifyChannel, error)
	DeleteNotifyChannel(ctx context.Context, id string) error
	SaveNotifyChannelSecret(ctx context.Context, sec store.NotifyChannelSecret) error
	NotifyChannelSecret(ctx context.Context, id string) (store.NotifyChannelSecret, bool, error)
	RecordNotifySend(ctx context.Context, id, status, detail, event string, at int64) error
}

func (s *Server) notifyStore(w http.ResponseWriter) (notifyStore, bool) {
	ns, ok := s.store.(notifyStore)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储实现不支持消息通道")
		return nil, false
	}
	return ns, true
}

// ── 配置 DTO（落库的 config 列就是它们的 JSON）──

type smtpChannelDTO struct {
	Host               string   `json:"host"`
	Port               int      `json:"port"`
	TLSMode            string   `json:"tlsMode"` // starttls | implicit | plaintext
	ServerName         string   `json:"serverName,omitempty"`
	CACert             string   `json:"caCert,omitempty"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify,omitempty"`
	AuthMode           string   `json:"authMode"` // none | plain | login
	Username           string   `json:"username,omitempty"`
	From               string   `json:"from"`
	FromName           string   `json:"fromName,omitempty"`
	Recipients         []string `json:"recipients"`
	TimeoutSec         int      `json:"timeoutSec,omitempty"`
}

type webhookChannelDTO struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	// SecretHeader 凭据要注入的头名（如 Authorization / X-Token）。
	// **头值不在这里**——它在 notify_channel_secrets 里加密存着，只写不读。
	SecretHeader string   `json:"secretHeader,omitempty"`
	Recipients   []string `json:"recipients,omitempty"` // webhook: 载荷里的 to；sms: 手机号
	TimeoutSec   int      `json:"timeoutSec,omitempty"`
}

// handleNotifyChannels 通道清单。
//
// ★响应里永远不含凭据原文，只有 hasSecret + 指纹前 8 位。
// 顺带下发 supportedKinds 与 droppedNotices：前者让控制台把未实现的类型置灰，
// 后者是**真实**的队列溢出计数——管理员没收到告警时，这个数字能区分
// 「压根没触发」与「触发了但队列满了没发出去」。
func (s *Server) handleNotifyChannels(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	ns, ok := s.notifyStore(w)
	if !ok {
		return
	}
	chans, err := ns.NotifyChannels(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load notify channels")
		return
	}
	kinds := []string{}
	for _, k := range []notify.Kind{notify.KindSMTP, notify.KindWebhook, notify.KindSMS} {
		kinds = append(kinds, string(k))
	}
	dropped := 0
	if s.notices != nil {
		dropped = s.notices.Dropped()
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"channels":       chans,
		"supportedKinds": kinds,
		"droppedNotices": dropped,
		// 诚实标注：短信通道就是一次 webhook 调用，控制台照抄这句话展示。
		"smsNote": "短信通道本质是一次 webhook 调用（载荷 mobiles + text），" +
			"白帝不实现任何短信网关协议——需要你自己搭一跳把它转成运营商/云厂商的请求。",
	})
}

// handleSaveNotifyChannel 新增 / 修改通道。
func (s *Server) handleSaveNotifyChannel(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	ns, ok := s.notifyStore(w)
	if !ok {
		return
	}
	var b struct {
		ID      string          `json:"id"`
		Name    string          `json:"name"`
		Kind    string          `json:"kind"`
		Enabled bool            `json:"enabled"`
		Config  json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || strings.TrimSpace(b.Name) == "" {
		httpx.Error(w, http.StatusBadRequest, "name 必填")
		return
	}
	kind := notify.Kind(strings.TrimSpace(b.Kind))
	if !kind.Supported() {
		// 装载期明确拒绝，不存下来再在告警发生时静默失败。
		httpx.Error(w, http.StatusBadRequest,
			"消息通道类型 "+b.Kind+" 本版本未实现（当前支持：smtp / webhook / sms）")
		return
	}
	cfg := "{}"
	if len(b.Config) > 0 {
		cfg = string(b.Config)
	}
	rec, err := ns.SaveNotifyChannel(r.Context(), store.NotifyChannel{
		ID: b.ID, Name: b.Name, Kind: string(kind), Enabled: b.Enabled, Config: cfg,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save notify channel")
		return
	}
	// 保存即校验：配置写错要当场知道，而不是等到真出安全事件那一刻才发现发不出去。
	// 构造失败不拒绝保存（管理员可能分几步填：先存配置、再设凭据），但把原因带回去。
	var warn string
	if _, _, berr := s.buildNotifyChannel(r.Context(), rec); berr != nil {
		warn = "配置已保存，但当前还不可用：" + berr.Error()
	}
	s.audit(r, "admin", "保存消息通道「"+rec.Name+"」（"+rec.Kind+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "channel": rec, "warning": warn})
}

func (s *Server) handleDeleteNotifyChannel(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	ns, ok := s.notifyStore(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	rec, found, err := ns.NotifyChannelByID(r.Context(), id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load notify channel")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "消息通道不存在")
		return
	}
	if err := ns.DeleteNotifyChannel(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete notify channel")
		return
	}
	// 删掉最后一条通道 = 安全事件从此无人知晓。审计里把这件事说出来。
	s.audit(r, "admin", "删除消息通道「"+rec.Name+"」（"+rec.Kind+"，连同其凭据）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// handleSetNotifyChannelSecret 设置通道凭据（SMTP 口令 / webhook 凭据头的取值）。
//
// **只写不读**：没有任何端点能把它读回去。AAD 绑 channel id——
// 把某一行密文剪贴到另一条通道上会直接解不开，而不是悄悄生效
// （不绑 AAD 的话，"能写库"就等于"能完成一次密钥转移"，不需要任何密码学突破）。
func (s *Server) handleSetNotifyChannelSecret(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	ns, ok := s.notifyStore(w)
	if !ok {
		return
	}
	rec, found, err := ns.NotifyChannelByID(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load notify channel")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "消息通道不存在")
		return
	}
	var b struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if strings.TrimSpace(b.Secret) == "" {
		httpx.Error(w, http.StatusBadRequest, "凭据不能为空（要取消认证请把通道的认证方式改为 none / 清掉凭据头）")
		return
	}
	box, err := secret.Default()
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, "凭据主密钥不可用："+err.Error())
		return
	}
	nonce, cipher, err := box.Seal(rec.ID, []byte(b.Secret))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "凭据加密失败")
		return
	}
	fp := box.Fingerprint([]byte(b.Secret))[:8]
	if err := ns.SaveNotifyChannelSecret(r.Context(), store.NotifyChannelSecret{
		ChannelID: rec.ID, Nonce: nonce, Cipher: cipher, Fingerprint: fp,
	}); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save secret")
		return
	}
	s.audit(r, "admin", "更新消息通道「"+rec.Name+"」的凭据", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "fingerprint": fp})
}

// handleTestNotifyChannel 真发一条测试消息，返回真实结果。
//
// ★不许假成功。这个按钮此前在别的页面上是纯装饰（认证源的「测试连接」就补过一次），
// 而消息通道的装饰性尤其致命：管理员点一下看见绿勾，就再也不会怀疑告警发不出去。
// 结果同时落进 last_* 四列——那是"数据面真正发出去那一次"的记录。
func (s *Server) handleTestNotifyChannel(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	ns, ok := s.notifyStore(w)
	if !ok {
		return
	}
	rec, found, err := ns.NotifyChannelByID(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load notify channel")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "消息通道不存在")
		return
	}
	// 自检要有上界：对端不可达时 TCP 可能吊很久，让管理员盯着转圈的按钮毫无意义。
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	start := time.Now()
	detail, err := s.sendVia(ctx, ns, rec, notify.Message{
		Event:   "test",
		Subject: "【白帝】消息通道测试",
		Body: "这是一条由管理员手动触发的测试消息。\n\n通道：" + rec.Name + "（" + rec.Kind + "）\n时间：" +
			time.Now().Format("2006-01-02 15:04:05") + "\n\n收到它说明该通道可用；真实的安全事件通知会走同一条路径。",
	}, []string{})
	if err != nil {
		// 审计只记已发生的事实：测试发送失败。
		s.audit(r, "admin", "测试消息通道「"+rec.Name+"」失败："+detail, "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": detail})
		return
	}
	s.audit(r, "admin", "测试消息通道「"+rec.Name+"」成功（"+detail+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "detail": detail, "elapsedMs": time.Since(start).Milliseconds(),
	})
}

// ── 构造与发送 ──

// buildNotifyChannel 把一条落库配置装成可发送的通道，并给出默认收件人。
//
// 凭据在这里、且**只在这里**被解密——与 authsrc.buildProvider 同款纪律：
// 「能读密文」的调用点越少，越不容易在某次重构里被顺手扩散到列表路径上。
func (s *Server) buildNotifyChannel(ctx context.Context, rec store.NotifyChannel) (notify.Channel, []string, error) {
	cred := ""
	if rec.HasSecret {
		ns, ok := s.store.(notifyStore)
		if !ok {
			return nil, nil, errors.New("当前存储实现不支持消息通道")
		}
		sec, found, err := ns.NotifyChannelSecret(ctx, rec.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("读取凭据失败：%w", err)
		}
		if found {
			box, err := secret.Default()
			if err != nil {
				return nil, nil, fmt.Errorf("凭据主密钥不可用：%w", err)
			}
			pt, err := box.Open(rec.ID, sec.Nonce, sec.Cipher)
			if err != nil {
				return nil, nil, fmt.Errorf("凭据解密失败：%w", err)
			}
			cred = string(pt)
		}
	}
	cfg := rec.Config
	if strings.TrimSpace(cfg) == "" {
		cfg = "{}"
	}
	switch notify.Kind(rec.Kind) {
	case notify.KindSMTP:
		var d smtpChannelDTO
		if err := json.Unmarshal([]byte(cfg), &d); err != nil {
			return nil, nil, fmt.Errorf("SMTP 配置不是合法 JSON：%w", err)
		}
		ch, err := notify.NewSMTP(notify.SMTPConfig{
			Host: d.Host, Port: d.Port, TLS: notify.SMTPTLSMode(d.TLSMode),
			ServerName: d.ServerName, CACert: d.CACert, InsecureSkipVerify: d.InsecureSkipVerify,
			Auth: notify.SMTPAuthMode(d.AuthMode), Username: d.Username, Password: cred,
			From: d.From, FromName: d.FromName,
			Timeout: time.Duration(d.TimeoutSec) * time.Second,
		})
		if err != nil {
			return nil, nil, err
		}
		return ch, d.Recipients, nil
	case notify.KindWebhook, notify.KindSMS:
		var d webhookChannelDTO
		if err := json.Unmarshal([]byte(cfg), &d); err != nil {
			return nil, nil, fmt.Errorf("webhook 配置不是合法 JSON：%w", err)
		}
		headers := map[string]string{}
		for k, v := range d.Headers {
			headers[k] = v
		}
		if h := strings.TrimSpace(d.SecretHeader); h != "" {
			if cred == "" {
				return nil, nil, errors.New("配置了凭据头 " + h + " 但尚未设置凭据（PUT …/secret）")
			}
			headers[h] = cred
		}
		wcfg := notify.WebhookConfig{
			URL: d.URL, Headers: headers, Timeout: time.Duration(d.TimeoutSec) * time.Second,
		}
		var ch notify.Channel
		var err error
		if notify.Kind(rec.Kind) == notify.KindSMS {
			ch, err = notify.NewSMS(wcfg)
		} else {
			ch, err = notify.NewWebhook(wcfg)
		}
		if err != nil {
			return nil, nil, err
		}
		return ch, d.Recipients, nil
	}
	return nil, nil, errors.New("消息通道类型 " + rec.Kind + " 本版本未实现")
}

// sendVia 经一条通道发送并**如实**记录结果。返回给人看的 detail 与错误。
//
// 无论成败都写 last_*：只在成功时写的话，一条从此再也发不出去的通道会永远停在
// 上一次成功的绿色上——那正是"配置齐全却零报错不生效"的经典形态。
func (s *Server) sendVia(ctx context.Context, ns notifyStore, rec store.NotifyChannel,
	m notify.Message, extraTo []string) (string, error) {
	ch, to, err := s.buildNotifyChannel(ctx, rec)
	if err != nil {
		detail := "配置不可用：" + err.Error()
		_ = ns.RecordNotifySend(ctx, rec.ID, store.NotifySendFail, detail, m.Event, time.Now().Unix())
		return detail, err
	}
	to = append(append([]string{}, to...), extraTo...)
	if err := ch.Send(ctx, to, m.Subject, m.Body); err != nil {
		detail := err.Error()
		_ = ns.RecordNotifySend(ctx, rec.ID, store.NotifySendFail, detail, m.Event, time.Now().Unix())
		return detail, err
	}
	detail := fmt.Sprintf("已投递 %d 个收件人", len(to))
	if len(to) == 0 {
		// 通用 webhook 允许没有收件人（收件人写在对面的机器人配置里）。
		// 措辞如实：只说"已投递到 webhook"，不谎称送到了谁。
		detail = "已投递到 webhook 对端"
	}
	_ = ns.RecordNotifySend(ctx, rec.ID, store.NotifySendOK, detail, m.Event, time.Now().Unix())
	return detail, nil
}

// ── 真实消费方：安全事件通知 ──

// notifySecurityEvent 把一条**已经发生**的安全事件排进通知队列。
//
// ★三条纪律：
//  1. 绝不阻塞主流程——入队是非阻塞的，队列满就丢并计数（账号已经锁了、
//     接入已经收缩了，通知发不出去不改变任何一个安全结论）；
//  2. 绝不带请求 ctx——handler 返回那一刻它就被取消了；
//  3. 措辞只记已发生的事实。
func (s *Server) notifySecurityEvent(event, subject, body string) {
	if s.notices == nil {
		return
	}
	s.notices.Enqueue(notify.Message{Event: event, Subject: subject, Body: body})
}

// deliverNotice 是派发器的 sink：向全部**已启用**通道各发一份。
//
// 一条通道失败不影响其余通道（依次发，不短路）——两条通道的意义就是互为备份，
// 第一条挂了就不发第二条等于没有备份。
func (s *Server) deliverNotice(ctx context.Context, m notify.Message) {
	ns, ok := s.store.(notifyStore)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	chans, err := ns.NotifyChannels(ctx)
	if err != nil {
		slog.Error("安全事件通知：通道清单读取失败，本条未发出", "event", m.Event, "err", err.Error())
		s.auditBG(ctx, "security", "安全事件通知未发出（消息通道清单读取失败）："+m.Subject, "fail")
		return
	}
	sent := 0
	for _, rec := range chans {
		if !rec.Enabled {
			continue
		}
		sent++
		detail, err := s.sendVia(ctx, ns, rec, m, nil)
		if err != nil {
			// ★发送失败必须落审计：这是"你以为已经通知到了、其实没有"的唯一痕迹。
			slog.Error("安全事件通知发送失败", "channel", rec.Name, "kind", rec.Kind, "event", m.Event, "err", err.Error())
			s.auditBG(ctx, "security",
				"安全事件通知发送失败（通道「"+rec.Name+"」/"+rec.Kind+"）："+m.Subject+" —— "+detail, "fail")
			continue
		}
		s.auditBG(ctx, "security",
			"安全事件通知已发出（通道「"+rec.Name+"」/"+rec.Kind+"，"+detail+"）："+m.Subject, "ok")
	}
	if sent == 0 {
		// 没配通道不是错误，但也不能完全无声：真出事时"为什么没人收到"要有据可查。
		slog.Warn("安全事件发生但没有任何启用中的消息通道，通知未发出", "event", m.Event, "subject", m.Subject)
	}
}
