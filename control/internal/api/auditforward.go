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

	"baidi.dev/control/internal/forward"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── 审计日志外送 · 管理端点（PRD ch16 + ch21.6，全部 requirePerm(PermSystem)）──
//
//	GET    /api/v1/audit/forward              出口清单 + 积压 / 丢弃 / 上次成败
//	POST   /api/v1/audit/forward              新增 / 修改
//	DELETE /api/v1/audit/forward/{id}         删除（连同凭据与积压）
//	PUT    /api/v1/audit/forward/{id}/secret  设置凭据（只写不读）
//	POST   /api/v1/audit/forward/{id}/test    真发一条测试记录
//
// ★归 system 那一权而不是 audit：这是"控制面往外拨号"的运维配置，与消息通道、
// 网关证书、组网同类。另一半理由是结构性的——PermAudit 按设计是**只读**权
// （见 store.PermAudit 的注释），让它持有写端点会在权限模型上开一个口子。
//
// ★读端点同样走 requirePerm 现算角色：出口配置里有 SIEM 主机名、内网收集器地址
// 这类内网拓扑信息，且"外送配到哪去了"本身就是攻击者想知道的事。

// auditForwardBatchSize 一次 pump 从队列取多少条。
//
// 200 条 ≈ 一条 syslog 连接上几十 KB，一次 TCP 生命周期内发得完；
// 太大则一次失败要整批重试（重试代价随批量线性上升），太小则追赶积压太慢。
const auditForwardBatchSize = 200

// auditForwardRoundsPerTick 一轮 pump 最多连发多少批。
//
// 有上界是为了让一个刚恢复的出口不会把整轮 pump 独占住（后面的出口一直等不到）；
// 追不完的下一轮继续，反正队列是持久化的。
const auditForwardRoundsPerTick = 20

// auditForwardDropReportEvery 队列溢出转成审计事件的最小间隔。
//
// 溢出会持续发生（对端一直连不上），每次都记一条的话审计表会被自己的告警刷爆——
// 而那条告警本身也要入队，又会被丢弃，形成一个只增不减的循环。
const auditForwardDropReportEvery = 10 * time.Minute

// ── 配置 DTO（落库的 config 列就是它们的 JSON）──

type syslogTargetDTO struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	// TLS 走 RFC 5425（默认 6514）。★没有"跳过证书校验"这一项，
	// 见 forward.SyslogConfig.TLS 的注释：证书对不上请填 serverName 或 caCert。
	TLS          bool   `json:"tls"`
	ServerName   string `json:"serverName,omitempty"`
	CACert       string `json:"caCert,omitempty"`
	Facility     int    `json:"facility,omitempty"`
	AppName      string `json:"appName,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Framing      string `json:"framing,omitempty"` // octet | lf
	EnterpriseID string `json:"enterpriseId,omitempty"`
	TimeoutSec   int    `json:"timeoutSec,omitempty"`
}

type httpTargetDTO struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	// SecretHeader 凭据要注入的头名（如 Authorization）。
	// **头值不在这里**——它在 audit_forward_secrets 里加密存着，只写不读。
	SecretHeader string `json:"secretHeader,omitempty"`
	CACert       string `json:"caCert,omitempty"`
	TimeoutSec   int    `json:"timeoutSec,omitempty"`
}

func (s *Server) auditForwardStore(w http.ResponseWriter) (store.AuditForwardStore, bool) {
	fs, ok := s.store.(store.AuditForwardStore)
	if !ok {
		httpx.Error(w, http.StatusServiceUnavailable, "当前存储实现不支持审计外送")
		return nil, false
	}
	return fs, true
}

// handleAuditForwardTargets 出口清单。
//
// 响应里永远不含凭据原文，只有 hasSecret + 指纹前 8 位。
// 顺带下发 queueMax 与 supportedKinds：前者让控制台把"积压 N / 上界 M"说清楚
// （光有积压数看不出离丢弃还有多远），后者让未实现的类型在界面上就没得选。
func (s *Server) handleAuditForwardTargets(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	fs, ok := s.auditForwardStore(w)
	if !ok {
		return
	}
	targets, err := fs.AuditForwardTargets(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load audit forward targets")
		return
	}
	kinds := []string{}
	for _, k := range []forward.Kind{forward.KindSyslog, forward.KindHTTP} {
		kinds = append(kinds, string(k))
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"targets":        targets,
		"supportedKinds": kinds,
		"queueMax":       fs.AuditForwardQueueMax(),
		// 诚实标注，控制台照抄展示。
		"note": "外送只覆盖配置生效之后产生的审计——历史日志不会补发（要交历史请用 CSV 导出）。" +
			"每条记录都带链序号 seq 与链式 MAC，SIEM 侧可据此独立验真。",
	})
}

// handleSaveAuditForwardTarget 新增 / 修改出口。
func (s *Server) handleSaveAuditForwardTarget(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	fs, ok := s.auditForwardStore(w)
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
	kind := forward.Kind(strings.TrimSpace(b.Kind))
	if !kind.Supported() {
		// 装载期明确拒绝，不存下来再在审计产生时静默失败。
		httpx.Error(w, http.StatusBadRequest,
			"审计外送出口类型 "+b.Kind+" 本版本未实现（当前支持：syslog / http）")
		return
	}
	cfg := "{}"
	if len(b.Config) > 0 {
		cfg = string(b.Config)
	}
	rec, err := fs.SaveAuditForwardTarget(r.Context(), store.AuditForwardTarget{
		ID: b.ID, Name: b.Name, Kind: string(kind), Enabled: b.Enabled, Config: cfg,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save audit forward target")
		return
	}
	// 保存即校验：配置写错要当场知道，而不是等到审计堆满队列才发现发不出去。
	// 构造失败不拒绝保存（管理员可能分两步：先存配置、再设凭据），但把原因带回去。
	var warn string
	if _, berr := s.buildAuditForwarder(r.Context(), rec); berr != nil {
		warn = "配置已保存，但当前还不可用：" + berr.Error()
	}
	s.audit(r, "admin", "保存审计外送出口「"+rec.Name+"」（"+rec.Kind+"，"+enabledZh(rec.Enabled)+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "target": rec, "warning": warn})
}

func enabledZh(v bool) string {
	if v {
		return "已启用"
	}
	return "已停用"
}

func (s *Server) handleDeleteAuditForwardTarget(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	fs, ok := s.auditForwardStore(w)
	if !ok {
		return
	}
	id := r.PathValue("id")
	rec, found, err := fs.AuditForwardTargetByID(r.Context(), id)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load audit forward target")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "审计外送出口不存在")
		return
	}
	if err := fs.DeleteAuditForwardTarget(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete audit forward target")
		return
	}
	// 措辞只记已发生的事实，且把"积压那些条一起没了"说出来——
	// 删除一个还堆着 8000 条待发记录的出口，与删除一个空出口不是一回事。
	s.audit(r, "admin", fmt.Sprintf("删除审计外送出口「%s」（%s，连同其凭据与 %d 条未送出的积压）",
		rec.Name, rec.Kind, rec.Queued), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "discarded": rec.Queued})
}

// handleSetAuditForwardSecret 设置出口凭据（HTTP 出口凭据头的取值）。
//
// **只写不读**：没有任何端点能把它读回去。AAD 绑 target id——把某一行密文剪贴到
// 另一个出口上会直接解不开，而不是悄悄生效。
func (s *Server) handleSetAuditForwardSecret(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	fs, ok := s.auditForwardStore(w)
	if !ok {
		return
	}
	rec, found, err := fs.AuditForwardTargetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load audit forward target")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "审计外送出口不存在")
		return
	}
	if forward.Kind(rec.Kind) != forward.KindHTTP {
		// syslog 出口没有凭据这回事（TLS 只做服务端认证）。收下再永远不用它，
		// 就是又一个"配了但不生效"的开关。
		httpx.Error(w, http.StatusBadRequest,
			"syslog 出口没有可设置的凭据（本版本不做客户端证书认证；需要双向认证请在前面放一跳 stunnel）")
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
		httpx.Error(w, http.StatusBadRequest, "凭据不能为空（不需要认证请把凭据头留空）")
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
	if err := fs.SaveAuditForwardSecret(r.Context(), store.AuditForwardSecret{
		TargetID: rec.ID, Nonce: nonce, Cipher: cipher, Fingerprint: fp,
	}); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save secret")
		return
	}
	s.audit(r, "admin", "更新审计外送出口「"+rec.Name+"」的凭据", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "fingerprint": fp})
}

// handleTestAuditForwardTarget 真发一条测试记录，返回真实结果。
//
// ★不许假成功，也不许把测试记录混进真实审计流：发出去的那条 event 明写
// 「连通性测试」且 seq=0——SIEM 侧看到 seq=0 就知道它不在链上，不会当成断链。
func (s *Server) handleTestAuditForwardTarget(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	fs, ok := s.auditForwardStore(w)
	if !ok {
		return
	}
	rec, found, err := fs.AuditForwardTargetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load audit forward target")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "审计外送出口不存在")
		return
	}
	// 自检要有上界：对端不可达时 TCP 可能吊很久，让管理员盯着转圈的按钮毫无意义。
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	start := time.Now()
	fw, berr := s.buildAuditForwarder(ctx, rec)
	if berr != nil {
		detail := "配置不可用：" + berr.Error()
		_ = fs.RecordAuditForwardResult(ctx, rec.ID, store.AuditForwardFail, detail, time.Now().Unix())
		s.audit(r, "admin", "测试审计外送出口「"+rec.Name+"」失败："+detail, "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": detail})
		return
	}
	probe := store.AuditEntry{
		Time:     time.Now().Format("2006-01-02 15:04:05"),
		Category: "admin",
		User:     "system",
		SrcIP:    "—",
		Event:    "审计外送连通性测试（管理员手动触发，这一条不是真实审计事件、不在防篡改链上）",
		Verdict:  "ok",
	}
	if err := fw.Send(ctx, []forward.Record{probe}); err != nil {
		detail := err.Error()
		_ = fs.RecordAuditForwardResult(ctx, rec.ID, store.AuditForwardFail, detail, time.Now().Unix())
		s.audit(r, "admin", "测试审计外送出口「"+rec.Name+"」失败："+detail, "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "detail": detail})
		return
	}
	detail := "已投递到 " + fw.Target()
	_ = fs.RecordAuditForwardResult(ctx, rec.ID, store.AuditForwardOK, detail, time.Now().Unix())
	s.audit(r, "admin", "测试审计外送出口「"+rec.Name+"」成功（"+detail+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "detail": detail, "elapsedMs": time.Since(start).Milliseconds(),
	})
}

// handleFlushAuditForwardTarget 立即投递：清零退避后当场跑一轮 pump。
//
// ★真实需求，不是装饰按钮：对端连不上时退避会涨到 15 分钟，SIEM 修好之后
// 让管理员干等一刻钟、期间无法确认"到底修好没有"，只会逼出手工删队列这种更坏的操作。
// 它跑的是 PumpAuditForward 同一条代码路径，不做第二份实现。
func (s *Server) handleFlushAuditForwardTarget(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	fs, ok := s.auditForwardStore(w)
	if !ok {
		return
	}
	rec, found, err := fs.AuditForwardTargetByID(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load audit forward target")
		return
	}
	if !found {
		httpx.Error(w, http.StatusNotFound, "审计外送出口不存在")
		return
	}
	if !rec.Enabled {
		// 停用的出口不投递（PumpAuditForward 会跳过它）。当场说清楚，
		// 而不是回一个"已触发"然后什么都没发生。
		httpx.Error(w, http.StatusConflict, "该出口已停用，启用后才会投递")
		return
	}
	reset, err := fs.ResetAuditForwardBackoff(r.Context(), rec.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to reset backoff")
		return
	}
	// 投递本身不带请求 ctx 的取消语义之外的东西；handler 同步等它跑完，
	// 这样按钮点下去看到的就是这一轮的真实结果。
	s.PumpAuditForward(r.Context())
	after, _, _ := fs.AuditForwardTargetByID(r.Context(), rec.ID)
	s.audit(r, "admin", fmt.Sprintf("对审计外送出口「%s」触发立即投递（清零 %d 条退避）", rec.Name, reset), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "reset": reset, "target": after,
	})
}

// ── 构造 ──

// buildAuditForwarder 把一条落库配置装成可发送的出口。
//
// 凭据在这里、且**只在这里**被解密——与 buildNotifyChannel / authsrc.buildProvider
// 同款纪律：「能读密文」的调用点越少，越不容易在某次重构里被扩散到列表路径上。
func (s *Server) buildAuditForwarder(ctx context.Context, rec store.AuditForwardTarget) (forward.Forwarder, error) {
	cfg := rec.Config
	if strings.TrimSpace(cfg) == "" {
		cfg = "{}"
	}
	switch forward.Kind(rec.Kind) {
	case forward.KindSyslog:
		var d syslogTargetDTO
		if err := json.Unmarshal([]byte(cfg), &d); err != nil {
			return nil, fmt.Errorf("syslog 配置不是合法 JSON：%w", err)
		}
		return forward.NewSyslog(forward.SyslogConfig{
			Host: d.Host, Port: d.Port, TLS: d.TLS, ServerName: d.ServerName, CACert: d.CACert,
			Facility: d.Facility, AppName: d.AppName, Hostname: d.Hostname,
			Framing: forward.Framing(d.Framing), EnterpriseID: d.EnterpriseID,
			Timeout: time.Duration(d.TimeoutSec) * time.Second,
		})
	case forward.KindHTTP:
		var d httpTargetDTO
		if err := json.Unmarshal([]byte(cfg), &d); err != nil {
			return nil, fmt.Errorf("http 外送配置不是合法 JSON：%w", err)
		}
		headers := map[string]string{}
		for k, v := range d.Headers {
			headers[k] = v
		}
		if h := strings.TrimSpace(d.SecretHeader); h != "" {
			cred, err := s.auditForwardCredential(ctx, rec)
			if err != nil {
				return nil, err
			}
			if cred == "" {
				return nil, errors.New("配置了凭据头 " + h + " 但尚未设置凭据（PUT …/secret）")
			}
			headers[h] = cred
		}
		return forward.NewHTTP(forward.HTTPConfig{
			URL: d.URL, Headers: headers, CACert: d.CACert,
			Timeout: time.Duration(d.TimeoutSec) * time.Second,
		})
	}
	return nil, errors.New("审计外送出口类型 " + rec.Kind + " 本版本未实现")
}

// auditForwardCredential 解出该出口的凭据原文（唯一解密点）。
func (s *Server) auditForwardCredential(ctx context.Context, rec store.AuditForwardTarget) (string, error) {
	if !rec.HasSecret {
		return "", nil
	}
	fs, ok := s.store.(store.AuditForwardStore)
	if !ok {
		return "", errors.New("当前存储实现不支持审计外送")
	}
	sec, found, err := fs.AuditForwardSecret(ctx, rec.ID)
	if err != nil {
		return "", fmt.Errorf("读取凭据失败：%w", err)
	}
	if !found {
		return "", nil
	}
	box, err := secret.Default()
	if err != nil {
		return "", fmt.Errorf("凭据主密钥不可用：%w", err)
	}
	pt, err := box.Open(rec.ID, sec.Nonce, sec.Cipher)
	if err != nil {
		return "", fmt.Errorf("凭据解密失败：%w", err)
	}
	return string(pt), nil
}

// ── 后台 pump ──

// StartAuditForwardLoop 起审计外送的后台投递循环。ctx 取消即退出；interval<=0 表示不启用。
//
// ★这条循环是整个功能的执行方。没有它，队列只是一张越写越长的表——
// 而"配了外送、SIEM 里什么都没有"恰恰是本项目最典型的静默失效形态。
func (s *Server) StartAuditForwardLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		slog.Warn("审计外送投递循环未启用（间隔 <=0）：已配置的出口不会收到任何审计，队列只增不减")
		return
	}
	if _, ok := s.store.(store.AuditForwardStore); !ok {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			s.PumpAuditForward(ctx)
		}
	}()
}

// PumpAuditForward 跑一轮外送投递：每个启用中的出口各排空一次队列（有上界）。
// 导出给测试与「立即投递」按钮用——同一条代码路径，不做第二份实现。
func (s *Server) PumpAuditForward(ctx context.Context) {
	fs, ok := s.store.(store.AuditForwardStore)
	if !ok {
		return
	}
	// 串行：后台循环与「立即投递」按钮可能同时进来，取批不做认领标记，
	// 并发两轮会把同一批送两遍。
	s.fwdPumpMu.Lock()
	defer s.fwdPumpMu.Unlock()
	targets, err := fs.AuditForwardTargets(ctx)
	if err != nil {
		slog.Error("审计外送：出口清单读取失败，本轮不投递", "err", err.Error())
		return
	}
	for _, t := range targets {
		// 停用的出口不发送，但它的积压**留着**：管理员再启用时应当把这段时间的
		// 审计补送过去（那些条是在启用期入队的，本来就该送）。
		if !t.Enabled {
			continue
		}
		s.reportForwardDrops(ctx, fs, t)
		s.drainForwardTarget(ctx, fs, t)
	}
}

// drainForwardTarget 排空单个出口的到期队列。
func (s *Server) drainForwardTarget(ctx context.Context, fs store.AuditForwardStore, t store.AuditForwardTarget) {
	var fw forward.Forwarder
	for round := 0; round < auditForwardRoundsPerTick; round++ {
		items, err := fs.ClaimAuditForwardBatch(ctx, t.ID, time.Now().Unix(), auditForwardBatchSize)
		if err != nil {
			slog.Error("审计外送：取批失败", "target", t.ID, "err", err.Error())
			return
		}
		if len(items) == 0 {
			return
		}
		// 出口在第一批要发时才构造：没有积压时不去解密凭据、不去解析配置。
		if fw == nil {
			fw, err = s.buildAuditForwarder(ctx, t)
			if err != nil {
				detail := "配置不可用：" + err.Error()
				s.failForwardBatch(ctx, fs, t, items, detail)
				return
			}
		}
		ids := make([]int64, 0, len(items))
		batch := make([]forward.Record, 0, len(items))
		for _, it := range items {
			ids = append(ids, it.ID)
			batch = append(batch, it.Entry)
		}
		if err := fw.Send(ctx, batch); err != nil {
			s.failForwardBatch(ctx, fs, t, items, err.Error())
			return
		}
		if err := fs.AckAuditForwardBatch(ctx, ids); err != nil {
			// 发出去了但没能出队：下一轮会重发这一批（SIEM 侧看到重复的 seq）。
			// 重复远好过丢失，但必须留痕说明为什么会重复。
			slog.Error("审计外送：已成功投递但出队失败，下一轮会重发同一批（重复优于丢失）",
				"target", t.ID, "count", len(ids), "err", err.Error())
			return
		}
		_ = fs.RecordAuditForwardResult(ctx, t.ID, store.AuditForwardOK,
			fmt.Sprintf("已投递 %d 条到 %s", len(batch), fw.Target()), time.Now().Unix())
	}
}

// failForwardBatch 整批留队 + 退避，并如实记录失败。
func (s *Server) failForwardBatch(ctx context.Context, fs store.AuditForwardStore,
	t store.AuditForwardTarget, items []store.AuditForwardItem, detail string) {
	// 退避档位取这一批里**已尝试次数最少**的那条：批内的 attempts 一般相同，
	// 取最小可以避免刚入队的新记录被前面那条老失败的长退避连累。
	minAttempts := items[0].Attempts
	ids := make([]int64, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.ID)
		if it.Attempts < minAttempts {
			minAttempts = it.Attempts
		}
	}
	next := time.Now().Add(forward.Backoff(minAttempts + 1)).Unix()
	if err := fs.RetryAuditForwardBatch(ctx, ids, next, detail); err != nil {
		slog.Error("审计外送：留队重试写入失败", "target", t.ID, "err", err.Error())
	}
	_ = fs.RecordAuditForwardResult(ctx, t.ID, store.AuditForwardFail, detail, time.Now().Unix())
	slog.Warn("审计外送失败，本批留在队列里等待重试（一条都不丢）",
		"target", t.ID, "count", len(ids), "attempts", minAttempts+1, "err", detail)
}

// reportForwardDrops 把队列溢出这件事写进审计。
//
// ★丢弃计数摆在页面上还不够：没人天天盯着那一页。审计里有一条
// 「累计丢弃 N 条」，事后复盘"这段时间的日志为什么在 SIEM 里缺了一截"才有据可查。
// 按出口节流（默认 10 分钟一条），否则溢出期间它会把审计表刷爆。
func (s *Server) reportForwardDrops(ctx context.Context, fs store.AuditForwardStore, t store.AuditForwardTarget) {
	if t.Dropped <= 0 {
		return
	}
	now := time.Now().Unix()
	s.mu.Lock()
	reported := s.fwdDropReported[t.ID]
	lastAt := s.fwdDropReportAt[t.ID]
	if t.Dropped <= reported || now-lastAt < int64(auditForwardDropReportEvery/time.Second) {
		s.mu.Unlock()
		return
	}
	s.fwdDropReported[t.ID] = t.Dropped
	s.fwdDropReportAt[t.ID] = now
	s.mu.Unlock()
	// 上界取**入队时判丢弃真正在用的那一份**（store 里那个），不是重读一遍配置的副本。
	s.auditBG(ctx, "security", fmt.Sprintf(
		"审计外送队列溢出：出口「%s」累计已丢弃 %d 条待外送记录（队列上界 %d），这些审计已落库但不会送达 SIEM",
		t.Name, t.Dropped, fs.AuditForwardQueueMax()), "fail")
}
