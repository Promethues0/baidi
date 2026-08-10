package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"baidi.dev/control/internal/config"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// bootTime 进程启动时间（包加载即固定，约等于进程启动），用于自检 uptime。
var bootTime = time.Now()

// gatewayOnlineWindow 网关心跳新鲜度窗口：超过则视为离线。
const gatewayOnlineWindow = 120 * time.Second

// DiagItem 一项检查的明细行（可展开，如每台网关的在线态/会话数）。
type DiagItem struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Status string `json:"status,omitempty"` // pass | warn | fail（明细行着色，可空）
}

// DiagCheck 一项运维自检结果。
type DiagCheck struct {
	Key      string     `json:"key"`
	Category string     `json:"category"` // control | storage | dataplane | stealth | cluster | identity | posture | security
	Name     string     `json:"name"`
	Status   string     `json:"status"` // pass | warn | fail | skip（skip=该能力未部署，不参与健康分）
	Summary  string     `json:"summary"`
	Metric   string     `json:"metric"`
	Hint     string     `json:"hint"`            // 处置建议（warn/fail 时）
	Items    []DiagItem `json:"items,omitempty"` // 可展开明细（如每台网关）
}

// DiagBundle 一次运维体检的完整结果（控制面真实探测，非种子）。
type DiagBundle struct {
	GeneratedAt string      `json:"generatedAt"`
	Component   string      `json:"component"`
	Version     string      `json:"version"`
	Env         string      `json:"env"`
	Uptime      string      `json:"uptime"`
	Score       int         `json:"score"` // 0-100 健康分（pass=1 / warn=0.5 / fail=0 加权；skip 不进分母）
	Pass        int         `json:"pass"`
	Warn        int         `json:"warn"`
	Fail        int         `json:"fail"`
	Skip        int         `json:"skip"`
	Checks      []DiagCheck `json:"checks"`
}

// pinger 可选的存储健康探测能力（SQLiteStore 实现）。
type pinger interface {
	Ping(ctx context.Context) error
}

// handleDiag 运维诊断：对控制面各子系统做一次真实体检（admin）。
func (s *Server) handleDiag(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	ctx := r.Context()
	up := humanizeDuration(time.Since(bootTime))

	checks := []DiagCheck{
		{
			Key: "control", Category: "control", Name: "控制面 baidi-control",
			Status: "pass", Summary: "控制中心进程运行正常，API 响应中",
			Metric: "v" + Version + " · 运行 " + up,
		},
		s.checkDatabase(ctx),
		s.checkAuditDisk(ctx),
		s.checkGateways(),
		s.checkStealth(),
		s.checkCluster(),
		s.checkAuthSources(ctx),
		s.checkPosture(ctx),
		s.checkSecurity(),
	}

	b := DiagBundle{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Component:   "baidi-control · 控制中心",
		Version:     Version, Env: s.env, Uptime: up,
		Checks: checks,
	}
	for _, c := range checks {
		switch c.Status {
		case "pass":
			b.Pass++
		case "warn":
			b.Warn++
		case "fail":
			b.Fail++
		case "skip":
			b.Skip++
		}
	}
	// skip（能力未部署）不进分母：单机形态不该因为"没有集群"被扣健康分——
	// 那会诱导运维去追一个本版本不存在的能力。
	if n := len(checks) - b.Skip; n > 0 {
		b.Score = int((float64(b.Pass)*100+float64(b.Warn)*50)/float64(n) + 0.5)
	}

	s.audit(r, "admin", "运行系统自检（运维诊断）", "ok")
	httpx.JSON(w, http.StatusOK, b)
}

// checkDatabase 探测管理数据库连接健康与往返延迟。
func (s *Server) checkDatabase(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "db", Category: "storage", Name: "管理数据库 SQLite"}
	p, ok := s.store.(pinger)
	if !ok {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "存储后端不支持健康探测（非 SQLite 持久化）"
		c.Hint = "确认控制面以 SQLite/持久化后端启动"
		return c
	}
	start := time.Now()
	if err := p.Ping(ctx); err != nil {
		c.Status, c.Metric = "fail", "不可达"
		c.Summary = "数据库连接探测失败：" + err.Error()
		c.Hint = "检查 BAIDI_DB 路径与磁盘可写性，必要时重启控制面"
		return c
	}
	lat := time.Since(start)
	c.Metric = "往返 " + humanizeLatency(lat)
	if lat > 200*time.Millisecond {
		c.Status = "warn"
		c.Summary = "数据库连接可用但往返延迟偏高"
		c.Hint = "排查磁盘 IO / WAL 检查点 / busy_timeout"
		return c
	}
	c.Status = "pass"
	c.Summary = "数据库连接正常，读写可用"
	return c
}

// auditDiskProber 审计存储的实测能力（SQLiteStore 实现）。
// Memory 种子后端不具备——那就如实报"无法实测"，而不是把种子编的 62% 当水位。
type auditDiskProber interface {
	AuditDiskStat(ctx context.Context) (store.AuditDiskStat, error)
}

// checkAuditDisk 检查审计日志存储水位：行数 COUNT(*) + 库文件实际大小 + 文件系统实测余量。
func (s *Server) checkAuditDisk(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "audit-disk", Category: "storage", Name: "审计日志留存"}
	p, ok := s.store.(auditDiskProber)
	if !ok {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "存储后端不支持磁盘水位实测（非 SQLite 持久化），不虚报占用率"
		c.Hint = "以 SQLite 持久化启动控制面后重新体检"
		return c
	}
	d, err := p.AuditDiskStat(ctx)
	if err != nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "审计磁盘水位实测失败：" + err.Error()
		c.Hint = "检查审计存储后端与库文件可读性"
		return c
	}
	retain := "未配置滚动清理"
	if d.RetainDays > 0 {
		retain = fmt.Sprintf("留存 %d 天", d.RetainDays)
	}
	if !d.FSSupported {
		c.Status = "warn"
		c.Metric = fmt.Sprintf("审计 %d 行 · 库文件 %s · %s", d.Rows, humanBytes(uint64(d.DBBytes)), retain)
		c.Summary = "当前平台不支持文件系统容量探测，磁盘水位未知"
		c.Hint = "控制面部署面为 darwin/linux，请在其上运行体检"
		return c
	}
	usedPct := d.UsedPct()
	c.Metric = fmt.Sprintf("审计 %d 行 · 库文件 %s · 磁盘余 %s / %s（占用 %d%%）· %s",
		d.Rows, humanBytes(uint64(d.DBBytes)), humanBytes(d.FSFreeBytes), humanBytes(d.FSTotalBytes), usedPct, retain)
	switch {
	case usedPct >= 90:
		c.Status = "fail"
		c.Summary = "审计库所在磁盘水位过高，存在丢日志风险"
		c.Hint = "立即清理/扩容磁盘或缩短 BAIDI_AUDIT_RETENTION_DAYS 留存周期"
	case usedPct >= 75:
		c.Status = "warn"
		c.Summary = "审计库所在磁盘水位偏高"
		c.Hint = "关注增长趋势，规划扩容或归档"
	case d.RetainDays <= 0:
		c.Status = "warn"
		c.Summary = "磁盘水位健康，但未配置审计滚动清理，审计库会无界增长"
		c.Hint = "设置 BAIDI_AUDIT_RETENTION_DAYS（默认 180）启用超期轮转"
	default:
		c.Status = "pass"
		c.Summary = "审计日志留存正常，磁盘水位健康"
	}
	return c
}

// checkGateways 检查数据面网关在线情况（基于注册心跳新鲜度）。
func (s *Server) checkGateways() DiagCheck {
	c := DiagCheck{Key: "gateways", Category: "dataplane", Name: "数据面网关在线"}
	now := time.Now().Unix()
	window := int64(gatewayOnlineWindow / time.Second)
	s.mu.Lock()
	total := len(s.gateways)
	online, clients, tunnels := 0, 0, 0
	for id, g := range s.gateways {
		up := now-g.LastSeen <= window
		if up {
			online++
			clients += g.Clients
			tunnels += g.Tunnels
		}
		st := "pass"
		state := "在线"
		if !up {
			st, state = "fail", "心跳超时"
		}
		c.Items = append(c.Items, DiagItem{
			Label:  id,
			Value:  fmt.Sprintf("%s · 会话 %d · 隧道 %d · 客户端 %d", state, len(s.gwSess[id]), g.Tunnels, g.Clients),
			Status: st,
		})
	}
	s.mu.Unlock()
	c.Metric = fmt.Sprintf("在线 %d / 注册 %d · 客户端 %d · 隧道 %d", online, total, clients, tunnels)
	switch {
	case total == 0:
		c.Status = "warn"
		c.Summary = "尚无数据面网关注册（控制面可独立运行）"
		c.Hint = "以 -control 指向本控制面启动 baidi-gateway 即自动注册"
	case online == 0:
		c.Status = "fail"
		c.Summary = "已注册网关全部心跳超时，数据面可能不可用"
		c.Hint = "检查网关进程与到控制面的网络连通"
	case online < total:
		c.Status = "warn"
		c.Summary = fmt.Sprintf("%d 台网关心跳超时", total-online)
		c.Hint = "排查离线网关节点"
	default:
		c.Status = "pass"
		c.Summary = "全部数据面网关在线，心跳正常"
	}
	return c
}

// checkStealth 检查 SPA 服务隐身。数据源与 GET /gateways 同一份：经 mTLS 注册心跳
// 上报的在线网关清单（s.gateways）。此前读的是 Memory.Gateway 种子拓扑——
// 网关一台没起，诊断页也能画出"隐身生效"，运维对着编造的拓扑什么都排查不了。
// 控制面并不从外部实测端口可见性，所以只陈述网关上报的事实：谁在线、隐身口在哪。
func (s *Server) checkStealth() DiagCheck {
	c := DiagCheck{Key: "spa", Category: "stealth", Name: "SPA 服务隐身"}
	now := time.Now().Unix()
	window := int64(gatewayOnlineWindow / time.Second)
	s.mu.Lock()
	total := len(s.gateways)
	online := 0
	for id, g := range s.gateways {
		up := now-g.LastSeen <= window
		st, state := "pass", "在线"
		if up {
			online++
		} else {
			st, state = "warn", "心跳超时"
		}
		c.Items = append(c.Items, DiagItem{
			Label:  id,
			Value:  fmt.Sprintf("%s · SPA 敲门口 %s · 隧道口 %s", state, g.SPA, g.Proxy),
			Status: st,
		})
	}
	s.mu.Unlock()
	c.Metric = fmt.Sprintf("在线 %d / 注册 %d", online, total)
	switch {
	case total == 0:
		c.Status = "warn"
		c.Summary = "无网关经 mTLS 注册，隐身状态未知"
		c.Hint = "以 -control + mTLS 证书启动 baidi-gateway，注册后此处才有事实可报"
	case online == 0:
		c.Status = "warn"
		c.Summary = "已注册网关全部心跳超时，隐身状态未知"
		c.Hint = "检查网关进程与到控制面的网络连通"
	default:
		c.Status = "pass"
		c.Summary = fmt.Sprintf("%d 台在线网关上报了 SPA 敲门端口（未授权包默认丢弃）；控制面不从外部实测端口可见性", online)
	}
	return c
}

// checkCluster 集群高可用。白帝当前是单机形态：没有节点发现、没有选主、没有主备——
// 这项检查从前读 Memory.System 种子拓扑输出"主备冗余就绪"，是给不存在的能力背书。
// 现在如实标记 skip（能力未部署，不参与健康分），文案只说事实。
func (s *Server) checkCluster() DiagCheck {
	return DiagCheck{
		Key: "cluster", Category: "cluster", Name: "集群高可用",
		Status:  "skip",
		Summary: "集群未部署：白帝当前为单机形态，无节点发现/选主机制",
		Metric:  "单机 · 1 进程 + SQLite",
		Hint:    "本版本无 HA 能力；如需冗余请依赖外部手段（备份恢复/冷备），不要按'集群健康'规划容量",
	}
}

// checkAuthSources 盘点认证源配置。数据源改为 SQLite auth_sources 真实配置
// （与 GET /api/v1/authsrc/sources 同一份）。此前读 Memory.AuthSrc 种子，
// 连代码层拒绝创建的 radius/短信源都能被报成"在线"。
// 连通性只有 probe（测试连接）才知道，这里绝不假称"可达/在线"。
func (s *Server) checkAuthSources(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "authsrc", Category: "identity", Name: "认证源配置"}
	as := s.authSrcStore()
	if as == nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "存储后端不支持认证源配置（非 SQLite 持久化）"
		c.Hint = "以 SQLite 持久化启动控制面后重新体检"
		return c
	}
	recs, err := as.AuthSources(ctx)
	if err != nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "认证源配置读取失败"
		c.Hint = "检查 auth_sources 表"
		return c
	}
	enabled := 0
	for _, r := range recs {
		st, state := "pass", "已启用"
		if r.Enabled {
			enabled++
		} else {
			st, state = "warn", "已停用"
		}
		c.Items = append(c.Items, DiagItem{Label: r.Name, Value: r.Kind + " · " + state, Status: st})
	}
	c.Metric = fmt.Sprintf("启用 %d / 配置 %d", enabled, len(recs))
	switch {
	case len(recs) == 0:
		c.Status = "warn"
		c.Summary = "未配置任何认证源"
		c.Hint = "至少配置一个认证源（本地目录为内置种子，缺失说明库被改过）"
	case enabled == 0:
		c.Status = "warn"
		c.Summary = "认证源全部处于停用状态，外部登录不可用"
		c.Hint = "在认证源接入页启用需要的源"
	default:
		c.Status = "pass"
		c.Summary = fmt.Sprintf("已配置 %d 个认证源（连通性以「测试连接」实测为准）", len(recs))
	}
	return c
}

// checkPosture 基于态势总览评估当前访问威胁压力。
// 威胁三元组在 SQLite 后端来自 audit_log 真实聚合（overview_sqlite.go）；
// 纯 Memory 后端只有种子，如实降级为 warn 而不是拿种子数字装体检。
// 在线数不用 ov.Sessions（那是种子），用网关上报的真实会话（与 handleOverview 同源）。
func (s *Server) checkPosture(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "posture", Category: "posture", Name: "访问威胁压力"}
	if _, ok := s.store.(auditDiskProber); !ok {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "存储后端为内存演示种子，态势数据非实测，不参与体检判定"
		c.Hint = "以 SQLite 持久化启动控制面后重新体检"
		return c
	}
	ov, err := s.store.Overview(ctx)
	if err != nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "态势数据读取失败"
		c.Hint = "检查态势聚合数据源"
		return c
	}
	t := ov.Threats
	sess := "—（无网关上报）"
	if n := s.onlineSessionCount(); n >= 0 {
		sess = fmt.Sprintf("%d", n)
	}
	c.Metric = fmt.Sprintf("拒绝 %d · 失败 %d · 二次鉴权 %d · 在线 %s", t.Rejected, t.Failed, t.Secondary, sess)
	switch {
	case t.Failed >= 100:
		c.Status = "fail"
		c.Summary = "登录失败激增，疑似口令爆破"
		c.Hint = "核查审计中心高频失败源，必要时联动封禁"
	case t.Failed >= 40:
		c.Status = "warn"
		c.Summary = "登录失败数偏高，关注异常登录"
		c.Hint = "结合用户状态页排查锁定账号"
	default:
		c.Status = "pass"
		c.Summary = "访问态势平稳，拒绝/二次鉴权为策略正常拦截"
	}
	return c
}

// checkSecurity 检查 JWT 密钥强度与传输加密拓扑（诚实反映控制面回环 HTTP + nginx 前置 TLS）。
func (s *Server) checkSecurity() DiagCheck {
	c := DiagCheck{Key: "secret", Category: "security", Name: "密钥与传输安全"}
	legacyOn := s.keys.AcceptsLegacy()
	defaultSecret := legacyOn && s.keys.LegacyIs(config.DefaultJWTSecret)
	c.Items = []DiagItem{
		{Label: "令牌签名", Value: "Ed25519 (EdDSA) · 按用途分密钥", Status: "pass"},
		{Label: "会话密钥 kid", Value: s.keys.SessKid(), Status: "pass"},
		{Label: "敲门密钥 kid", Value: s.keys.KnockKid() + "（仅此公钥分发给数据面）", Status: "pass"},
	}
	switch {
	case defaultSecret && s.env == "prod":
		c.Status, c.Metric = "fail", "默认共享密钥 · 生产"
		c.Summary = "生产仍接受默认 HS256 共享密钥签发的令牌，任何持该密钥者可伪造 admin"
		c.Hint = "注入强随机 BAIDI_JWT_SECRET，并尽快置 BAIDI_ACCEPT_HS256=0 关闭迁移窗口"
	case legacyOn:
		c.Status, c.Metric = "warn", "迁移窗口开启"
		c.Summary = "令牌已切 Ed25519 非对称签名，但仍接受存量 HS256 令牌（升级兼容窗口）"
		c.Hint = "存量 8h 会话令牌全部自然过期后，置 BAIDI_ACCEPT_HS256=0 收口"
		c.Items = append(c.Items, DiagItem{Label: "HS256 兼容", Value: "仍接受（迁移期）", Status: "warn"})
	default:
		c.Status, c.Metric = "pass", "非对称签名 · 已收口"
		c.Summary = "令牌由 control 私钥签发，数据面只持公钥、不具备签发能力；HS256 兼容已关闭"
		c.Items = append(c.Items, DiagItem{Label: "HS256 兼容", Value: "已关闭", Status: "pass"})
	}
	return c
}

// humanizeDuration 把时长格式化为中文可读形式。
func humanizeDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时 %d 分", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%d 天 %d 小时", int(d.Hours())/24, int(d.Hours())%24)
	}
}

// humanizeLatency 把往返延迟格式化为 µs/ms。
func humanizeLatency(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// humanBytes 把字节数格式化为 B/KB/MB/GB（1024 进制）。
func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}
