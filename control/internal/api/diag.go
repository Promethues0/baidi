package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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
	Status   string     `json:"status"` // pass | warn | fail
	Summary  string     `json:"summary"`
	Metric   string     `json:"metric"`
	Hint     string     `json:"hint"`             // 处置建议（warn/fail 时）
	Items    []DiagItem `json:"items,omitempty"`  // 可展开明细（如每台网关）
}

// DiagBundle 一次运维体检的完整结果（控制面真实探测，非种子）。
type DiagBundle struct {
	GeneratedAt string      `json:"generatedAt"`
	Component   string      `json:"component"`
	Version     string      `json:"version"`
	Env         string      `json:"env"`
	Uptime      string      `json:"uptime"`
	Score       int         `json:"score"` // 0-100 健康分（pass=1 / warn=0.5 / fail=0 加权）
	Pass        int         `json:"pass"`
	Warn        int         `json:"warn"`
	Fail        int         `json:"fail"`
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
		s.checkStealth(ctx),
		s.checkCluster(ctx),
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
		}
	}
	if n := len(checks); n > 0 {
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

// checkAuditDisk 检查审计日志存储水位。
func (s *Server) checkAuditDisk(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "audit-disk", Category: "storage", Name: "审计日志留存"}
	ab, err := s.store.Audit(ctx)
	if err != nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "审计磁盘水位读取失败"
		c.Hint = "检查审计存储后端"
		return c
	}
	d := ab.Disk
	c.Metric = fmt.Sprintf("占用 %d%% · %dGB · 留存 %d 天", d.UsedPct, d.TotalGB, d.RetainDays)
	switch {
	case d.UsedPct >= 90:
		c.Status = "fail"
		c.Summary = "审计磁盘水位过高，存在丢日志风险"
		c.Hint = "立即清理/扩容审计存储或缩短留存周期"
	case d.UsedPct >= 75:
		c.Status = "warn"
		c.Summary = "审计磁盘水位偏高"
		c.Hint = "关注增长趋势，规划扩容或归档"
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

// checkStealth 检查 SPA 服务隐身是否生效。
func (s *Server) checkStealth(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "spa", Category: "stealth", Name: "SPA 服务隐身"}
	gb, err := s.store.Gateway(ctx)
	if err != nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "隐身状态读取失败"
		c.Hint = "检查网关与控制面的 SPA 状态上报"
		return c
	}
	spa := gb.Spa
	c.Metric = fmt.Sprintf("%s · 守护 %d 端口", spa.Generation, len(spa.ProtectedPorts))
	switch {
	case spa.Hidden && spa.KnockOK:
		c.Status = "pass"
		c.Summary = "SPA 单包授权生效，受保护端口对未授权源不可见"
	case spa.Hidden && !spa.KnockOK:
		c.Status = "warn"
		c.Summary = "端口已隐身，但敲门链路自检未通过"
		c.Hint = "核对网关与控制面 SPA 共享密钥（BAIDI_JWT_SECRET）"
	default:
		c.Status = "fail"
		c.Summary = "服务隐身未生效，受保护端口可能暴露"
		c.Hint = "确认网关以 SPA 隐身模式启动"
	}
	return c
}

// checkCluster 检查集群节点健康与高可用冗余。
func (s *Server) checkCluster(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "cluster", Category: "cluster", Name: "集群高可用"}
	sys, err := s.store.System(ctx)
	if err != nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "集群状态读取失败"
		c.Hint = "检查集群状态数据源"
		return c
	}
	nodes := make([]store.ClusterNode, 0, len(sys.Cluster.LocalNodes)+len(sys.Cluster.DistNodes))
	nodes = append(nodes, sys.Cluster.LocalNodes...)
	nodes = append(nodes, sys.Cluster.DistNodes...)
	healthy, degraded, down := 0, 0, 0
	for _, n := range nodes {
		switch n.Status {
		case "healthy":
			healthy++
		case "degraded":
			degraded++
		default:
			down++
		}
	}
	c.Metric = fmt.Sprintf("健康 %d · 降级 %d · 故障 %d / 共 %d", healthy, degraded, down, len(nodes))
	switch {
	case down > 0:
		c.Status = "fail"
		c.Summary = fmt.Sprintf("%d 个集群节点故障", down)
		c.Hint = "立即排查故障节点，确认主备切换"
	case degraded > 0:
		c.Status = "warn"
		c.Summary = fmt.Sprintf("%d 个集群节点降级", degraded)
		c.Hint = "关注降级节点负载与链路"
	case len(sys.Cluster.LocalNodes) < 2:
		c.Status = "warn"
		c.Summary = "本地为单节点，无高可用冗余"
		c.Hint = "部署备节点形成 HA 主备"
	default:
		c.Status = "pass"
		c.Summary = "集群节点全部健康，主备冗余就绪"
	}
	return c
}

// checkAuthSources 检查认证源可达状态。
func (s *Server) checkAuthSources(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "authsrc", Category: "identity", Name: "认证源可达"}
	ab, err := s.store.AuthSrc(ctx)
	if err != nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "认证源状态读取失败"
		c.Hint = "检查认证源配置数据源"
		return c
	}
	total := len(ab.Sources)
	online, problem := 0, 0
	var bad []string
	for _, src := range ab.Sources {
		if src.Status == "online" {
			online++
		} else {
			problem++
			bad = append(bad, src.Name)
		}
	}
	c.Metric = fmt.Sprintf("在线 %d / 接入 %d", online, total)
	switch {
	case total == 0:
		c.Status = "warn"
		c.Summary = "未接入任何认证源"
		c.Hint = "至少接入一个主认证源（本地/AD/LDAP）"
	case problem > 0:
		c.Status = "warn"
		c.Summary = fmt.Sprintf("%d 个认证源异常：%s", problem, strings.Join(bad, "、"))
		c.Hint = "核对异常认证源的连通与凭据"
	default:
		c.Status = "pass"
		c.Summary = "全部认证源在线可达"
	}
	return c
}

// checkPosture 基于态势总览评估当前访问威胁压力。
func (s *Server) checkPosture(ctx context.Context) DiagCheck {
	c := DiagCheck{Key: "posture", Category: "posture", Name: "访问威胁压力"}
	ov, err := s.store.Overview(ctx)
	if err != nil {
		c.Status, c.Metric = "warn", "—"
		c.Summary = "态势数据读取失败"
		c.Hint = "检查态势聚合数据源"
		return c
	}
	t := ov.Threats
	c.Metric = fmt.Sprintf("拒绝 %d · 失败 %d · 二次鉴权 %d · 在线 %d", t.Rejected, t.Failed, t.Secondary, ov.Sessions)
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
	defaultSecret := string(s.secret) == config.DefaultJWTSecret
	switch {
	case defaultSecret && s.env == "prod":
		c.Status, c.Metric = "fail", "默认密钥 · 生产"
		c.Summary = "生产环境仍使用默认 JWT 密钥，令牌可被伪造"
		c.Hint = "立即经 BAIDI_JWT_SECRET 注入高强度随机密钥并重启"
	case defaultSecret:
		c.Status, c.Metric = "warn", "默认密钥 · 开发"
		c.Summary = "使用开发默认 JWT 密钥（控制面回环 HTTP，前置 nginx 终止 TLS）"
		c.Hint = "上线前经 BAIDI_JWT_SECRET 注入随机密钥"
	default:
		c.Status, c.Metric = "pass", "自定义密钥"
		c.Summary = "JWT 密钥已自定义；控制面经前置 nginx 终止 TLS，数据面国密证书由网关自治"
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
