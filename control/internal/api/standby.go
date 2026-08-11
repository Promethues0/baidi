package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/standby"
	"baidi.dev/control/internal/upgrade"
)

// 控制面温备（warm standby，PRD 15.5 / FR-ARCH-03）的主机侧。
//
//	GET  /api/v1/standby/backup   备机拉一份加密配置备份（**只挂 mTLS 监听**，CN 须 standby-*）
//	POST /api/v1/standby/status   备机回报「校验通过并落盘」/「本轮失败」
//
// ★为什么不能用管理员会话令牌拉备份：备机是**机器身份**，而这份备份是整套系统的
// 全部信任材料（CA 私钥、三把签名私钥、审计链密钥、认证源凭据、IPSec PSK、整个库）。
// 挂在明文口 + Bearer 上意味着任何一次令牌泄露都等于系统被完整复制走，且只留下
// 一条看起来很正常的「导出配置备份」审计。所以走 mTLS，与网关同一套 CA、
// 以 CN 前缀分权（照 ipsec- 的既有做法）。明文口对 /api/v1/standby/ 一律 403。
//
// ★为什么复用 upgrade.CreateBackup 而不另造一套同步格式：再造一套就是第二个
// 「哪些材料算完整」的定义，两者迟早会分叉——而分叉的表现是切换那天才发现少了个文件。

// standbyPullAuditWindow 「备机来拉过」审计的节流窗口。
//
// 同步是周期动作（默认 10 分钟一轮，下限 1 分钟），每轮两条审计在默认节奏下无所谓，
// 但把间隔调到下限就会开始刷屏。**只节流成功那条**：失败一条都不许省——
// 「备机连续拉失败」正是这套机制唯一需要被看见的信号。
const standbyPullAuditWindow = 5 * time.Minute

// standbyStaleFromEnv 解析 BAIDI_STANDBY_STALE_SECONDS。
// 非法/缺省/非正值一律落回 standby.DefaultStaleAfter——**没有"永不判落后"这一档**：
// 一个能把阈值关掉的开关，等于给"备机其实早就不同步了"配一块永久绿灯。
func standbyStaleFromEnv(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return standby.DefaultStaleAfter
	}
	return time.Duration(n) * time.Second
}

// handleStandbyBackup 备机拉取加密配置备份（mTLS，CN standby-*）。
func (s *Server) handleStandbyBackup(w http.ResponseWriter, r *http.Request) {
	node := GatewayCN(r.Context())
	if s.standbyPass == "" {
		// fail-closed：没有口令就没有加密，而不加密的备份绝不能出这台机器。
		httpx.Error(w, http.StatusServiceUnavailable,
			"温备同步未启用：主机未配置 BAIDI_STANDBY_PASSPHRASE（备份必须加密，没有口令就不产出）")
		return
	}
	sources, cleanup, err := s.backupSources(r.Context())
	defer cleanup()
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	meta := upgrade.BackupMeta{
		Version:   Version,
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		Note:      "温备同步 → " + node,
	}
	var buf bytes.Buffer
	if err := upgrade.CreateBackup(&buf, meta, s.standbyPass, sources); err != nil {
		s.auditAs(r, node, "system", "温备节点拉取配置备份失败："+err.Error(), "fail")
		httpx.Error(w, http.StatusInternalServerError, "备份生成失败："+err.Error())
		return
	}
	if s.sb != nil {
		if err := s.sb.NoteStandbyPull(r.Context(), node, "", time.Now().Unix()); err != nil {
			// 记不上台账不该让同步失败——备机手上那份备份的价值与台账无关。
			slog.Error("登记温备拉取失败", "node", node, "err", err)
		}
	}
	if s.throttleStandbyAudit(node) {
		s.auditAs(r, node, "system",
			fmt.Sprintf("温备节点拉取配置备份（%d 项材料，%d 字节）", len(sources), buf.Len()), "ok")
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=baidi-standby.bak")
	_, _ = w.Write(buf.Bytes())
}

// handleStandbyStatus 备机回报本轮同步结果（mTLS，CN standby-*）。
//
// ★节点 id 取自证书 CN，**不采信请求体**：按自报的名字落库的话，一台备机
// 可以顶着另一台的名字回报"同步正常"，而那台真出问题的在页面上永远是绿的。
// ★落库时间用**服务端时间**：客户端时钟不参与任何新鲜度判定（一台时钟快 3 小时的
// 备机会把自己显示成"刚同步过"）。
func (s *Server) handleStandbyStatus(w http.ResponseWriter, r *http.Request) {
	node := GatewayCN(r.Context())
	if s.sb == nil {
		httpx.Error(w, http.StatusServiceUnavailable,
			"当前后端不支持温备台账（需要 SQLite 存储；纯内存演示栈无此能力）")
		return
	}
	var b struct {
		Addr            string `json:"addr"`
		IntervalSec     int    `json:"intervalSec"`
		Status          string `json:"status"` // ok | fail
		Detail          string `json:"detail"`
		BackupVersion   string `json:"backupVersion"`
		BackupCreatedAt string `json:"backupCreatedAt"`
		SHA256          string `json:"sha256"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid payload")
		return
	}
	ok := strings.TrimSpace(strings.ToLower(b.Status)) == "ok"
	now := time.Now().Unix()
	n := standby.Node{
		NodeID: node, Addr: trimTo(b.Addr, 128), IntervalSec: b.IntervalSec,
		BackupVersion: trimTo(b.BackupVersion, 64), BackupCreatedAt: trimTo(b.BackupCreatedAt, 32),
		BackupSHA256: trimTo(b.SHA256, 64), LastDetail: trimTo(b.Detail, 512),
	}
	if err := s.sb.SaveStandbyStatus(r.Context(), n, ok, now); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "登记同步状态失败")
		return
	}
	switch {
	case !ok:
		s.auditAs(r, node, "system",
			"温备节点回报同步失败："+orElse(n.LastDetail, "（无详情）"), "fail")
	case s.throttleStandbyAudit(node + "|status"):
		s.auditAs(r, node, "system", fmt.Sprintf(
			"温备节点回报同步成功（备份版本 %s，生成于 %s，sha256 %s…）",
			orElse(n.BackupVersion, "未知"), orElse(n.BackupCreatedAt, "未知"),
			shortHash(n.BackupSHA256)), "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "nodeId": node, "recordedAt": now})
}

// handleStandbyPlaintextDenied 明文口对温备接口的显式拒绝。
//
// ★为什么专门挂一个拒绝 handler 而不是让它 404：404 会被排查的人读成"版本不对/路径写错"，
// 于是去改路径；说清楚"这条路只在 mTLS 口上"才会让人去配证书。
// 顺带它也是那条纪律的可测断言点——**管理员令牌永远拉不走备份**。
func (s *Server) handleStandbyPlaintextDenied(w http.ResponseWriter, _ *http.Request) {
	httpx.Error(w, http.StatusForbidden,
		"温备同步接口只在 mTLS 端口提供（BAIDI_MTLS_ADDR），且要求 CN 以 "+standby.CNPrefix+
			" 开头的客户端证书：备机是机器身份，管理员令牌不能用来拉走整套信任材料")
}

// throttleStandbyAudit 报告这条成功审计现在该不该记（按 key 5 分钟一条）。
func (s *Server) throttleStandbyAudit(key string) bool {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.standbyAudited[key]; ok && now-last < int64(standbyPullAuditWindow/time.Second) {
		return false
	}
	s.standbyAudited[key] = now
	return true
}

// clusterView 集群区块的唯一答案：System 页与 /diag checkCluster 都读它。
//
// ★三态严格分开，不许合并成一句"未部署"：
//
//	后端记不下来（纯内存栈）→ Unsupported，skip
//	读库失败              → Unknown，**warn**（读不到就说读不到，绝不回"健康"）
//	读到了                → Evaluate 真判定（未配置 / 新鲜 / 落后）
func (s *Server) clusterView(ctx context.Context) standby.ClusterView {
	if s.sb == nil {
		return standby.Unsupported("当前后端不支持温备台账（需要 SQLite 存储；纯内存演示栈无此能力）")
	}
	nodes, err := s.sb.StandbyNodes(ctx)
	if err != nil {
		return standby.Unknown("备机台账 standby_nodes 读取失败：" + err.Error())
	}
	v := standby.Evaluate(nodes, time.Now(), s.standbyStale, s.issuedStandbyCNs(ctx)...)
	// 配了备机却没配口令 = 同步端点一律 503，备机会持续失败。这件事在节点状态上
	// 要过几轮才看得出来（先是"最近一次失败"，再是"落后"），在这里当场说清楚。
	if v.Deployed && s.standbyPass == "" {
		v.Status = "warn"
		v.Note += "　⚠ 主机未配置 BAIDI_STANDBY_PASSPHRASE：同步端点一律回 503，备机拉不到任何东西。"
	}
	return v
}

// issuedStandbyCNs 列出**已签发且未吊销**的备机证书 CN（去重、有序）。
//
// 它是 clusterView 唯一的交叉核对材料：备机台账为空时，有没有签过备机证书决定了
// 这是「根本没配」还是「配了但一次都没连上来」——后者是切换那天才发现没有备份的形态。
// 读不到就当没有（这里只影响措辞的精细度，不影响任何安全判定）。
func (s *Server) issuedStandbyCNs(ctx context.Context) []string {
	certs, err := s.store.GatewayCerts(ctx)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range certs {
		if c.Revoked || !strings.HasPrefix(c.GatewayID, standby.CNPrefix) || seen[c.GatewayID] {
			continue
		}
		seen[c.GatewayID] = true
		out = append(out, c.GatewayID)
	}
	sort.Strings(out) // 页面文案要稳定，不能随查询顺序抖
	return out
}

// trimTo 截断备机自报的字符串字段（它们直接进库并显示在页面上）。
func trimTo(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > n {
		return string([]rune(s)[:n])
	}
	return s
}

// shortHash 取哈希前 16 位做展示（审计里记全串没有意义，也让行变得难读）。
func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return orElse(h, "未知")
}
