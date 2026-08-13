package api

// License 管理（PRD ch15）REST 与容量执行点。
//
//	GET  /api/v1/license   状态 + 用量（读=任意管理员，角色现算）
//	POST /api/v1/license   导入/替换（PermSystem；未配置发行公钥一律拒，照升级包验签先例）
//
// ★刻意没有 DELETE：导入过 license 的部署只能用另一份有效 license 替换。
// 若允许"删掉回演示模式"，容量上限就等价于一个自愿开关——谁被限住谁就删。
// （持库文件写权限的人当然还是能清掉 settings 行；这套机制演示的是容量执行，
// 不是防拷贝，边界见 licenseBoundaries。）
//
// ★执行点只有真正有闸的两维：
//   - 用户席位：POST /users、POST /admins 的建号分支（提权已有账号不占新席位）；
//   - 网关席位：POST /pki/gateway-certs 给**新 gatewayId** 签发（换证不占新席位，
//     吊销即释放——计数就是「未吊销证书的去重 gatewayId」）。
//
// ★外部认证源自动建号**刻意不硬拦**：拦在登录链路，第 N+1 个 AD 用户会在
// 工作日中间收到一句"登录失败"，而管理员没有任何预警——那是把容量条款做成了
// 随机拒绝服务。超限走的是如实呈现：状态页亮红 + GET /license 的 usage 标超限。

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/license"
	"baidi.dev/control/internal/store"
)

const licenseSettingKey = "license.blob"

// settingReader / settingWriter settings 表的最小读写口（SQLiteStore 实现；
// Memory 不实现 → license 在内存种子模式下不可导入、恒为 demo）。
type settingReader interface {
	Setting(ctx context.Context, k string) (string, bool, error)
}
type settingWriter interface {
	SetSetting(ctx context.Context, k, v string) error
}

// licenseBoundaries 页面上的诚实声明。
func licenseBoundaries() []string {
	return []string{
		"这套机制演示的是「容量执行」（建号与签发网关证书两处硬闸），不是防拷贝：" +
			"持数据库文件写权限的人可以清掉 license 记录，正如持二进制的人可以改代码。",
		"外部认证源自动建号不硬拦：硬拦意味着第 N+1 个 AD 用户在工作日中间收到一句" +
			"莫名的登录失败。超限如实亮红，由管理员决定扩容还是清理账号。",
		"过期后存量业务（登录/隧道/策略）照常，仅新增容量（建号/签网关证书）被拒——" +
			"到期日让全员断连的产品行为，这里刻意不复刻。",
		"发行私钥在发行方离线保管（control/cmd/baidi-license），控制面只持公钥；" +
			"未配置公钥时导入一律被拒，而不是跳过验签（跳过的验签比没有验签更糟）。",
	}
}

// licenseStatus 读当前状态。每次现算不缓存——导入/到期要立刻算数，
// 与管理员角色现算同一条纪律。
func (s *Server) licenseStatus(r *http.Request) license.Status {
	st, ok := s.store.(settingReader)
	if !ok {
		return license.Status{Mode: license.ModeDemo}
	}
	blob, found, err := st.Setting(r.Context(), licenseSettingKey)
	if err != nil {
		// 读失败 ≠ 没有：按 invalid（fail-closed）处理并说明。
		// 当 demo 处理会在库抖动的那一刻放开容量闸——错的方向。
		return license.Status{Mode: license.ModeInvalid, Reason: "license 记录读取失败：" + err.Error()}
	}
	if !found {
		return license.Status{Mode: license.ModeDemo}
	}
	return license.Evaluate([]byte(blob), s.licenseKeys, time.Now())
}

// licenseUsage 当前席位占用。计数走既有读口，不加新 SQL：
// 用户 = users 全表（含管理员与外部建号——占的都是命名席位；禁用不释放，删除才释放）；
// 网关 = 未吊销证书的去重 gatewayId（吊销即释放，换证不占新席位）。
// 读失败回 -1 = 不可判定：绝不回 0，0 的含义是"空着"。
func (s *Server) licenseUsage(r *http.Request) (users, gateways int) {
	users, gateways = -1, -1
	if b, err := s.store.Users(r.Context()); err == nil {
		users = len(b.Users)
	}
	if certs, err := s.store.GatewayCerts(r.Context()); err == nil {
		seen := map[string]bool{}
		for _, c := range certs {
			if !c.Revoked {
				seen[c.GatewayID] = true
			}
		}
		gateways = len(seen)
	}
	return
}

// licenseAdmit 容量闸。kind ∈ {"user","gateway"}；ok=false 时 reason 直接回 409。
//
// demo → 放行（从未声称被许可，不限）；invalid/expired → 拒（fail-closed，
// 方向的理由见 license.Evaluate 注释）；licensed → 查对应维度席位。
func (s *Server) licenseAdmit(r *http.Request, kind string) (string, bool) {
	st := s.licenseStatus(r)
	switch st.Mode {
	case license.ModeDemo:
		return "", true
	case license.ModeInvalid, license.ModeExpired:
		return "License 不可用：" + st.Reason, false
	}
	users, gateways := s.licenseUsage(r)
	switch kind {
	case "user":
		if st.Manifest.MaxUsers > 0 {
			if users < 0 {
				return "License 用户席位无法核算（用户目录读取失败），按拒绝处理", false
			}
			if users >= st.Manifest.MaxUsers {
				return "License 用户席位已满（" + strconv.Itoa(users) + "/" + strconv.Itoa(st.Manifest.MaxUsers) +
					"）：删除闲置账号释放席位，或导入更大容量的 license", false
			}
		}
	case "gateway":
		if st.Manifest.MaxGateways > 0 {
			if gateways < 0 {
				return "License 网关席位无法核算（证书台账读取失败），按拒绝处理", false
			}
			if gateways >= st.Manifest.MaxGateways {
				return "License 网关席位已满（" + strconv.Itoa(gateways) + "/" + strconv.Itoa(st.Manifest.MaxGateways) +
					"）：吊销不再使用的网关证书释放席位，或导入更大容量的 license", false
			}
		}
	}
	return "", true
}

// handleLicense GET：状态 + 用量。读=任意管理员——容量与到期是三权都需要的运维事实。
func (s *Server) handleLicense(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	st := s.licenseStatus(r)
	users, gateways := s.licenseUsage(r)
	_, canStore := s.store.(settingReader)
	out := map[string]any{
		"mode":       st.Mode,
		"reason":     st.Reason,
		"boundaries": licenseBoundaries(),
		// keysConfigured 如实下发：没配公钥时导入必被拒，页面要在导入框旁边说清，
		// 而不是让人贴完 blob 才吃一个 400。
		"keysConfigured": len(s.licenseKeys) > 0,
		"canImport":      canStore && len(s.licenseKeys) > 0,
		"usage": map[string]any{
			"users": users, "gateways": gateways,
			"maxUsers": st.Manifest.MaxUsers, "maxGateways": st.Manifest.MaxGateways,
			// 超限只在 licensed 态有意义（expired/invalid 时容量闸整体关死，另有 reason）。
			"overUsers":    st.Mode == license.ModeLicensed && st.Manifest.MaxUsers > 0 && users > st.Manifest.MaxUsers,
			"overGateways": st.Mode == license.ModeLicensed && st.Manifest.MaxGateways > 0 && gateways > st.Manifest.MaxGateways,
		},
	}
	if st.Mode == license.ModeLicensed || st.Mode == license.ModeExpired {
		out["manifest"] = st.Manifest
	}
	httpx.JSON(w, http.StatusOK, out)
}

// handleImportLicense POST：导入/替换（PermSystem）。
func (s *Server) handleImportLicense(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	if len(s.licenseKeys) == 0 {
		// 照升级包验签的先例：未配置发行公钥必须拦住，不得静默放行。
		httpx.Error(w, http.StatusBadRequest,
			"未配置 License 发行公钥（BAIDI_LICENSE_PUBKEY）：无法验证任何 license，导入被拒。"+
				"公钥由发行方 baidi-license -genkey 产出，经部署期配置分发")
		return
	}
	wr, ok := s.writer.(settingWriter)
	if !ok {
		httpx.Error(w, http.StatusNotImplemented, "当前存储后端不支持保存 license（内存种子模式）")
		return
	}
	blob, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "license 文件过大（上限 64 KiB）")
		return
	}
	f, m, err := license.Parse(blob)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := license.Verify(f, s.licenseKeys); err != nil {
		// 验签失败要落审计：一次伪造 license 的尝试与一次贴错文件在日志上必须可区分（detail 里有）。
		s.audit(r, "system", "导入 license 被拒："+err.Error(), "fail")
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	// 已过期的拒收：导入它唯一的效果是把当前状态劣化成 expired（容量闸关死）。
	if time.Now().Format("2006-01-02") > m.ExpiresAt {
		httpx.Error(w, http.StatusBadRequest, "该 license 已于 "+m.ExpiresAt+" 过期，拒绝导入")
		return
	}
	if err := wr.SetSetting(r.Context(), licenseSettingKey, string(blob)); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "license 保存失败")
		return
	}
	s.audit(r, "system", "导入 license："+m.Licensee+"（用户 ≤"+capText(m.MaxUsers)+
		" · 网关 ≤"+capText(m.MaxGateways)+" · 到期 "+m.ExpiresAt+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "manifest": m})
}

func capText(n int) string {
	if n <= 0 {
		return "不限"
	}
	return strconv.Itoa(n)
}

// parseLicenseKeys 解析 BAIDI_LICENSE_PUBKEY（base64 Ed25519 公钥，逗号分隔可多把供轮换）。
// 与 parseUpgradeKeys 同构且刻意不合并：两把公钥属于两个信任域（升级发布方 / License
// 发行方），合成一个函数迟早有人顺手也合成一个环境变量。
func parseLicenseKeys(env string) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, part := range strings.Split(env, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(part)
		if err != nil || len(b) != ed25519.PublicKeySize {
			continue
		}
		out = append(out, ed25519.PublicKey(b))
	}
	return out
}
