package api

// TOTP 二次认证（RFC 6238，wave7 行动 4：FR-AUTH-03/12/16）。
//
// 与 passkey 的分工：passkey 抗钓鱼、最强，但 RP ID 必须是可注册域名——裸 IP
// 部署（含演示站）启用不了；TOTP 不依赖域名，是裸 IP 下唯一的标准二因子，
// 用来替换 legacy 演示验证码 123456 那条回落。
//
// 判定顺序（secondFactor）：passkey > TOTP > 认证策略。已确认 TOTP 的账号
// 与 passkey 同款纪律——登录**无条件**要求验证码，策略豁免碰不到它。
//
// 密钥纪律：
//   - 密钥原文只在两个瞬间出现在响应里：注册那一次（secret + otpauth URI）。
//     状态/确认/登录端点永不回显。
//   - 落库经 secret 盒 AES-256-GCM，AAD="totp:"+account（跨账号剪贴密文行
//     直接解密失败）。
//   - 防重放：Verify 返回命中的时间计数器，ConsumeTotpCounter 原子消费，
//     同一 30s 步长内的码只能成功一次——截获的一次性码重放无效。

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/totp"
)

// totpIssuer otpauth URI 里的发行方（authenticator App 列表里的显示名）。
const totpIssuer = "白帝安全接入"

// totpAAD 密文行的 AAD。前缀隔离命名空间：账号名与其他表的记录 id 撞值时
// 也不会出现「A 表密文剪到 B 表还能解开」。
func totpAAD(account string) string { return "totp:" + normUser(account) }

// totpSecretFor 读某账号的 TOTP 行并解密。found=false = 未注册。
func (s *Server) totpSecretFor(ctx context.Context, account string) (store.TotpRecord, string, bool, error) {
	rec, found, err := s.store.TotpFor(ctx, account)
	if err != nil || !found {
		return store.TotpRecord{}, "", false, err
	}
	box, err := secret.Default()
	if err != nil {
		return store.TotpRecord{}, "", false, err
	}
	raw, err := box.Open(totpAAD(account), rec.Nonce, rec.Cipher)
	if err != nil {
		return store.TotpRecord{}, "", false, err
	}
	return rec, string(raw), true, nil
}

// handleTotpStatus GET /api/v1/totp——我的 TOTP 状态（需登录，不含密钥材料）。
func (s *Server) handleTotpStatus(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	rec, found, err := s.store.TotpFor(r.Context(), c.Name)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "TOTP 状态读取失败")
		return
	}
	st := store.TotpStatus{}
	if found {
		st = store.TotpStatus{Enrolled: true, Confirmed: rec.Confirmed, CreatedAt: rec.CreatedAt}
	}
	httpx.JSON(w, http.StatusOK, st)
}

// handleTotpEnroll POST /api/v1/totp/enroll——生成新密钥（未确认态）。
// 密钥原文只在本响应回显一次；重复调用直接换新密钥并复位确认态（旧密钥作废）。
func (s *Server) handleTotpEnroll(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	account := normUser(c.Name)
	sec, err := totp.GenerateSecret()
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "密钥生成失败")
		return
	}
	box, err := secret.Default()
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "加密盒不可用")
		return
	}
	nonce, cipher, err := box.Seal(totpAAD(account), []byte(sec))
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "密钥加密失败")
		return
	}
	if err := s.writer.SaveTotpSecret(r.Context(), account, nonce, cipher); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "密钥落库失败")
		return
	}
	s.auditAs(r, account, "auth", "TOTP 注册开始（待验证码确认后生效）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"secret": sec,
		"uri":    totp.ProvisioningURI(totpIssuer, account, sec),
	})
}

// handleTotpConfirm POST /api/v1/totp/confirm {code}——用一个正确验证码把注册转正。
// 从确认那一刻起，该账号登录强制 TOTP（与 passkey 同款「注册即强制」）。
func (s *Server) handleTotpConfirm(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	account := normUser(c.Name)
	var b struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Code == "" {
		httpx.Error(w, http.StatusBadRequest, "请填写认证器 App 显示的 6 位验证码")
		return
	}
	rec, sec, found, err := s.totpSecretFor(r.Context(), account)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "TOTP 状态读取失败")
		return
	}
	if !found {
		httpx.Error(w, http.StatusBadRequest, "尚未开始注册，请先生成密钥")
		return
	}
	counter, okCode := totp.Verify(sec, b.Code, time.Now())
	if !okCode {
		s.auditAs(r, account, "auth", "TOTP 确认失败：验证码不正确", "fail")
		httpx.Error(w, http.StatusBadRequest, "验证码不正确，请确认扫码/录入无误后重试")
		return
	}
	if rec.Confirmed {
		// 已确认态重复确认：走防重放消费，别让确认端点变成绕过 last_counter 的侧门
		used, cerr := s.writer.ConsumeTotpCounter(r.Context(), account, counter)
		if cerr != nil || !used {
			httpx.Error(w, http.StatusBadRequest, "验证码已使用，请等下一个刷新周期")
			return
		}
	} else if err := s.writer.ConfirmTotp(r.Context(), account, counter); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "确认落库失败")
		return
	}
	s.auditAs(r, account, "auth", "TOTP 二次认证已启用（此后登录强制动态验证码）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTotpDisable POST /api/v1/totp/disable {code}——解绑。
// 已生效的注册必须出示当前验证码：拿到会话令牌 ≠ 拿到认证器，
// 否则劫持一次会话就能顺手把二因子拆掉。未确认的半截注册可直接取消。
func (s *Server) handleTotpDisable(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	account := normUser(c.Name)
	var b struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	rec, sec, found, err := s.totpSecretFor(r.Context(), account)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "TOTP 状态读取失败")
		return
	}
	if !found {
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true}) // 幂等
		return
	}
	if rec.Confirmed {
		counter, okCode := totp.Verify(sec, b.Code, time.Now())
		if !okCode {
			s.auditAs(r, account, "auth", "TOTP 解绑被拒：未出示正确的当前验证码", "deny")
			httpx.Error(w, http.StatusForbidden, "解绑需要输入认证器 App 当前显示的验证码")
			return
		}
		if used, cerr := s.writer.ConsumeTotpCounter(r.Context(), account, counter); cerr != nil || !used {
			httpx.Error(w, http.StatusForbidden, "验证码已使用，请等下一个刷新周期")
			return
		}
	}
	if _, err := s.writer.DeleteTotp(r.Context(), account); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "解绑落库失败")
		return
	}
	s.auditAs(r, account, "auth", "TOTP 二次认证已解绑", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTotpLogin POST /api/v1/auth/totp {ticket, code}——TOTP 登录第二回合。
// 身份由「口令已验」的一次性 mfaTicket 承载（与 WebAuthn 断言同款），
// 免 Bearer 中间件但 handler 内强校验；完成后签发会话令牌。
func (s *Server) handleTotpLogin(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Ticket string `json:"ticket"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		httpx.Error(w, http.StatusBadRequest, "请求格式不正确")
		return
	}
	account, ok := s.verifyMfaTicket(b.Ticket)
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "认证票据无效或已过期，请重新登录")
		return
	}
	// 防爆破锁：验证码猜测失败也计数，锁定可能在两回合之间触发，此处再拦一次。
	if s.loginGateLocked(w, r, account) {
		return
	}
	rec, sec, found, err := s.totpSecretFor(r.Context(), account)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "TOTP 状态读取失败")
		return
	}
	if !found || !rec.Confirmed {
		// 票据在手却没有已确认的 TOTP：不该走到这条路径（secondFactor 只对
		// 已确认账号发 needTotp）。按无效处理，不泄露账号注册状态。
		httpx.Error(w, http.StatusUnauthorized, "该账号未启用 TOTP")
		return
	}
	counter, okCode := totp.Verify(sec, b.Code, time.Now())
	if okCode {
		// 防重放消费必须在发令牌之前：消费失败（同码二用）与验错同罪。
		used, cerr := s.writer.ConsumeTotpCounter(r.Context(), account, counter)
		if cerr != nil {
			httpx.Error(w, http.StatusInternalServerError, "TOTP 状态更新失败")
			return
		}
		okCode = used
	}
	if !okCode {
		s.noteLoginFailure(r, account) // 验证码猜测与口令爆破同一道闸
		s.auditAs(r, account, "auth", "TOTP 验证码校验失败", "fail")
		httpx.Error(w, http.StatusUnauthorized, "验证码不正确或已使用")
		return
	}
	cred, credFound, err := s.store.Credential(r.Context(), account)
	if err != nil || !credFound {
		httpx.Error(w, http.StatusInternalServerError, "账号信息读取失败")
		return
	}
	// 账号状态门：口令那步已查过，这里再查一次，杜绝两回合之间被禁用仍能拿令牌。
	if accountBlocked(cred.Status) {
		s.auditAs(r, account, "auth", "TOTP 校验被拒（账号已"+statusZh[cred.Status]+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "账号已被"+statusZh[cred.Status])
		return
	}
	s.lockout.Success(account) // 二次认证走完才算成功登录，此刻清零失败计数
	if cred.MustChangePw {
		s.auditAs(r, account, "auth", "TOTP 二次认证通过", "ok")
		s.mustChangeLogin(w, r, cred)
		return
	}
	s.noteLoginSuccess(r.Context(), account)
	s.auditAs(r, account, "auth", "TOTP 二次认证通过，登录成功", "ok")
	tok := s.keys.Sign(auth.Claims{Sub: cred.Account, Role: cred.Role, Name: cred.Account, Jti: auth.RandJTI()}, tokenTTL)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "token": tok, "displayName": cred.Name, "role": cred.Role,
	})
}
