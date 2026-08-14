package api

// 外部账号状态回验循环（wave7 行动 3：FR-AUTH-04/08 的状态回验半边）。
//
// ★补的是「持续验证」的第一个反例：AD 管理员禁了号，白帝这边已签发的 8h 会话、
// 由它派生的敲门令牌、乃至 JIT 授予，在此之前会继续有效到自然过期——
// docs/ARCHITECTURE.md 把它列为「目前最需要补的一个洞」。本循环把失效窗
// 从 8h 压到回验周期（BAIDI_EXTAUTH_RECHECK，默认 5 分钟）。
//
// 三条方向性纪律（与本项目常见的 fail-closed 恰好相反，理由都在于"谁在自伤"）：
//   - **源不可用绝不动手**：AD 抖一下就禁掉全部外部账号，是比 8h 失效窗大得多的
//     自伤。只有目录**明确说了**禁用/过期/不存在才处置（见 authsrc.StatusChecker）。
//   - **只单向禁用，不自动恢复**：目录侧重新启用后由管理员手工恢复。自动恢复会
//     悄悄撤销本地管理员的显式禁用（他禁的可能正是这个人，理由目录侧不知道）。
//   - **幂等**：已禁用的行跳过——否则每个周期都重复落审计、重复刷封禁，
//     审计页会被同一件事冲成噪声。
//
// OIDC 源整体跳过并非偷懒：标准 OIDC 不提供"按 sub 查账号状态"的通道，
// RP 拿到的只是登录时刻的断言。协议边界如实标注（SCOPE ch7）。

import (
	"context"
	"log/slog"
	"time"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

// extBindingStore 回验所需的 store 能力（SQLiteStore 实现）。
type extBindingStore interface {
	ExternalBindings(ctx context.Context, sourceID string) ([]store.ExternalBinding, error)
}

// stateZh 回验结论的处置文案。
var stateZh = map[authsrc.AccountState]string{
	authsrc.StateDisabled: "已在目录侧被禁用",
	authsrc.StateExpired:  "已在目录侧过期",
	authsrc.StateGone:     "在目录中已不存在",
}

// StartExternalRecheckLoop 启动回验循环。interval<=0 = 不启用（如实告警一次）。
func (s *Server) StartExternalRecheckLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		slog.Warn("外部账号状态回验未启用（BAIDI_EXTAUTH_RECHECK<=0）：" +
			"外部目录禁号后，已签发的会话与其派生令牌将继续有效至自然过期（最长 8h）")
		return
	}
	if _, ok := s.store.(extBindingStore); !ok {
		return // 内存种子模式没有绑定表，也没有外部账号可回验
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
			s.RecheckExternalAccounts(ctx)
		}
	}()
}

// RecheckExternalAccounts 跑一轮回验。导出给测试与将来可能的"立即回验"按钮——
// 同一条代码路径，不做第二份实现（照 PumpAuditForward 先例）。
// 返回（回验过的账号数, 实际处置数）。
func (s *Server) RecheckExternalAccounts(ctx context.Context) (checked, acted int) {
	ebs, ok := s.store.(extBindingStore)
	if !ok {
		return 0, 0
	}
	as := s.authSrcStore()
	if as == nil {
		return 0, 0
	}
	srcs, err := as.AuthSources(ctx)
	if err != nil {
		slog.Warn("外部账号回验：认证源清单读取失败，本轮跳过", "err", err.Error())
		return 0, 0
	}
	for _, rec := range srcs {
		kind := authsrc.Kind(rec.Kind)
		if !rec.Enabled || (kind != authsrc.KindLDAP && kind != authsrc.KindAD) {
			continue // OIDC 无回验通道（协议边界）；local 的权威就是本库
		}
		sc, err := s.statusCheckerFor(ctx, rec)
		if err != nil {
			slog.Warn("外部账号回验：认证源不可用，本轮不处置该源名下任何账号",
				"源", rec.Name, "err", err.Error())
			continue
		}
		bindings, err := ebs.ExternalBindings(ctx, rec.ID)
		if err != nil {
			slog.Warn("外部账号回验：绑定清单读取失败", "源", rec.Name, "err", err.Error())
			continue
		}
		srcDown := false
		for _, b := range bindings {
			if b.Status != "active" {
				continue // 幂等：已禁用/锁定的行不重复处置、不重复落审计
			}
			if srcDown {
				break // 源已判定不可用：本轮剩余账号不再逐个撞超时
			}
			checked++
			state, err := sc.CheckAccount(ctx, b.Subject)
			if err != nil {
				// ★源不可用绝不动手（方向说明见文件头）。一条日志代表整源，
				// 不逐账号刷屏——中断本源循环。
				slog.Warn("外部账号回验：查询失败，本轮不处置该源名下任何账号",
					"源", rec.Name, "err", err.Error())
				srcDown = true
				continue
			}
			if state == authsrc.StateActive {
				continue
			}
			zh, known := stateZh[state]
			if !known {
				continue // 未知状态不猜语义
			}
			if err := s.writer.SetUserStatus(ctx, b.UserID, "disabled"); err != nil {
				slog.Error("外部账号回验：禁用落库失败", "账号", b.Account, "err", err.Error())
				continue
			}
			// 数据面联动与管理员手工禁用同一条通道：撤窗断隧道 + 拒发敲门令牌。
			s.mu.Lock()
			s.revoked[normUser(b.Account)] = revokeInfo{
				Reason:  "外部目录账号" + zh,
				Until:   time.Now().Add(kickBanTTL).Unix(),
				Display: b.Account,
			}
			s.mu.Unlock()
			s.auditBG(ctx, "security",
				"外部账号回验：「"+b.Account+"」（源 "+rec.Name+"）"+zh+
					"，已禁用本地账号并撤窗断隧道（恢复须管理员手工启用）", "ok")
			acted++
		}
	}
	return checked, acted
}

// statusCheckerFor 构造某源的回验器；testStatusChecker 是测试注入缝
// （照 testRedirectAuth 先例：LDAP 协议路径另有 gldap 真服务端用例）。
func (s *Server) statusCheckerFor(ctx context.Context, rec store.AuthSourceRec) (authsrc.StatusChecker, error) {
	if s.testStatusChecker != nil {
		return s.testStatusChecker(rec)
	}
	prov, err := s.buildProvider(ctx, rec)
	if err != nil {
		return nil, err
	}
	sc, ok := prov.(authsrc.StatusChecker)
	if !ok {
		return nil, authsrc.ErrNotConfigured
	}
	return sc, nil
}
