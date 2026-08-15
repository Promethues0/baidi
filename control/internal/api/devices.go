// 授信终端主线（PRD ch9 FR-EP-10/12/13/14/15）。
//
// 本文件把「设备」从一张只读台账变成**准入判据**。分三段：
//
//	① 生命周期  首次 posture 上报即登记（api/posture.go 调 enrollReportingDevice）→
//	            pending/trusted → 管理员批准 / 吊销 / 重命名 / 清理陈旧；
//	            审批复用既有 approvals 表（不另起一套流程）。
//	② 准入闸    deviceAdmissionGate 挂在 handleKnockToken 上。敲门令牌是终端进入数据面的
//	            唯一入口（网关 strict 只认 control 签的 use=knock 令牌），拒发即从密码学上
//	            敲不开门——不需要网关改一行代码。
//	③ 吊销联动  吊销一台设备时把该账号并入强制下线封禁表，网关下轮 applyRevoked 撤窗断隧道。
//
// ★③ 有一条必须说清楚的**能力边界**（不假装做到了）：
//
//	数据面的撤销通道是**按账号**表达的（cplane.Revoked{User, Until} → al.RevokeUser /
//	proxy.KillUser）。整条数据面链路上根本没有"设备"这个维度：敲门令牌的 claims 只有
//	sub/role/name/jti/use，网关放行窗按**源 IP** 记账，隧道会话按**账号**记账——
//	控制面无从告诉网关"只切这台机器的隧道"，网关也无从分辨。
//
//	因此设备吊销的会话撤销**降级为按账号撤销**：该账号在**所有**终端上的隧道都会被切断，
//	并在封禁窗（kickBanTTL = 5min）内无法重新接入，哪怕换一台已授信的设备。
//	控制台的吊销确认框把这句话原样写给管理员看，审计也照实记录影响面。
//
//	要做到真正的按设备撤销，需要把指纹一路带进 knock 令牌 → 放行窗记账 → 隧道会话，
//	是一次贯穿数据面的改造，本轮不做——**做一半（只在控制面标记、数据面照旧）比不做更坏**：
//	页面显示"已吊销"，那台机器的隧道还开着，而谁也看不出来。
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// deviceObserveInterval 观察模式下同一 (账号,设备) 两条审计之间的最小间隔。
//
// ★必须节流：敲门令牌是保活热路径（baidi-tun 每 15s 一次 reknock）。不节流的话
// 一台未授信终端一天产出约 5700 条内容相同的审计，真正的处置事件会被冲刷掉——
// 与 auditGrayObserved 同一条理由、同一个量级。
const deviceObserveInterval = 5 * time.Minute

// deviceObserveMaxKeys 观察模式节流水位表的键数上界（见 auditDeviceObserved 里的说明）。
// 20 台/账号 × 200 账号量级绰绰有余；触顶即整张清空，不做 LRU——
// 为一张"最坏后果是多写几条审计"的表引入淘汰算法不值当。
const deviceObserveMaxKeys = 4096

// ── ① 生命周期：终端上报时登记 ──

// enrollReportingDevice 在 posture 上报落库后登记/刷新设备台账。
//
// 返回 created 表示这次是新设备（调用方据此决定要不要落审计——每 15s 一次的上报
// 若都记一条，审计表会被刷成噪声）。上限超出时把 store.ErrDeviceCap 原样带回，
// 由 handler 转成与 posture 同一条 403 文案。
func (s *Server) enrollReportingDevice(r *http.Request, account, fingerprint, platform, os string) (store.Device, bool, error) {
	st, err := s.store.DeviceTrustSetting(r.Context())
	if err != nil {
		// 设置读不出来按默认（审批绑定）处理：新设备落 pending 是保守方向——
		// 宁可让管理员多点一次批准，也不能因为一次读失败把设备静默放成 trusted。
		slog.Error("授信终端准入设置读取失败，本次登记按默认（审批绑定）处理", "账号", account, "err", err.Error())
		st = store.DefaultDeviceTrustSetting()
	}
	name := strings.TrimSpace(os)
	dev, created, err := s.writer.EnrollDevice(r.Context(), account, fingerprint, name, platform, st.BindMethod)
	if err != nil {
		return store.Device{}, false, err
	}
	if !created {
		return dev, false, nil
	}
	if dev.Status == store.DeviceStatusTrusted {
		s.auditAs(r, account, "security", "新终端首次登记并按「自动绑定」置为授信："+account+" / "+dev.Name+
			"（指纹 "+shortFP(fingerprint)+"）", "ok")
	} else {
		s.auditAs(r, account, "security", "新终端首次登记，状态 pending 待批准："+account+" / "+dev.Name+
			"（指纹 "+shortFP(fingerprint)+"，已生成绑定审批单 "+dev.ApprovalID+"）", "ok")
	}
	return dev, true, nil
}

// ── ② 准入闸：敲门令牌签发 ──

// deviceAdmissionResult 设备闸的判定结果。
type deviceAdmissionResult struct {
	Allowed bool
	Reason  string // 拒绝原因（人话，回给客户端 + 写审计）
}

// deviceAdmissionGate 授信终端准入判定（敲门令牌签发前）。
//
// 判定矩阵（fingerprint 为客户端随 /knock-token 上报的指纹，浏览器/旧客户端为空）：
//
//	状态\模式     observe                      strict
//	trusted       放行                          放行
//	pending       放行 + 审计（节流）            拒绝
//	未登记        放行 + 审计（节流）            拒绝
//	缺指纹        放行 + 审计（节流）            拒绝
//	revoked       **拒绝**                      拒绝
//
// ★revoked 在 observe 下也拒：observe 放宽的是"这台设备我还不认识"（纳管进度问题），
// 而 revoked 是管理员显式说过"这台不许进"。若默认配置下连它都放行，「吊销」按钮
// 就是个空动作——页面变红、审计有记录、设备照常接入，没有任何报错。
//
// **资产分类叠加在上面这张表之上**（wave7 行动 15）：已登记设备若是 personal
// （managed 按企业资产处理，不受约束），再过一道 personalPolicy：
//
//	inherit  什么都不做，与上表完全一致（默认，行为与本功能上线前逐字节相同）
//	strict   该设备恒按 strict 判——即使全局是 observe
//	deny     直接拒——即使它已经是 trusted
//
// ★分类判定必须落在**这里**而不是并入风险降权：degrade 是账号维度的，一个人
// 同时有企业机与个人机时按账号降权会连他的企业机一起误伤。理由详见
// store.PersonalPolicyInherit 一节，用例 TestPersonalDenyDoesNotAffectEnterpriseDevice。
//
// 设备状态读失败（err != nil）在 strict 下拒、observe 下放行：
// 与准入模式本身的语义一致，运维选了 strict 就是选了"说不清楚就不放行"。
//
// ★**准入设置本身**读失败时沿用上一次成功读到的设置（deviceTrustPolicy），绝不回落默认值：
// 默认是 observe + inherit，而这里是敲门令牌的签发路径——回落默认等于一次 settings 读失败
// 就把整道闸静默关掉（strict / deny 配了跟没配一样），且现场只剩一条 slog。这与同一函数里
// DeviceByFingerprint 读失败在 strict 下拒是同一个方向。
func (s *Server) deviceAdmissionGate(r *http.Request, account, fingerprint string) deviceAdmissionResult {
	set := s.deviceTrustPolicy(r.Context(), account)
	strict := set.Mode == store.DeviceTrustStrict
	fingerprint = strings.TrimSpace(fingerprint)

	if fingerprint == "" {
		if strict {
			return deviceAdmissionResult{Reason: "未上报终端指纹（严格准入模式要求终端登记为授信设备）"}
		}
		s.auditDeviceObserved(r, account, "", "未上报终端指纹")
		return deviceAdmissionResult{Allowed: true}
	}
	dev, found, derr := s.store.DeviceByFingerprint(r.Context(), account, fingerprint)
	if derr != nil {
		slog.Error("设备授信状态读取失败", "账号", account, "strict", strict, "err", derr.Error())
		if strict {
			return deviceAdmissionResult{Reason: "终端授信状态读取失败（严格准入模式下拒绝接入）"}
		}
		return deviceAdmissionResult{Allowed: true}
	}
	// ① 吊销优先于分类：管理员对这台机器的**显式**处置，理由也更具体，
	//    先判它才能让被拒的人看到"这台被吊销了、理由是 X"而不是一句资产分类。
	if found && dev.Status == store.DeviceStatusRevoked {
		reason := "该终端已被吊销"
		if dev.RevokeReason != "" {
			reason += "：" + dev.RevokeReason
		}
		return deviceAdmissionResult{Reason: reason}
	}
	// ② 资产分类（只对已登记设备可判——未登记设备连分类都还不存在，走 ③ 的原有分支）。
	if found && store.IsPersonalAsset(dev.AssetClass) {
		switch set.PersonalPolicy {
		case store.PersonalPolicyDeny:
			// ★拒绝原因必须点名资产分类。回一句泛泛的"终端未授信"，用户会照着
			// "去找管理员批准"这条错路走，而这台机器批过了也照样进不来。
			return deviceAdmissionResult{Reason: "该终端登记为「个人资产」，当前策略为「个人资产一律拒绝接入」，" +
				"已授信也不放行。请改用企业资产终端接入；确需用这台机器，请联系管理员将其纳管后改标为「企业纳管个人」"}
		case store.PersonalPolicyStrict:
			// 个人资产按严格准入判：全局 observe 也不放宽。
			strict = true
		}
	}
	if found && dev.Status == store.DeviceStatusTrusted {
		return deviceAdmissionResult{Allowed: true}
	}
	// ③ pending / 未登记
	what := "终端未登记"
	if found {
		what = "终端待批准（pending）"
	}
	if strict {
		reason := what + "，严格准入模式下不予接入，请联系管理员批准该终端"
		// 全局是 observe、只因为这台是个人资产才被拒时，必须说清楚是哪条策略在起作用——
		// 否则管理员对着「准入模式：观察」的页面永远排不出这次拒绝是从哪来的。
		if set.Mode != store.DeviceTrustStrict {
			reason = what + "，且该终端登记为「个人资产」，当前策略为「个人资产按严格准入判定」" +
				"（全局准入模式仍是观察）——请联系管理员批准该终端"
		}
		return deviceAdmissionResult{Reason: reason}
	}
	s.auditDeviceObserved(r, account, fingerprint, what)
	return deviceAdmissionResult{Allowed: true}
}

// deviceTrustPolicy 取当前生效的准入设置，并把每次**成功**读到的值记为"上次已知"。
//
// 读失败时的取值顺序：上次已知 → 内置默认（observe + inherit）。落到内置默认只可能
// 发生在控制面启动后**一次都没读成功过**的情形（那时库多半整体不可用，敲门链路上游早已失败），
// 此时按默认处理并记 Error；只要成功读到过一次，此后任何抖动都沿用那一次的答案。
//
// ★缓存的是**整份设置**而不只是 Mode：personalPolicy 与 Mode 一样是收缩方向的开关，
// 只缓存其一的话，一次读失败会把 deny 静默降级成 inherit——个人资产在那段时间里
// 全部照常接入，而页面上仍写着"一律拒绝"。
func (s *Server) deviceTrustPolicy(ctx context.Context, account string) store.DeviceTrustSetting {
	st, err := s.store.DeviceTrustSetting(ctx)
	if err == nil {
		s.mu.Lock()
		s.deviceTrustSeen = st
		s.mu.Unlock()
		return st
	}
	s.mu.Lock()
	seen := s.deviceTrustSeen
	s.mu.Unlock()
	if seen.Mode != "" {
		slog.Error("授信终端准入设置读取失败，沿用上一次成功读到的设置（绝不因一次读失败把闸放宽）",
			"账号", account, "沿用模式", seen.Mode, "沿用个人资产策略", seen.PersonalPolicy, "err", err.Error())
		return seen
	}
	fallback := store.DefaultDeviceTrustSetting()
	slog.Error("授信终端准入设置读取失败，且本进程启动后从未成功读到过，本次按内置默认处理",
		"账号", account, "默认模式", fallback.Mode, "err", err.Error())
	return fallback
}

// auditDeviceObserved 观察模式下的放行留痕（按 (账号,指纹) 节流）。
//
// 措辞只陈述已发生的事实：签了令牌、设备是什么状态、当前是观察模式。
// 不写"已拦截""已限制"——观察模式下什么都没拦。
func (s *Server) auditDeviceObserved(r *http.Request, account, fingerprint, what string) {
	key := normUser(account) + "|" + fingerprint
	now := time.Now().Unix()
	s.mu.Lock()
	// ★水位表的键含**客户端自报**的指纹，是攻击者可控的：持一个合法会话每次换一个随机
	// 指纹敲门，就能让这张表无界增长（grayObserved 按账号计键，没有这个面）。
	// 超过上界整张清空——最坏结果只是接下来多记几条 observing 审计，而那本来就是该被看见的。
	if len(s.deviceObserved) > deviceObserveMaxKeys {
		s.deviceObserved = map[string]int64{}
	}
	last, seen := s.deviceObserved[key]
	due := !seen || now-last >= int64(deviceObserveInterval.Seconds())
	if due {
		s.deviceObserved[key] = now
	}
	s.mu.Unlock()
	if !due {
		return
	}
	fp := "（无指纹）"
	if fingerprint != "" {
		fp = "指纹 " + shortFP(fingerprint)
	}
	s.auditAs(r, account, "security", "授信终端观察模式：已为 "+account+" 签发敲门令牌，"+what+
		"（"+fp+"）。切换为严格模式后此类接入将被拒绝", "observing")
}

// ── ③ 管理端点 ──

// handleDevices 终端管理页数据（准入设置 + 设备清单 + 待审批队列）。
//
// 读权限 = 任意管理员且**角色现算**（requireAdmin 走 store.AdminRoleFor，不信令牌里的
// role 快照）。设备清单含账号与硬件指纹，此前这个端点连一道闸都没有——任意登录终端
// 都能拉走全量指纹台账。指纹不是秘密，但"谁有几台什么设备"是组织信息。
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	b, err := s.store.Devices(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load devices")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

// handleSaveDeviceTrustSetting 保存准入设置（PermSecurity）。
func (s *Server) handleSaveDeviceTrustSetting(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	var body store.DeviceTrustSetting
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if body.Mode != store.DeviceTrustObserve && body.Mode != store.DeviceTrustStrict {
		httpx.Error(w, http.StatusBadRequest, "mode 取值须为 observe|strict")
		return
	}
	if body.BindMethod != store.DeviceBindAuto && body.BindMethod != store.DeviceBindApproval {
		httpx.Error(w, http.StatusBadRequest, "bindMethod 取值须为 auto|approval")
		return
	}
	if body.StaleDays < 1 || body.StaleDays > 3650 {
		httpx.Error(w, http.StatusBadRequest, "staleDays 取值须在 1~3650 天之间")
		return
	}
	// personalPolicy 缺省（旧版控制台 / 按老文档写的脚本不发这个字段）→ **保留当前值**，
	// 绝不收成 inherit。
	//
	// ★"没带这一项"与"把这一项设成 inherit"是两件事，混为一谈就是一次静默降级：
	// 本 handler 是全量 PUT，于是任何按本功能上线**前**的接口写的客户端，只要保存一次
	// 准入设置（哪怕只是把陈旧阈值从 30 改成 60），就会把已配置的 deny 无声改回 inherit——
	// 被挡住的那批个人资产终端下一次敲门全部放行，而页面上写着「跟随全局」，
	// 没有人会把这两件事联系起来。仓库里已有同款前车之鉴（灰度弹窗恒发 groups:[]，见 SCOPE ch4）。
	// 方向上也必须与读侧一致：deviceTrustPolicy 为了「绝不因一次读失败把闸放宽」才缓存整份设置，
	// 写侧就不能留一条把同一个闸放宽的路。
	if body.PersonalPolicy == "" {
		cur, cerr := s.store.DeviceTrustSetting(r.Context())
		if cerr != nil {
			// 读不到当前值就不敢保存：fail-closed 好过把一个收缩方向的开关猜成 inherit。
			httpx.Error(w, http.StatusInternalServerError, "读取当前准入设置失败，未做任何改动（请重试）")
			return
		}
		body.PersonalPolicy = cur.PersonalPolicy
		if !store.PersonalPolicyValid(body.PersonalPolicy) {
			body.PersonalPolicy = store.PersonalPolicyInherit // 库里是空/脏值时才落回默认
		}
	}
	if !store.PersonalPolicyValid(body.PersonalPolicy) {
		httpx.Error(w, http.StatusBadRequest, "personalPolicy 取值须为 inherit|strict|deny")
		return
	}
	saved, err := s.writer.SaveDeviceTrustSetting(r.Context(), body)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save device trust setting")
		return
	}
	modeZh := map[string]string{store.DeviceTrustObserve: "观察（放行并留痕）", store.DeviceTrustStrict: "严格（非授信终端拒发敲门令牌）"}
	bindZh := map[string]string{store.DeviceBindAuto: "自动绑定", store.DeviceBindApproval: "审批绑定"}
	s.audit(r, "admin", "保存授信终端准入设置：准入模式="+modeZh[saved.Mode]+
		"、绑定方式="+bindZh[saved.BindMethod]+"、陈旧阈值="+strconv.Itoa(saved.StaleDays)+" 天"+
		"、个人资产策略="+store.PersonalPolicyZh(saved.PersonalPolicy), "ok")
	httpx.JSON(w, http.StatusOK, saved)
}

// handleSetDeviceStatus 批准 / 吊销 / 打回一台设备（PermSecurity）。
//
// 吊销（含从 trusted 打回 pending）会连带把该账号并入强制下线封禁表——影响面见文件头 ③。
func (s *Server) handleSetDeviceStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil ||
		!store.DeviceStatusValid(body.Status) {
		httpx.Error(w, http.StatusBadRequest, "status 取值须为 pending|trusted|revoked")
		return
	}
	actor := actorOf(r)
	before, after, err := s.writer.SetDeviceStatus(r.Context(), id, body.Status, actor, strings.TrimSpace(body.Reason))
	if errors.Is(err, store.ErrDeviceNotFound) {
		httpx.Error(w, http.StatusNotFound, "设备不存在")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to update device")
		return
	}
	resp := map[string]any{"ok": true, "device": after}
	switch after.Status {
	case store.DeviceStatusTrusted:
		s.audit(r, "security", "批准授信终端："+after.Account+" / "+after.Name+"（指纹 "+shortFP(after.Fingerprint)+
			"，原状态 "+before.Status+"）", "ok")
	case store.DeviceStatusRevoked:
		until := s.banAccountForDevice(after, body.Reason)
		resp["banUntil"] = until
		resp["blastRadius"] = deviceRevokeBlastRadius
		s.audit(r, "security", deviceRevokeAudit(after, body.Reason, until), "deny")
	default:
		s.audit(r, "security", "撤回授信终端授权，打回待批准："+after.Account+" / "+after.Name+
			"（指纹 "+shortFP(after.Fingerprint)+"）。该终端将无法在严格准入模式下接入", "ok")
	}
	httpx.JSON(w, http.StatusOK, resp)
}

// handleRenameDevice 重命名设备（PermSecurity，台账维护）。
func (s *Server) handleRenameDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil ||
		strings.TrimSpace(body.Name) == "" {
		httpx.Error(w, http.StatusBadRequest, "name 必填")
		return
	}
	d, err := s.writer.RenameDevice(r.Context(), id, body.Name)
	if errors.Is(err, store.ErrDeviceNotFound) {
		httpx.Error(w, http.StatusNotFound, "设备不存在")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "admin", "重命名终端："+d.Account+" / 指纹 "+shortFP(d.Fingerprint)+" → 「"+d.Name+"」", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "device": d})
}

// handleSetDeviceAsset 改一台设备的资产分类与标签（PermSecurity，wave7 行动 15）。
//
// 权限与「批准 / 吊销」同一档，因为**资产分类是准入判据**：在 personalPolicy=deny 下，
// 把一台设备标成个人资产等价于吊销它，标回企业资产等价于放行它。标签本身没有执行方，
// 但它和分类在同一个请求里，端点按更严的那一项收权（低权入口能顺手改判据是常见的越权面）。
func (s *Server) handleSetDeviceAsset(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	var body struct {
		AssetClass string   `json:"assetClass"`
		Tags       []string `json:"tags"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid payload")
		return
	}
	// 分类必填且必须合法：缺省兜成 enterprise 的话，一次前端字段名写错就会把
	// 全体被编辑过的设备静默改回企业资产，而 personalPolicy 随之对它们失效。
	if !store.AssetClassValid(body.AssetClass) {
		httpx.Error(w, http.StatusBadRequest, "assetClass 取值须为 enterprise|personal|managed")
		return
	}
	// 标签只做归一（去空/去重/截长/截数量），不拒绝：它没有执行方，为一个纯台账字段
	// 把整次编辑打回去，只会让管理员连分类也改不成。
	if len(body.Tags) > store.DeviceTagMaxCount*4 {
		httpx.Error(w, http.StatusBadRequest, "标签数量过多（单台上限 "+strconv.Itoa(store.DeviceTagMaxCount)+" 个）")
		return
	}
	before, after, err := s.writer.SetDeviceAsset(r.Context(), id, body.AssetClass, body.Tags)
	if errors.Is(err, store.ErrDeviceNotFound) {
		httpx.Error(w, http.StatusNotFound, "设备不存在")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "security", deviceAssetAudit(before, after, s.deviceTrustPolicy(r.Context(), after.Account)), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "device": after})
}

// deviceAssetAudit 资产分类/标签变更的审计文案。
//
// ★分类变更要写"从 X 改成 Y"并带上**当前生效的个人资产策略**：分类本身不说明任何后果，
// 同一次「改成个人资产」在 inherit 下什么都没发生、在 deny 下等于当场吊销这台机器。
// 事后复盘时没有这半句，就得去翻当时的设置才知道这条记录意味着什么。
// 标签变更只如实记录，并写明它不参与判定——免得后来人把它读成一次访问控制变更。
func deviceAssetAudit(before, after store.Device, set store.DeviceTrustSetting) string {
	txt := "标注终端资产：" + after.Account + " / " + after.Name + "（指纹 " + shortFP(after.Fingerprint) + "）"
	if before.AssetClass != after.AssetClass {
		txt += "，资产分类 " + store.AssetClassZh(before.AssetClass) + " → " + store.AssetClassZh(after.AssetClass) +
			"（当前个人资产策略：" + store.PersonalPolicyZh(set.PersonalPolicy) + "）"
		switch {
		case store.IsPersonalAsset(after.AssetClass) && set.PersonalPolicy == store.PersonalPolicyDeny:
			txt += "。★该终端此后将被拒发敲门令牌（即使状态仍是已授信）"
		case store.IsPersonalAsset(after.AssetClass) && set.PersonalPolicy == store.PersonalPolicyStrict:
			txt += "。★该终端此后按严格准入判定，非已授信状态将被拒发敲门令牌"
		case store.IsPersonalAsset(before.AssetClass) && set.PersonalPolicy != store.PersonalPolicyInherit:
			txt += "。★该终端此后不再受个人资产策略约束"
		}
	} else {
		txt += "，资产分类未变（" + store.AssetClassZh(after.AssetClass) + "）"
	}
	txt += "；标签 " + tagsText(before.Tags) + " → " + tagsText(after.Tags) + "（标签仅用于台账筛选与盘点，不参与任何准入或授权判定）"
	return txt
}

// tagsText 标签集合的可读形式（空集合写「（无）」而不是空字符串——审计里
// "标签  → " 这种句子读不出发生了什么）。
func tagsText(tags []string) string {
	if len(tags) == 0 {
		return "（无）"
	}
	return "「" + strings.Join(tags, "、") + "」"
}

// handleDeleteDevice 删除一台设备登记（PermSecurity）。
//
// ★同时删掉它的 posture 报告——两表口径统一（上限按 trusted_devices 计数）。
// 审计如实写明副作用：该指纹下次上报会作为**新设备**重新登记；若删的是 revoked 设备，
// 等于解除了这条吊销记录。
func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	id := r.PathValue("id")
	d, err := s.writer.DeleteDevice(r.Context(), id)
	if errors.Is(err, store.ErrDeviceNotFound) {
		httpx.Error(w, http.StatusNotFound, "设备不存在")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete device")
		return
	}
	extra := ""
	if d.Status == store.DeviceStatusRevoked {
		extra = "。★该设备原为已吊销状态，删除记录后同一指纹再次上报将作为新设备重新登记，吊销不再生效"
	}
	s.audit(r, "security", "删除终端登记："+d.Account+" / "+d.Name+"（指纹 "+shortFP(d.Fingerprint)+
		"，同时删除其终端环境报告）"+extra, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "device": d})
}

// handleCleanupStaleDevices 批量清理陈旧设备（PermSecurity）。
//
// 陈旧 = last_seen（最近一次 posture 上报）早于 staleDays 天前。**跳过 revoked**，
// 理由见 store.PurgeStaleDevices：清掉吊销记录等于给吊销配一个静默的有效期。
func (s *Server) handleCleanupStaleDevices(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	st, err := s.store.DeviceTrustSetting(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load device trust setting")
		return
	}
	victims, err := s.writer.PurgeStaleDevices(r.Context(), st.StaleDays)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to purge stale devices")
		return
	}
	if len(victims) > 0 {
		names := make([]string, 0, len(victims))
		for _, d := range victims {
			names = append(names, d.Account+"/"+d.Name)
		}
		shown := strings.Join(names, "、")
		if len(names) > 5 {
			shown = strings.Join(names[:5], "、") + " 等 " + strconv.Itoa(len(names)) + " 台"
		}
		s.audit(r, "security", "清理陈旧终端 "+strconv.Itoa(len(victims))+" 台（超过 "+strconv.Itoa(st.StaleDays)+
			" 天未上报终端环境；已吊销设备不在清理范围内）："+shown, "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "removed": len(victims), "devices": victims, "staleDays": st.StaleDays})
}

// ── 吊销联动 ──

// deviceRevokeBlastRadius 吊销影响面说明。控制台确认框与 API 应答用**同一份文本**，
// 免得界面上写一套、实际做另一套。
const deviceRevokeBlastRadius = "数据面的撤销通道按**账号**表达（网关只认账号，敲门令牌与放行窗里都没有设备维度），" +
	"因此吊销该终端会切断该账号在所有终端上的活跃隧道，并在 5 分钟封禁窗内拒绝其重新接入（含已授信设备）。" +
	"封禁到期后，其余已授信终端可正常接入；被吊销的这一台在严格与观察两种模式下都将被持续拒绝。"

// banAccountForDevice 把设备所属账号并入强制下线封禁表，返回封禁截止时间。
//
// 复用强制下线那条既有通道（s.revoked → handleGatewayPolicy 下发 → 网关 applyRevoked
// 撤放行窗 + KillUser 断隧道）。这是本轮**能做到**的最强处置；按设备撤销做不到，
// 原因与取舍见文件头 ③。
func (s *Server) banAccountForDevice(d store.Device, reason string) int64 {
	until := time.Now().Add(kickBanTTL).Unix()
	txt := "授信终端已吊销"
	if strings.TrimSpace(reason) != "" {
		txt += "：" + strings.TrimSpace(reason)
	}
	s.mu.Lock()
	s.revoked[normUser(d.Account)] = revokeInfo{Reason: txt, Until: until, Display: d.Account}
	s.mu.Unlock()
	return until
}

// deviceRevokeAudit 吊销审计文案。**只记已发生的事实**：设备被置为 revoked、
// 账号被并入封禁名单到几点、以及"按账号撤销"这个真实的影响面。
// 不写"已切断该设备隧道"——控制面并没有、也无法做到只切一台设备。
func deviceRevokeAudit(d store.Device, reason string, until int64) string {
	txt := "吊销授信终端：" + d.Account + " / " + d.Name + "（指纹 " + shortFP(d.Fingerprint) + "）"
	if strings.TrimSpace(reason) != "" {
		txt += "，理由：" + strings.TrimSpace(reason)
	}
	return txt + "。该终端此后在观察与严格两种准入模式下均被拒发敲门令牌；" +
		"同时已将账号 " + d.Account + " 并入强制下线封禁至 " + time.Unix(until, 0).Format("15:04:05") +
		"，网关下一轮策略轮询将撤销其放行窗口并切断隧道——" +
		"★撤销通道按账号表达，影响该账号在所有终端上的会话，不只是被吊销的这一台"
}

// shortFP 指纹的可读短形（审计与提示文案用；指纹本身不是秘密，截断只为可读）。
func shortFP(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "…"
}

// actorOf 取当前请求的行为人账号（批准人 / 审批人落库用）。
func actorOf(r *http.Request) string {
	if c, ok := auth.FromContext(r.Context()); ok {
		if c.Name != "" {
			return c.Name
		}
		return c.Sub
	}
	return "system"
}
