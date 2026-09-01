package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
	"baidi.dev/control/internal/upgrade"
)

// 产品升级管理（PRD 第 4 章）REST。
//
//	GET  /api/v1/upgrade                 当前版本 + 组件版本 + 规则 + 灰度计划（读=任意管理员）
//	PUT  /api/v1/upgrade/rules           改升级校验规则（PermSystem）
//	POST /api/v1/upgrade/check           上传包描述+签名，即时回校验结论（PermSystem）
//	PUT  /api/v1/upgrade/gray            保存某平台灰度计划（PermSystem）
//	POST /api/v1/upgrade/backup          导出加密配置备份（PermSystem ∩ PermAdmins，见 handleBackup）
//	POST /api/v1/upgrade/backup/inspect  只读备份头部，不解密（PermSystem）
//	GET  /api/v1/client/update           终端检查更新（登录用户；灰度判定在这里发生）
//
// ★权限归 PermSystem：升级是系统管理员职责。**备份导出例外，要两权**
// （PermSystem ∩ PermAdmins，理由见 handleBackup）——一份备份含 CA 私钥与全部凭据，
// 能导出备份等于能带走整套系统的信任材料，进而能自签任意管理员令牌。

// upgradeBundle 升级管理页一次取全。
type upgradeBundle struct {
	Control  string             `json:"control"`  // 控制面当前版本
	Gateways map[string]string  `json:"gateways"` // 网关 id → 上报版本（空串=旧网关不上报）
	Rules    upgrade.Rules      `json:"rules"`
	Gray     []upgrade.GrayPlan `json:"gray"`
	// Coverage 每条灰度计划**精确**命中的账号数（key = platform）。
	//
	// ★不是 accounts×percent/100 的估算：分桶是确定性的，真实命中数能直接数出来
	// （upgrade.Coverage）。显示近似值会让管理员在「说好 10% 结果 13 个人」时
	// 怀疑灰度本身有问题。改造前这个函数**全仓只有三条单测在调**，
	// 而它的注释白纸黑字写着「供控制台显示『预计影响 N 人』」。
	Coverage map[string]int `json:"coverage"`
	// Total 参与分桶的账号总数（覆盖数的分母）。
	Total int `json:"total"`
	// Versions 现场终端的**实际**版本分布（posture 上报）。灰度只决定"告诉谁有新版"，
	// 不决定任何人实际装了什么——放开比例前要看的是这一份。
	Versions []store.ClientVersionStat `json:"versions"`
	// Groups 用户组候选（灰度定向用，与资源授权/认证策略共用 subjectOptions）。
	Groups []subjectOption `json:"groups"`
	// SignKeysConfigured 是否配了升级包发布公钥（BAIDI_UPGRADE_PUBKEY）。
	//
	// ★没配时验签是 **fail-closed** 的（`upgrade.VerifySignature` 直接拒），
	// 于是「上传包 → 校验」这条路在任何未配置的部署上**恒为「校验不通过」**，
	// 而页面上此前不说原因——管理员会以为是自己的包有问题，反复换包重传。
	// 现在页面据此**预先**置灰校验入口并说清怎么配（发布方 genkey → 填公钥），
	// 而不是让人先撞一次墙。
	SignKeysConfigured bool `json:"signKeysConfigured"`
	// SignKeyNote 未配置时的一句人话（后端下发，页面不自己编）。
	SignKeyNote string `json:"signKeyNote,omitempty"`
	// Boundaries 如实告知本功能做到哪、没做哪——PRD 第 4 章有大量源产品专有内容，
	// 不说清楚的话，管理员会以为界面上没有的就是「还没做完」而不是「刻意不做」。
	Boundaries []string `json:"boundaries"`
}

// upgradeBoundaries 是这一章最重要的诚实声明，直接展示在页面上。
func upgradeBoundaries() []string {
	return []string{
		"白帝的服务端升级由部署脚本执行（deploy/deploy.sh 重跑即换版本并保留数据库）。" +
			"控制台负责升级前的校验与备份，不代替脚本替换二进制——那需要进程自替换与回滚，" +
			"当前未实现，谎称能一键升级的后果是升级中断时无人能恢复。",
		"源 PRD 里的版本链（2.1.1→2.1.5→2.1.12）、包格式（.run/.ssu/.bin）、" +
			"后台账号与默认口令是源产品的实现事实，白帝没有那段历史，故未照搬。" +
			"强制跳跃链路机制保留，版本号由管理员在下方规则里自行配置。",
		"集群升级编排（先备后主 / 拆集群逐台）未实现：白帝控制面没有双活形态，" +
			"只有温备（备机周期拉加密备份、不提供服务，见系统管理→集群）。" +
			"温备节点上没有需要升级的服务端进程——它只跑 baidi-standby，" +
			"换版本就是重跑一次部署脚本；编排一个不存在的多活拓扑没有意义。",
	}
}

func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	b, err := s.upgradeBundle(r)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load upgrade config")
		return
	}
	httpx.JSON(w, http.StatusOK, b)
}

func (s *Server) upgradeBundle(r *http.Request) (upgradeBundle, error) {
	b := upgradeBundle{Control: Version, Gateways: s.gatewayVersions(), Boundaries: upgradeBoundaries()}
	b.SignKeysConfigured = len(s.upgradeKeys) > 0
	if !b.SignKeysConfigured {
		b.SignKeyNote = "未配置升级包发布公钥（BAIDI_UPGRADE_PUBKEY），升级包校验不可用——" +
			"这是 fail-closed 的默认姿态：不验签就等于任何人都能推一个包上来。" +
			"需要用这个功能时：① 在**发布方**机器上跑 `baidi-upgrade -genkey`（私钥绝不放到控制面机器上）；" +
			"② 把 upgrade-sign.pub 的内容填进部署的 BAIDI_UPGRADE_PUBKEY（轮换期可逗号分隔多把）；" +
			"③ 发包时用 `baidi-upgrade -manifest/-sign` 产出 manifest 与签名，上传时一并提交。"
	}
	if s.upg == nil {
		b.Rules = upgrade.DefaultRules()
		b.Gray = []upgrade.GrayPlan{}
		return b, nil
	}
	var err error
	if b.Rules, err = s.upg.UpgradeRules(r.Context()); err != nil {
		return b, err
	}
	if b.Gray, err = s.upg.GrayPlans(r.Context()); err != nil {
		return b, err
	}
	s.fillGrayCoverage(r, &b)
	return b, nil
}

// fillGrayCoverage 补上「预计影响 N 人」「实际版本分布」「用户组候选」三样。
//
// best-effort：任何一处读失败都只让对应字段缺席，不影响升级页主体
// （规则与灰度计划已经取到了）。★缺席与 0 在前端是两种渲染：
// 前者显示「—（读取失败）」，后者显示「0 人」——把读失败画成 0 人，
// 管理员会以为这条灰度谁也没命中，进而把比例调高。
func (s *Server) fillGrayCoverage(r *http.Request, b *upgradeBundle) {
	if vs, ok := s.store.(interface {
		ClientVersionStats(ctx context.Context) ([]store.ClientVersionStat, error)
	}); ok {
		if list, err := vs.ClientVersionStats(r.Context()); err == nil {
			b.Versions = list
		}
	}
	_, groups, err := s.subjectOptions(r.Context())
	if err == nil {
		b.Groups = groups
	}
	ub, err := s.store.Users(r.Context())
	if err != nil {
		return
	}
	// ★分母是**目录里的全部账号**，与 Decide 的入参口径一致。
	// 只数"在线的"或"报过 posture 的"会让同一条计划在不同时刻显示不同的覆盖数，
	// 而分桶本身是确定性的——那种跳动会被读成"灰度不稳定"。
	accounts := make([]string, 0, len(ub.Users))
	for _, u := range ub.Users {
		accounts = append(accounts, u.Account)
	}
	b.Total = len(accounts)
	groupsOf := func(string) []string { return nil }
	if ix, err := s.store.SubjectIndex(r.Context()); err == nil {
		byAcct := map[string][]string{}
		for gid, accts := range ix.GroupAccounts {
			for _, a := range accts {
				byAcct[a] = append(byAcct[a], gid)
			}
		}
		groupsOf = func(a string) []string { return byAcct[normUser(a)] }
	}
	b.Coverage = map[string]int{}
	for _, p := range b.Gray {
		b.Coverage[p.Platform] = upgrade.Coverage(p, accounts, groupsOf)
	}
}

// gatewayVersions 取各网关**上报**的版本。旧网关不上报时是空串——
// 空串必须原样传给判定层，由它标成「无法校验」；在这里补成当前版本
// 会让「网关其实是旧版」这件事永远不被发现。
func (s *Server) gatewayVersions() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.gateways))
	for id, g := range s.gateways {
		out[id] = g.Version
	}
	return out
}

func (s *Server) handleSaveUpgradeRules(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) || !s.upgradeReady(w) {
		return
	}
	var rules upgrade.Rules
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&rules); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid rules payload")
		return
	}
	if err := s.upg.SaveUpgradeRules(r.Context(), rules); err != nil {
		httpx.Error(w, http.StatusBadRequest, "升级规则不合法："+err.Error())
		return
	}
	s.audit(r, "system", fmt.Sprintf("修改升级校验规则：允许降级=%v 组件一致性=%v 强制链路=%d 条",
		rules.AllowDowngrade, rules.RequireComponentMatch, len(rules.Hops)), "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "rules": rules})
}

// handleUpgradeCheck 上传包描述 + 签名，即时回校验结论（PRD 4.5「上传即校验」）。
//
// 只收描述与签名、不收包体：包体动辄上百 MB，而全部**判定**信息都在描述里。
// 包体的校验和由执行升级的一方（部署脚本 / uctl）在落盘时用 upgrade.VerifyPayload 核对，
// 控制台负责的是「这个包该不该升」而不是「这个文件传完整了没有」。
func (s *Server) handleUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	var body struct {
		Manifest  json.RawMessage `json:"manifest"`  // 描述原文（验签对象，必须原样传，不能重新序列化）
		Signature string          `json:"signature"` // base64
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid payload")
		return
	}
	m, err := upgrade.ParseManifest(body.Manifest)
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{
			"blocked": true, "reasons": []string{err.Error()}})
		return
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body.Signature))
	if err != nil {
		httpx.JSON(w, http.StatusOK, map[string]any{
			"blocked": true, "reasons": []string{"签名不是合法的 base64"}})
		return
	}
	if err := upgrade.VerifySignature(body.Manifest, sig, s.upgradeKeys); err != nil {
		s.audit(r, "system", "升级包验签失败："+m.Version+"（"+err.Error()+"）", "fail")
		httpx.JSON(w, http.StatusOK, map[string]any{
			"blocked": true, "reasons": []string{err.Error()}, "manifest": m})
		return
	}

	rules := upgrade.DefaultRules()
	if s.upg != nil {
		if got, err := s.upg.UpgradeRules(r.Context()); err == nil {
			rules = got
		}
	}
	c := upgrade.CheckPackage(m, Version, rules, upgrade.Components{
		Control: Version, Gateways: s.gatewayVersions()})
	s.audit(r, "system", fmt.Sprintf("校验升级包 %s→%s（组件 %s）：%s",
		Version, m.Version, m.Component, verdictWord(c.Blocked)), okFail(!c.Blocked))
	httpx.JSON(w, http.StatusOK, map[string]any{
		"blocked": c.Blocked, "reasons": c.Reasons, "warnings": c.Warnings,
		"nextHop": c.NextHop, "manifest": m})
}

func verdictWord(blocked bool) string {
	if blocked {
		return "不通过"
	}
	return "通过"
}
func okFail(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

func (s *Server) handleSaveGrayPlan(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) || !s.upgradeReady(w) {
		return
	}
	var p upgrade.GrayPlan
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&p); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid gray plan payload")
		return
	}
	plans, err := s.upg.SaveGrayPlan(r.Context(), p)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	verb := fmt.Sprintf("设置 %s 平台灰度：%s → %s（%d%%，定向 %d 账号 / %d 组）",
		p.Platform, p.Stable, p.Version, p.Percent, len(p.Accounts), len(p.Groups))
	if p.Version == "" {
		verb = fmt.Sprintf("撤销 %s 平台的灰度计划", p.Platform)
	}
	s.audit(r, "system", verb, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "gray": plans})
}

// handleClientUpdate 终端检查更新（FR-UPG-19 的消费端）。
//
// ★灰度判定在**服务端**做，客户端只被告知一个版本号。
// 让客户端自己算比例的话，改一个本地配置就能提前拿到灰度包，
// 灰度也就失去了「先小范围验证」的意义。
func (s *Server) handleClientUpdate(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.FromContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "需要登录")
		return
	}
	platform := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("platform")))
	if platform == "" {
		httpx.Error(w, http.StatusBadRequest, "缺少 platform 参数")
		return
	}
	current := strings.TrimSpace(r.URL.Query().Get("version"))

	var plans []upgrade.GrayPlan
	if s.upg != nil {
		if got, err := s.upg.GrayPlans(r.Context()); err == nil {
			plans = got
		} else {
			// 读不出灰度计划时**不下发任何更新**，而不是回稳定版：
			// 回稳定版会把灰度中的终端悄悄降回旧版本。
			httpx.Error(w, http.StatusServiceUnavailable, "灰度配置暂不可读，请稍后重试")
			return
		}
	}
	var plan upgrade.GrayPlan
	for _, p := range plans {
		if p.Platform == platform {
			plan = p
			break
		}
	}
	if plan.Platform == "" {
		httpx.JSON(w, http.StatusOK, map[string]any{
			"platform": platform, "current": current, "update": false,
			"reason": "该平台当前没有发布计划"})
		return
	}

	d := upgrade.Decide(plan, c.Sub, s.groupsOf(r, c.Sub))
	resp := map[string]any{
		"platform": platform, "current": current,
		"latest": d.Version, "inGray": d.InGray, "reason": d.Reason, "update": false,
	}
	// 只有目标版本**高于**当前版本才提示更新。相等或更低时不提示——
	// 提示一个「更新」到更旧的版本，用户点下去就是降级。
	if d.Version != "" && current != "" {
		cur, e1 := upgrade.ParseVersion(current)
		tgt, e2 := upgrade.ParseVersion(d.Version)
		if e1 == nil && e2 == nil && tgt.Compare(cur) > 0 {
			resp["update"] = true
		}
	} else if d.Version != "" && current == "" {
		resp["update"] = true // 客户端没报版本：把最新版告诉它，由它自行比对
	}
	httpx.JSON(w, http.StatusOK, resp)
}

// groupsOf 取某账号所属用户组 id（灰度的定向分组用）。
// 展开在控制面做，与资源授权的组织/组展开同一条纪律。
func (s *Server) groupsOf(r *http.Request, account string) []string {
	b, err := s.store.Users(r.Context())
	if err != nil {
		return nil
	}
	for _, u := range b.Users {
		if strings.EqualFold(strings.TrimSpace(u.Account), strings.TrimSpace(account)) {
			return u.GroupIDs
		}
	}
	return nil
}

// ── 配置备份与恢复（FR-UPG-09/10）──

// handleBackup 导出加密配置备份。
//
// ★权限是 `PermSystem ∩ PermAdmins`（实际只有 root），不是单 PermSystem。
//
// 这份备份**就是**温备端点吐出来的那一份（同一个 backupSources）：CA 私钥 + 三把
// 签名私钥 + 审计链密钥 + 认证源凭据 + IPSec PSK + 整个库。口令还由导出者自己指定，
// 也就是他随手就能解开。于是单 PermSystem 时三权分立可以被一条直路绕开：
// 系统管理员导出备份 → 解出 BAIDI_JWT_KEY → 自签一张 Name=某 root 的会话令牌 →
// requireAdmin/currentAdminRole 按账号现算角色，直接拿到全权（含他本不该有的 PermAudit）。
// 「能拿走全部信任材料」等价于「能造任意管理员」，所以它必须要 admins 权。
// 与审计外送出口增删（PermSystem ∩ PermAudit）是同一条不变量的另一面。
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerms(w, r, store.PermSystem, store.PermAdmins) {
		return
	}
	var body struct {
		Passphrase string `json:"passphrase"`
		Note       string `json:"note"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid payload")
		return
	}
	// 输入校验先做：口令太短是用户输入问题，不该被「没有可备份材料」这种
	// 环境问题的错误码盖过去（那会让管理员以为是系统坏了而不是自己口令太短）。
	if err := upgrade.CheckPassphrase(body.Passphrase); err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	sources, cleanup, err := s.backupSources(r.Context())
	defer cleanup()
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	meta := upgrade.BackupMeta{
		Version: Version, CreatedAt: time.Now().Format("2006-01-02 15:04:05"), Note: body.Note,
	}
	var buf bytes.Buffer
	if err := upgrade.CreateBackup(&buf, meta, body.Passphrase, sources); err != nil {
		if errors.Is(err, upgrade.ErrBackupPassphrase) {
			httpx.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.Error(w, http.StatusInternalServerError, "备份失败："+err.Error())
		return
	}
	// ★审计里绝不记口令，只记「谁在什么时候导出了备份」——
	// 备份被导出这件事本身就是最该留痕的动作之一（一份备份=整套信任材料）。
	s.audit(r, "system", fmt.Sprintf("导出配置备份（%d 项材料，%d 字节）", len(sources), buf.Len()), "ok")

	name := "baidi-backup-" + time.Now().Format("20060102-150405") + ".bak"
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	_, _ = w.Write(buf.Bytes())
}

// handleBackupInspect 只读备份头部（不解密），供恢复前核对这份备份是哪台机器、哪个版本。
func (s *Server) handleBackupInspect(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSystem) {
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<20))
	if err != nil {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "备份文件过大（上限 256 MiB）")
		return
	}
	meta, _, err := upgrade.ReadBackupMeta(b)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	warn := ""
	if meta.Version != Version {
		warn = fmt.Sprintf("这份备份来自 %s，当前运行 %s：跨版本恢复可能与数据库结构不兼容。",
			meta.Version, Version)
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"meta": meta, "warning": warn})
}

// backupSources 列出要备份的持久化材料。
//
// ★恢复的执行方**刻意不做成 HTTP 端点**：恢复要覆写正在被使用的数据库与密钥文件，
// 在进程运行中就地覆盖会让一半请求读到旧库、一半读到新库，且失败后没有回头路。
// 恢复由停机后的部署脚本执行（解开归档覆盖回目录再启动），控制台只负责导出与预览。
// 这条边界写在 upgradeBoundaries 里直接呈现给管理员。
// 第二个返回值是清理函数（删掉临时的数据库快照），调用方必须 defer 掉它。
func (s *Server) backupSources(ctx context.Context) ([]upgrade.BackupSource, func(), error) {
	var out []upgrade.BackupSource
	add := func(name, path string) {
		if path == "" {
			return
		}
		if _, err := os.Stat(path); err == nil {
			out = append(out, upgrade.BackupSource{Name: name, Path: path})
		}
	}
	cleanup := func() {}
	// ★库路径问真正在用的那个 store，不自己重读 BAIDI_DB 推导：
	// 两处推导一旦不一致，备份会静默不含数据库，而管理员以为自己有完整备份——
	// 这类错误只在真正需要恢复的那天才暴露。
	type dbPather interface{ DBPath() string }
	p, ok := s.store.(dbPather)
	if !ok || p.DBPath() == "" {
		return nil, cleanup, errors.New("当前后端没有可备份的持久化材料（纯内存演示栈）")
	}
	if _, err := os.Stat(p.DBPath()); err != nil {
		// 找不到库文件就**直接失败**，绝不产出一份不含数据库的「成功」备份。
		return nil, cleanup, fmt.Errorf("数据库文件不可读（%s）：%v", p.DBPath(), err)
	}
	// ★进归档的必须是**一致性快照**，不是活库文件本身。
	//
	// 库跑在 WAL 模式下，提交先落 baidi.db-wal，主库文件只在 checkpoint 时才被写回；
	// 直接整读主库文件（且不带 -wal）拿到的是「上一次 checkpoint 为止」的内容——
	// 今天改的策略、建的账号可能一条都不在里面，而备份解得开、也含 baidi.db，
	// 备机校验通过、页面显示「同步新鲜 · RPO = 10 分钟」，真实 RPO 无上界。
	// 这类错误只在真正切换的那天暴露，所以判据必须结构性成立，不能靠"记得先 checkpoint"。
	type snapshotter interface {
		SnapshotTo(context.Context, string) error
	}
	sn, ok := s.store.(snapshotter)
	if !ok {
		return nil, cleanup, errors.New("当前存储后端不支持一致性快照，拒绝产出可能缺数据的备份")
	}
	dir, err := os.MkdirTemp("", "baidi-backup-")
	if err != nil {
		return nil, cleanup, fmt.Errorf("创建快照临时目录失败：%v", err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	snap := filepath.Join(dir, "baidi.db")
	if err := sn.SnapshotTo(ctx, snap); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	add("baidi.db", snap)
	// ★内部 CA 与三把签名私钥：问**真正在用它们的那个对象**要路径，绝不重读环境变量。
	//
	//   此前这里是 os.Getenv("BAIDI_PKI_DIR") 与三个 BAIDI_JWT_*_KEY，而这四项在
	//   config 里**都有非空默认值**（pki / jwt-ed25519{,-knock,-web}.pem）——标准部署
	//   根本不设那些环境变量，于是四项材料全部静默跳过（add 对空路径直接 return）。
	//   备份照样"成功"，备机校验（解得开 + 含 baidi.db）照样通过，页面显示同步新鲜。
	//   只在真正恢复的那天暴露：
	//     - 内部 CA 丢了 → 签不出网关 mTLS 证书、也验不了已签发的那些 → 网关全部连不上控制面；
	//     - 三把私钥丢了 → control 重新生成，而各网关装的还是旧公钥 → 敲门令牌验不过
	//       （全员无法接入）、web 票据验不过（B/S 全挂）。
	//   同一个函数里审计链密钥那条早就改成问 store 要真路径了（见下），这四项是漏网的那半。
	if s.ca != nil {
		add("pki", s.ca.Dir())
	}
	kp := s.keys.Paths()
	for _, k := range []string{kp.Sess, kp.Knock, kp.Web} {
		if k == "" {
			continue
		}
		add(filepath.Base(k), k)
		add(filepath.Base(k)+".pub", k+".pub")
	}
	// ★审计链密钥问 store 要真正在用的那份，不读环境变量。
	// 该变量默认为空（默认路径由 OpenSQLite 按库文件目录推导），照旧写法的后果是
	// **标准部署的备份里根本没有这把密钥**，恢复后全链校验永久失败。
	type auditKeyPather interface{ AuditKeyPath() string }
	if k, ok := s.store.(auditKeyPather); ok {
		add("audit-hmac.key", k.AuditKeyPath())
	}
	return out, cleanup, nil
}

// upgradeReady 后端是否支持升级配置持久化。
func (s *Server) upgradeReady(w http.ResponseWriter) bool {
	if s.upg == nil {
		httpx.Error(w, http.StatusServiceUnavailable,
			"当前后端不支持升级配置（需要 SQLite 存储；纯内存演示栈无此能力）")
		return false
	}
	return true
}

// parseUpgradeKeys 解析 BAIDI_UPGRADE_PUBKEY（base64 的 Ed25519 公钥，逗号分隔可多把供轮换）。
func parseUpgradeKeys(env string) []ed25519.PublicKey {
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
