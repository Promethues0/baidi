package api

// 用户批量导入导出（wave7 行动 14 · users 域）。
//
// 两条纪律贯穿本文件：
//
// ① 导出：每个单元格都过 csvCell。账号名、姓名、组织名全是用户/管理员可控的文本，
//    以 = + - @ 开头的单元格会被 Excel/LibreOffice 当公式求值（DDE 可外带数据甚至
//    执行命令）。这份 CSV 的读者就是拿电子表格打开它的人，中和是唯一正确的默认。
//    口径与 handleAuditExport 完全一致（同一个 csvCell）。
//
// ② 导入：**不是建管理员的后门**。POST /api/v1/users 早已收口成只建普通用户，
//    建管理员的唯一入口是 POST /api/v1/admins（需 PermAdmins，只有超管持有）。
//    一个能从 CSV 里读 role 列的导入器，等于把那道收口整个绕过去——而且是批量的、
//    在一份看起来只是"人员名单"的文件里。这里的做法是**当场拒收整份文件**
//    （见 rejectedImportColumns）：静默忽略也能挡住提权，但管理员会以为自己导入了
//    一批管理员，直到某天发现那些人登不进控制台——那是另一种静默失效。
//    纵深第二道：buildImportUser 无条件写死 Role="user" / AdminRole=""，
//    即便将来有人给解析器加了 role 列，它也落不到库里。

import (
	"encoding/csv"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

const (
	// userImportMaxBytes 单文件字节上限。先于一切解析生效——行数上限要先把文件读进来
	// 才判得了，字节上限是那之前唯一的闸。
	userImportMaxBytes = 1 << 20 // 1 MiB
	// userImportMaxRows 单次导入的数据行上限。
	//
	// ★这个数字受制于 bcrypt 而不是内存：每行要哈希一次初始口令（cost 10，约 50~100ms），
	// 500 行就已经是半分钟量级的同步请求。再往上，请求会先被前置 nginx 的读超时掐断，
	// 而那时账号已经建了一半——调用方看到的是"导入失败"，库里却多了几百个账号，
	// 且逐行回报随响应一起丢失。宁可让管理员分批导，也不要那种半成品。
	userImportMaxRows = 500
	// usersCSVBOM UTF-8 BOM 的字符串形态。导出时写它（Excel 认它才不把中文显示成乱码），
	// 导入时剥它（Excel 存盘也会写它，不剥的话首列表头永远匹配不上）。
	usersCSVBOM = "\uFEFF"
)

// ── 导出 ──────────────────────────────────────────────────────────────

// handleUsersExport GET /api/v1/users/export（PermSecurity）：流式导出用户台账 CSV 附件。
//
// 权限比列表页（GET /api/v1/users 是 requireAdmin，任意管理员）**更严**：
// 逐页浏览目录与"把整份人员台账打成一个文件带走"不是一回事，后者是一次性的批量外带。
// 收在 PermSecurity（用户与组织本来就归这一权）也让导出与导入同权，
// 页面上那两个按钮落在同一条权限线上，不会出现"能导入不能导出"的怪组合。
func (s *Server) handleUsersExport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	ex, ok := s.store.(store.UserExporter)
	if !ok {
		httpx.Error(w, http.StatusInternalServerError, "当前存储不支持用户台账导出")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="baidi-users-`+time.Now().Format("20060102")+`.csv"`)
	w.WriteHeader(http.StatusOK)
	// UTF-8 BOM：Excel 打开含中文的 CSV 不乱码（与审计导出同一处理）。
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	// 表头同时是导入侧认得的列名（组织ID / 组织 两列都给，见 userExportOrgNote）。
	_ = cw.Write([]string{"账号", "姓名", "组织", "组织ID", "用户组", "状态", "角色", "管理员角色", "邮箱", "最后登录", "创建时间"})
	n := 0
	err := ex.ExportUsers(r.Context(), func(u store.UserExportRow) error {
		n++
		// 全列过 csvCell：账号/姓名/组织名/用户组名都是可控文本，逐列判断"哪列可信"
		// 是一种迟早会判错的省事——统一中和，代价只是极少数以 - 开头的名字前多个单引号。
		return cw.Write([]string{
			csvCell(u.Account), csvCell(u.Name), csvCell(u.Org), csvCell(u.OrgID),
			csvCell(strings.Join(u.Groups, ";")),
			csvCell(pickStr(statusZh[u.Status], u.Status)),
			csvCell(userRoleZh(u.Role)), csvCell(u.AdminRole), csvCell(u.Email),
			csvCell(u.LastLogin), csvCell(u.CreatedAt),
		})
	})
	cw.Flush()
	if err != nil {
		// 响应头已发出，改不了状态码；靠截断让下载侧感知失败，且不落"已导出"审计。
		return
	}
	// 审计只记已发生的事实：流式写完才算导出完成（措辞与审计导出同构）。
	s.audit(r, "admin", "导出用户台账 CSV，共 "+strconv.Itoa(n)+" 条（不含口令哈希与口令强度）", "ok")
}

// userRoleZh 权威鉴权角色的中文名。导出面向人读，admin|user 两个英文词在一列
// 中文表头下会被误当成"某个系统里的用户名"。
func userRoleZh(role string) string {
	if role == "admin" {
		return "管理员"
	}
	return "普通用户"
}

// ── 导入 ──────────────────────────────────────────────────────────────

// userImportResult 逐行结果的一项。成功给 id，失败给 reason——
// 「部分失败不整批回滚」的前提是调用方能逐行看到发生了什么（照 handleIdleLock 的先例）。
type userImportResult struct {
	// Row 是**文件里的物理行号**（含表头行，故首个数据行通常是 2），不是"第几条记录"：
	// 管理员要拿这个数字回到 Excel 里定位那一行。带引号的多行单元格会让两者不等，
	// 所以取自 csv.Reader.FieldPos 而不是循环计数。
	Row     int    `json:"row"`
	Account string `json:"account,omitempty"`
	Name    string `json:"name,omitempty"`
	ID      string `json:"id,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// handleUsersImport POST /api/v1/users/import（PermSecurity）：CSV 批量建普通用户。
//
// 请求体就是 CSV 原文（Content-Type 随意，按字节读）。逐行执行、逐行回报，
// 部分失败不回滚已成功的那些——批量导入 300 个账号时，因为第 47 行的部门名打错
// 而整批消失，是最没法向管理员交代的行为。
func (s *Server) handleUsersImport(w http.ResponseWriter, r *http.Request) {
	if !s.requirePerm(w, r, store.PermSecurity) {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, userImportMaxBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			httpx.Error(w, http.StatusRequestEntityTooLarge,
				"CSV 超过单文件上限 "+strconv.Itoa(userImportMaxBytes>>10)+" KiB，请拆分后分批导入")
			return
		}
		httpx.Error(w, http.StatusBadRequest, "读取上传内容失败")
		return
	}
	// Excel 存出来的 CSV 带 BOM（我们自己的导出也带）。不剥的话首列表头会变成
	// "<BOM>账号"，于是"账号列缺失"——一个只在 Excel 用户身上复现的失败。
	body := strings.TrimPrefix(string(raw), usersCSVBOM)
	if strings.TrimSpace(body) == "" {
		httpx.Error(w, http.StatusBadRequest, "CSV 内容为空")
		return
	}

	rd := csv.NewReader(strings.NewReader(body))
	// 允许列数参差：短一列的行按缺字段处理并逐行回报，比整份文件在第一处畸形上
	// 报一句 "wrong number of fields" 有用得多。
	rd.FieldsPerRecord = -1
	header, err := rd.Read()
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "CSV 表头解析失败："+userCSVErrZh(err))
		return
	}
	cols, ignored, bad, badWhy := mapUserImportColumns(header)
	if bad != "" {
		// 角色列 = 一次批量提权尝试。它可能只是管理员把导出的台账原样传了回来
		// （那份带角色列），但两种情况在服务端无从分辨，一律拒收并留痕。
		s.audit(r, "security", "拒绝用户批量导入：CSV 含不可导入的列「"+bad+"」——"+badWhy, "deny")
		httpx.Error(w, http.StatusBadRequest, "CSV 含不可导入的列「"+bad+"」："+badWhy)
		return
	}
	if cols.account < 0 || cols.name < 0 {
		httpx.Error(w, http.StatusBadRequest,
			"CSV 表头须含「账号」与「姓名」两列（可选列：组织 / 组织ID / 用户组 / 邮箱 / 初始口令）")
		return
	}

	// 先整份读进来（字节数已被上限夹住），为的是在**动手建号之前**判行数上限：
	// 边读边建的话，超限那一刻前面几百个账号已经落库了。
	type rawRow struct {
		line int
		rec  []string
	}
	rows := []rawRow{}
	for {
		rec, err := rd.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// ★行号只能从 ParseError 取，不能用 FieldPos：解析失败那一轮 fieldPositions 是空的，
			// 而 FieldPos 的契约是「越界即 panic」（encoding/csv/reader.go）。此前这里先调 FieldPos
			// 再判 err，于是**数据行**里只要有一个落单的引号就 panic 成 500 internal error——
			// 而下面这句精心写的中文原因，反倒只在表头畸形时才可达。
			// 触发门槛就是「Excel 存出来的文件里有个孤引号」，不是构造攻击。
			l := 0
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				l = pe.Line
			}
			httpx.Error(w, http.StatusBadRequest, "CSV 第 "+strconv.Itoa(l)+" 行解析失败："+userCSVErrZh(err))
			return
		}
		line, _ := rd.FieldPos(0) // 只在 err==nil 之后调；拿的是**物理行号**（管理员回 Excel 定位用）
		if blankUserRecord(rec) {
			continue // Excel 常在末尾留空行，不算一条失败
		}
		rows = append(rows, rawRow{line: line, rec: rec})
		if len(rows) > userImportMaxRows {
			httpx.Error(w, http.StatusBadRequest,
				"CSV 数据行超过单次导入上限 "+strconv.Itoa(userImportMaxRows)+" 行，请拆分后分批导入")
			return
		}
	}
	if len(rows) == 0 {
		httpx.Error(w, http.StatusBadRequest, "CSV 只有表头，没有数据行")
		return
	}

	// 组织与用户组字典一次取齐（不随行数放大）：逐行查库会把一次导入变成上千次往返，
	// 而这两张表在一次导入期间不会变。
	orgs, err := s.store.OrgUnits(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "组织清单读取失败")
		return
	}
	groups, err := s.store.UserGroups(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "用户组清单读取失败")
		return
	}

	created := []userImportResult{}
	failed := []userImportResult{}
	seen := map[string]int{} // 规范化账号 → 已出现的行号
	for _, row := range rows {
		acct := strings.TrimSpace(userCell(row.rec, cols.account))
		name := strings.TrimSpace(userCell(row.rec, cols.name))
		res := userImportResult{Row: row.line, Account: acct, Name: name}
		fail := func(reason string) {
			res.Reason = reason
			failed = append(failed, res)
		}
		if acct == "" || name == "" {
			fail("账号与姓名都不能为空")
			continue
		}
		// 文件内查重与库内查重口径都用 lower(trim)——与 users.account 的唯一索引、
		// 与登录链路 Credential 的查法一致。两行 "Alice" 与 "alice" 是同一个令牌主体，
		// 让第二行安静地失败在建号那一步（唯一索引）只会得到一句 SQL 原文。
		key := normUser(acct)
		if prev, dup := seen[key]; dup {
			fail("文件内账号重复（第 " + strconv.Itoa(prev) + " 行已出现同一账号）")
			continue
		}
		seen[key] = row.line
		if _, exists, err := s.store.Credential(r.Context(), acct); err != nil {
			fail("账号查重失败，未创建")
			continue
		} else if exists {
			fail("账号已存在")
			continue
		}
		orgID, orgErr := resolveImportOrg(orgs, userCell(row.rec, cols.orgID), userCell(row.rec, cols.org))
		if orgErr != "" {
			fail(orgErr)
			continue
		}
		groupIDs, gErr := resolveImportGroups(groups, userCell(row.rec, cols.groups))
		if gErr != "" {
			fail(gErr)
			continue
		}
		pw := strings.TrimSpace(userCell(row.rec, cols.password))
		if pw == "" {
			pw = seedInitialPassword // 与 handleCreateUser 同一默认：留空也保证新账号可登录
		}
		if len(pw) < 6 {
			fail("初始口令至少 6 位")
			continue
		}
		// License 席位闸逐行判：导入若不判，它就是绕开容量限制最省事的一条路
		// （单个建号判、批量建号不判，等于没判）。
		if reason, ok := s.licenseAdmit(r, "user"); !ok {
			s.audit(r, "admin", "批量导入用户「"+acct+"」被 License 拒绝："+reason, "fail")
			fail(reason)
			continue
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			fail("口令哈希失败，未创建")
			continue
		}
		u := buildImportUser(name, acct, strings.TrimSpace(userCell(row.rec, cols.email)), orgID, groupIDs, hash, pw)
		out, err := s.writer.CreateUser(r.Context(), u)
		if err != nil {
			fail(importStoreErrZh(err))
			continue
		}
		res.ID = out.ID
		created = append(created, res)
		// 逐账号落审计：批量导入建出来的账号与手工建的账号在库里没有任何区别，
		// 审计里也不该有——每一个新身份都要能被单独追溯到是谁、什么时候建的。
		s.audit(r, "admin", "批量导入：新增用户「"+out.Name+"」("+out.Account+"，组织 "+
			pickStr(out.Org, "无归属")+")，已置首登改密", "ok")
	}
	s.audit(r, "admin", "用户批量导入完成：成功 "+strconv.Itoa(len(created))+" 条、失败 "+
		strconv.Itoa(len(failed))+" 条（共 "+strconv.Itoa(len(rows))+" 行）", "ok")

	resp := map[string]any{
		"ok": true, "total": len(rows), "created": created, "failed": failed,
	}
	if len(ignored) > 0 {
		// 未识别的列必须说出来：管理员填了一列"手机号"却什么都没发生时，
		// 页面上得有一句话解释，而不是让他以为存进去了。
		resp["ignoredColumns"] = ignored
	}
	httpx.JSON(w, http.StatusOK, resp)
}

// buildImportUser 把一行 CSV 装成待落库的 DirUser。
//
// ★Role / AdminRole 在这里被无条件写死，这是**第二道**防提权闸（第一道是
// mapUserImportColumns 直接拒收角色列）。两道都在，是因为它们防的是不同的事故：
// 第一道防"管理员误以为能用 CSV 建管理员"，第二道防"将来有人给解析器加了 role 列"。
func buildImportUser(name, account, email, orgID string, groupIDs []string, hash, plain string) store.DirUser {
	return store.DirUser{
		Name: name, Account: account, Email: email, OrgID: orgID, GroupIDs: groupIDs,
		PassHash:  hash,
		Role:      "user", // 见函数注释：导入永远只建普通用户
		AdminRole: "",
		// 口令强度只能在拿得到明文的这一刻判（登录链路只有 bcrypt 哈希）。
		// 不判的话，导入进来的账号 pw_strength 恒为 unknown，认证策略的「弱密码」
		// 增强规则对整批导入用户永久不命中——静默失效的经典形态。
		PwStrength: auth.PasswordStrength(account, plain),
		// 初始口令是管理员定的（或 CSV 里明文写的），不是本人私密：首登必须换掉。
		// 批量导入尤其如此——那份 CSV 会在邮件和聊天窗口里流传。
		MustChangePw: true,
		Device:       "未登记",
		IP:           "—",
		Auth:         "密码",
		Roles:        []string{},
	}
}

// userImportCols 各语义列在 CSV 里的下标，-1 = 该列不存在。
type userImportCols struct {
	account, name, org, orgID, groups, email, password int
}

// userImportAliases 列名别名表（规范化后比对）。刻意**不收** "用户名"/"username"：
// 中文语境里它既可能指姓名也可能指登录账号，猜错就是把两列对调后批量建号，
// 而结果看起来完全正常。宁可让它落进"未识别列"被报出来。
var userImportAliases = map[string]string{
	"账号": "account", "登录账号": "account", "account": "account",
	"姓名": "name", "名称": "name", "name": "name", "displayname": "name",
	"组织": "org", "部门": "org", "所属组织": "org", "org": "org", "department": "org",
	"组织id": "orgid", "部门id": "orgid", "orgid": "orgid", "org_id": "orgid",
	"用户组": "groups", "所属用户组": "groups", "groups": "groups", "group": "groups",
	"邮箱": "email", "电子邮件": "email", "email": "email", "mail": "email",
	"初始口令": "password", "口令": "password", "密码": "password", "初始密码": "password",
	"password": "password", "pwd": "password",
}

// rejectedImportColumns 一旦出现就拒收整份文件的列名（规范化后比对）。
// 全是"能决定这个账号有多大权"的列——导入这条路上它们只有一个用途：提权。
var rejectedImportColumns = map[string]string{
	"角色": rejectRoleCol, "role": rejectRoleCol, "roles": rejectRoleCol,
	"管理员角色": rejectRoleCol, "adminrole": rejectRoleCol, "admin_role": rejectRoleCol,
	"是否管理员": rejectRoleCol, "isadmin": rejectRoleCol, "is_admin": rejectRoleCol,
	"权限": rejectRoleCol, "perm": rejectRoleCol, "perms": rejectRoleCol,
	"permission": rejectRoleCol, "permissions": rejectRoleCol,
	"状态": rejectStatusCol, "status": rejectStatusCol,
}

const (
	// rejectRoleCol 角色/权限类列的拒收理由——它就是本文件顶部那条纪律的对外说法。
	rejectRoleCol = "导入只能创建普通用户，请删除该列后重试；管理员账号请在「系统管理 → 管理员」页单独创建"
	// rejectStatusCol 状态列的拒收理由。导入一律建启用账号：把它建成 disabled 没有实际用途，
	// 而"照建成 active、CSV 里那个 disabled 被悄悄忽略"是会误导人的静默失效。
	rejectStatusCol = "导入一律创建启用状态的账号，请删除该列后重试；停用/锁定请在用户详情里就地处置"
)

// mapUserImportColumns 解析表头。返回 (列下标, 未识别列名, 触发拒收的列名, 拒收理由)。
func mapUserImportColumns(header []string) (userImportCols, []string, string, string) {
	cols := userImportCols{account: -1, name: -1, org: -1, orgID: -1, groups: -1, email: -1, password: -1}
	ignored := []string{}
	for i, h := range header {
		raw := strings.TrimSpace(strings.TrimPrefix(h, usersCSVBOM))
		key := normUserHeader(raw)
		if key == "" {
			continue
		}
		if why, bad := rejectedImportColumns[key]; bad {
			return cols, nil, raw, why
		}
		// ★同名语义列**先到先得**：后者覆盖的话，`账号,姓名,账号` 会让真正有值的第 1 列
		// 被忽略，整批报「账号与姓名都不能为空」——错误信息指向的地方根本没问题。
		// devices 侧同款处理，两处口径统一。
		set := func(dst *int, i int) {
			if *dst < 0 {
				*dst = i
			}
		}
		switch userImportAliases[key] {
		case "account":
			set(&cols.account, i)
		case "name":
			set(&cols.name, i)
		case "org":
			set(&cols.org, i)
		case "orgid":
			set(&cols.orgID, i)
		case "groups":
			set(&cols.groups, i)
		case "email":
			set(&cols.email, i)
		case "password":
			set(&cols.password, i)
		default:
			ignored = append(ignored, raw)
		}
	}
	return cols, ignored, "", ""
}

// normUserHeader 表头规范化：去空白（含全角空格）、去下划线以外的分隔噪声、转小写。
func normUserHeader(h string) string {
	h = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '　', '*', '（', '）', '(', ')':
			return -1
		}
		return r
	}, h)
	return strings.ToLower(h)
}

// resolveImportOrg 解析组织归属：先认 id（稳定键），再认名字。
//
// ★同名部门可以存在于组织树的不同分支（"研发部"在两个大区下各有一个），
// 所以按名字命中多条时**拒绝这一行**而不是随便挑一个——挑错的后果是这个人
// 从此按错误的组织被授权，而页面上一切正常。
func resolveImportOrg(orgs []store.Org, idCell, nameCell string) (string, string) {
	id := strings.TrimSpace(idCell)
	if id != "" {
		for _, o := range orgs {
			if o.ID == id {
				return o.ID, ""
			}
		}
		return "", "组织ID「" + id + "」不存在"
	}
	name := strings.TrimSpace(nameCell)
	if name == "" {
		return "", "" // 不填 = 暂不归属，与新增用户表单一致
	}
	// 名字也允许直接写 id（导出文件里 组织 一列是名字，但手写模板的人常直接填 id）
	hit := ""
	n := 0
	for _, o := range orgs {
		if o.ID == name {
			return o.ID, ""
		}
		if strings.EqualFold(strings.TrimSpace(o.Name), name) {
			hit = o.ID
			n++
		}
	}
	switch n {
	case 0:
		return "", "组织「" + name + "」不存在，请先在组织架构里创建"
	case 1:
		return hit, ""
	default:
		return "", "组织名「" + name + "」在组织树里有 " + strconv.Itoa(n) + " 个同名部门，请改用「组织ID」列指明"
	}
}

// resolveImportGroups 解析用户组（分号分隔，接受半角/全角）。
//
// 只接受 static 组：role 组的成员由用户展示角色派生、external 组由认证源每次登录刷新，
// 写进去要么被 store 拒、要么被下一次登录冲掉。在这里当场说清，比让管理员
// 事后发现"导入时明明填了组"要好。
func resolveImportGroups(groups []store.UserGroup, cellVal string) ([]string, string) {
	v := strings.TrimSpace(cellVal)
	if v == "" {
		return nil, ""
	}
	out := []string{}
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == '；' || r == '|' }) {
		nm := strings.TrimSpace(part)
		if nm == "" {
			continue
		}
		var hit *store.UserGroup
		for i := range groups {
			g := &groups[i]
			if g.ID == nm || strings.EqualFold(strings.TrimSpace(g.Name), nm) {
				hit = g
				break
			}
		}
		if hit == nil {
			return nil, "用户组「" + nm + "」不存在"
		}
		if hit.Kind != store.GroupKindStatic {
			return nil, "用户组「" + hit.Name + "」是" + userGroupKindZh(hit.Kind) + "，成员不可手工指定"
		}
		out = append(out, hit.ID)
	}
	return out, ""
}

// userGroupKindZh 用户组来源的中文名（错误文案用，说清"为什么这个组填不了"）。
func userGroupKindZh(kind string) string {
	switch kind {
	case store.GroupKindRole:
		return "角色派生组（成员由用户展示角色决定）"
	case store.GroupKindExternal:
		return "外部目录组（成员由认证源在每次登录时刷新）"
	default:
		return "非显式成员组"
	}
}

// importStoreErrZh 把 store 层的建号错误翻成逐行可读的原因。
// 唯一索引撞车（并发导入 / 查重与落库之间挤进了一次建号）必须说成"账号已存在"，
// 而不是把一句 SQL 约束原文抛给管理员。
func importStoreErrZh(err error) string {
	switch {
	case errors.Is(err, store.ErrOrgNotFound):
		return "组织不存在"
	case errors.Is(err, store.ErrGroupNotFound):
		return "用户组不存在"
	case errors.Is(err, store.ErrGroupDerived):
		return "用户组成员由系统派生，不可手工指定"
	}
	if strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
		return "账号已存在"
	}
	return "创建失败：" + err.Error()
}

// userCSVErrZh csv 解析错误的可读化（保留原文，前面补一句人话）。
func userCSVErrZh(err error) string {
	var pe *csv.ParseError
	if errors.As(err, &pe) {
		if errors.Is(pe.Err, csv.ErrQuote) {
			return "引号不成对（含逗号或换行的单元格需用英文双引号包裹）"
		}
		return pe.Err.Error()
	}
	return err.Error()
}

// userCell 取第 i 列（越界/负下标回空串）：短一列的行按"该列没填"处理，
// 而不是让整份导入崩在一个少打了个逗号的行上。
func userCell(rec []string, i int) string {
	if i < 0 || i >= len(rec) {
		return ""
	}
	return rec[i]
}

// blankUserRecord 整行全空（Excel 存盘常在末尾留一行逗号）。
func blankUserRecord(rec []string) bool {
	for _, v := range rec {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}
