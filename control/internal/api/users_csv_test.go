package api

// 用户批量导入导出（wave7 行动 14 · users 域）的回归。
//
// 钉住四条：
//   ① 导出绝不含口令哈希（DirUser.PassHash 的 `json:"-"` 在 CSV 里没有对应物，
//      只能靠这条用例守）；
//   ② 导出的每个单元格都中和了 CSV 公式注入（姓名/账号是可控文本）；
//   ③ 导入不是建管理员的后门（含角色列整份拒收 + 建出来的账号恒为普通用户）；
//   ④ 上限（行数/字节）真的拦得住，且逐行失败原因回得清楚。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// newUsersCSVServer 起一台带导入导出路由的测试服务。
//
// ★路由由 api.go 统一注册（并行改动中，本轮不由本文件落地）。这里外挂一层 mux
// 把两个 pattern 挂上、其余落回真实路由表：ServeMux 的最具体者优先，因此
// api.go 之后真的注册了同名路由，这里也不会重复注册同一 pattern 而 panic。
func newUsersCSVServer(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/users/export", s.handleUsersExport)
	mux.HandleFunc("POST /api/v1/users/import", s.handleUsersImport)
	mux.Handle("/", s.Routes())
	return auth.Middleware(testKeys, s.IsOpen)(mux)
}

// exportUsers 发一次导出请求，返回 (响应, CSV 正文)。
func exportUsers(t *testing.T, h http.Handler, token string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/users/export", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Body)
	return rec, string(b)
}

// importUsers 发一次导入请求（请求体即 CSV 原文）。
func importUsers(t *testing.T, h http.Handler, token, csvBody string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/users/import", strings.NewReader(csvBody))
	req.Header.Set("Content-Type", "text/csv")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// ── 导出 ──────────────────────────────────────────────────────────────

func TestUsersExportCSV(t *testing.T) {
	h := newUsersCSVServer(t)
	rec, body := exportUsers(t, h, adminToken())
	if rec.Code != http.StatusOK {
		t.Fatalf("导出应 200, got %d: %s", rec.Code, body)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "baidi-users-") || !strings.Contains(cd, ".csv") {
		t.Fatalf("应带日期文件名附件头: %q", cd)
	}
	if !strings.HasPrefix(body, "\xEF\xBB\xBF") {
		t.Fatal("应带 UTF-8 BOM（否则 Excel 打开中文乱码）")
	}
	if !strings.Contains(body, "账号,姓名,组织,组织ID,用户组,状态,角色,管理员角色,邮箱,最后登录,创建时间") {
		t.Fatalf("表头不符: %q", body[:min(120, len(body))])
	}
	// 种子账号在册，且组织名跟着组织表走（不是 users.org 那个展示遗物）
	if !strings.Contains(body, "zhang.wei") || !strings.Contains(body, "研发部") {
		t.Fatalf("应含种子用户与其组织: %s", body)
	}
	// 角色列是中文，管理员看得出谁是管理员
	if !strings.Contains(body, "管理员") || !strings.Contains(body, "普通用户") {
		t.Fatalf("角色列应中文可读: %s", body)
	}

	// ★口令哈希绝不出现。bcrypt 哈希恒以 $2a$/$2b$ 开头，种子账号全都有哈希，
	// 一旦有人给导出加了 pass_hash 列，这条会立刻红。
	for _, needle := range []string{"$2a$", "$2b$", "$2y$", "pass_hash", "passHash"} {
		if strings.Contains(body, needle) {
			t.Fatalf("导出泄露了口令材料 %q: %s", needle, body)
		}
	}
	// 口令强度同样不导（判定材料 + 攻击排序表，见 store.UserExportRow 注释）
	for _, needle := range []string{auth.PwWeak, auth.PwStrong, "口令强度"} {
		if strings.Contains(body, needle) {
			t.Fatalf("导出不应含口令强度 %q: %s", needle, body)
		}
	}

	// 导出留痕（措辞只说已发生的事）
	if !usersAuditContains(t, h, "导出用户台账 CSV") {
		t.Fatal("导出完成后应落一条审计")
	}
}

// 公式注入中和：姓名/账号是可控文本，以 = + - @ 开头的单元格在 Excel 里会被求值。
func TestUsersExportNeutralizesFormulaInjection(t *testing.T) {
	h := newUsersCSVServer(t)
	payload := `=cmd|'/C calc'!A1`
	code, out := doJSON(t, h, "POST", "/api/v1/users", adminToken(),
		map[string]any{"name": payload, "account": "+evil.acct", "password": "baidi@123456"})
	if code != http.StatusCreated {
		t.Fatalf("建号 http %d: %v", code, out)
	}
	_, body := exportUsers(t, h, adminToken())
	// 姓名在第二列：前面一定跟着逗号
	if !strings.Contains(body, ",'"+payload) {
		t.Fatalf("公式前缀单元格应被加 ' 中和: %s", body)
	}
	if strings.Contains(body, ","+payload) {
		t.Fatalf("导出不应含裸公式单元格: %s", body)
	}
	// 账号在第一列（行首），同样要中和
	if !strings.Contains(body, "\n'+evil.acct") {
		t.Fatalf("行首单元格也要中和: %s", body)
	}
}

// 权限：导出/导入都收在 PermSecurity，比列表页（任意管理员）更严。
func TestUsersCSVRequiresSecurityPerm(t *testing.T) {
	h := newUsersCSVServer(t)
	audTok := makeAdmin(t, h, "aud.admin", "audit")
	sysTok := makeAdmin(t, h, "sys.admin", "system")
	secTok := makeAdmin(t, h, "sec.admin", "security")

	// 审计/系统管理员读得到目录列表，却导不走整份台账
	for _, tok := range []string{audTok, sysTok} {
		if code, _ := doJSON(t, h, "GET", "/api/v1/users", tok, nil); code != http.StatusOK {
			t.Fatal("任意管理员应读得到目录列表（前提不成立则本用例无意义）")
		}
		if rec, _ := exportUsers(t, h, tok); rec.Code != http.StatusForbidden {
			t.Fatalf("非安全管理员导出应 403, got %d", rec.Code)
		}
		if code, _ := importUsers(t, h, tok, "账号,姓名\nx.y,某人\n"); code != http.StatusForbidden {
			t.Fatalf("非安全管理员导入应 403, got %d", code)
		}
	}
	// 普通用户连门都进不来
	if rec, _ := exportUsers(t, h, userToken("li.fang")); rec.Code != http.StatusForbidden {
		t.Fatalf("普通用户导出应 403, got %d", rec.Code)
	}
	// 安全管理员两条都能走
	if rec, _ := exportUsers(t, h, secTok); rec.Code != http.StatusOK {
		t.Fatalf("安全管理员导出应 200, got %d", rec.Code)
	}
	if code, out := importUsers(t, h, secTok, "账号,姓名\nnew.one,新人\n"); code != http.StatusOK {
		t.Fatalf("安全管理员导入应 200, got %d: %v", code, out)
	}
}

// ── 导入 ──────────────────────────────────────────────────────────────

// 逐行回报：成功的成功、失败的各自给出原因，部分失败不整批回滚。
func TestUsersImportPerRowResults(t *testing.T) {
	h := newUsersCSVServer(t)
	// 一个显式成员组，供"用户组"列命中
	if code, out := doJSON(t, h, "POST", "/api/v1/groups", adminToken(),
		map[string]any{"name": "高敏访问组", "kind": "static"}); code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("建用户组 http %d: %v", code, out)
	}

	csvBody := "账号,姓名,组织,用户组,邮箱,初始口令,手机号\n" +
		"qian.qi,钱七,研发部,高敏访问组,qian@example.com,baidi@123456,13800000000\n" + // 2 成功
		"sun.ba,孙八,dev,,,\n" + // 3 成功（组织写 id、口令留空走默认）
		"QIAN.QI,钱七大写,研发部,,,\n" + // 4 文件内重复（规范化后同一账号）
		"zhang.wei,张伟,研发部,,,\n" + // 5 库里已存在
		"zhou.jiu,周九,不存在的部门,,,\n" + // 6 组织不存在
		"wu.shi,吴十,研发部,不存在的组,,\n" + // 7 用户组不存在
		",无账号,研发部,,,\n" + // 8 账号为空
		"duan.pw,短口令,研发部,,,123\n" // 9 口令不足 6 位

	code, out := importUsers(t, h, adminToken(), csvBody)
	if code != http.StatusOK {
		t.Fatalf("导入应 200（部分失败不算整体失败）, got %d: %v", code, out)
	}
	created := out["created"].([]any)
	failed := out["failed"].([]any)
	if len(created) != 2 || len(failed) != 6 {
		t.Fatalf("应 2 成功 6 失败，实得 created=%v failed=%v", created, failed)
	}
	// 未识别列要说出来，别让人以为"手机号"存进去了
	ign, _ := out["ignoredColumns"].([]any)
	if len(ign) != 1 || ign[0] != "手机号" {
		t.Fatalf("未识别列应回报: %v", out["ignoredColumns"])
	}
	// 逐行原因对得上行号（行号是文件物理行号，含表头）
	wantReason := map[float64]string{
		4: "文件内账号重复", 5: "账号已存在", 6: "组织", 7: "用户组", 8: "不能为空", 9: "至少 6 位",
	}
	for _, raw := range failed {
		m := raw.(map[string]any)
		row := m["row"].(float64)
		want, ok := wantReason[row]
		if !ok {
			t.Fatalf("第 %v 行不该失败: %v", row, m)
		}
		if !strings.Contains(m["reason"].(string), want) {
			t.Fatalf("第 %v 行原因应含 %q，实得 %q", row, want, m["reason"])
		}
		delete(wantReason, row)
	}
	if len(wantReason) != 0 {
		t.Fatalf("这些行本该失败却没有: %v", wantReason)
	}

	// 落库核对：组织归属对齐到组织表，用户组真的挂上了
	_, dir := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	byAcct := map[string]map[string]any{}
	for _, raw := range dir["users"].([]any) {
		m := raw.(map[string]any)
		byAcct[m["account"].(string)] = m
	}
	qian := byAcct["qian.qi"]
	if qian == nil || qian["org"] != "研发部" || qian["orgId"] != "dev" {
		t.Fatalf("组织归属应落到 dev/研发部: %v", qian)
	}
	if gs, _ := qian["groups"].([]any); len(gs) != 1 {
		t.Fatalf("用户组应挂上一个: %v", qian["groups"])
	}
	if byAcct["sun.ba"] == nil || byAcct["sun.ba"]["orgId"] != "dev" {
		t.Fatalf("组织列写 id 也应认: %v", byAcct["sun.ba"])
	}
	// 失败的那些一个都没建
	for _, acct := range []string{"zhou.jiu", "wu.shi", "duan.pw", "qian.qi大写"} {
		if byAcct[acct] != nil {
			t.Fatalf("失败行不该落库: %s", acct)
		}
	}

	// ★导入的初始口令是管理员定的（还会随 CSV 在聊天窗口里流传）：首登必须强制改密。
	_, lo := doJSON(t, h, "POST", "/api/v1/portal/login", "",
		map[string]string{"username": "qian.qi", "password": "baidi@123456"})
	if lo["mustChangePassword"] != true {
		t.Fatalf("导入账号首登应强制改密，实得 %v", lo)
	}
	// 留空口令的那个走默认口令，同样能登进来（不是一个建了却登不进的死账号）
	_, lo2 := doJSON(t, h, "POST", "/api/v1/portal/login", "",
		map[string]string{"username": "sun.ba", "password": seedInitialPassword})
	if lo2["ok"] != true {
		t.Fatalf("留空口令应回落默认口令，实得 %v", lo2)
	}
}

// ★安全红线：导入绝不能成为 POST /api/v1/admins 的后门。
func TestUsersImportNeverCreatesAdmin(t *testing.T) {
	for _, col := range []string{"角色", "role", "admin_role", "管理员角色", "是否管理员"} {
		t.Run(col, func(t *testing.T) {
			h := newUsersCSVServer(t)
			body := "账号,姓名," + col + "\nevil.admin,坏人,admin\n"
			code, out := importUsers(t, h, adminToken(), body)
			if code != http.StatusBadRequest {
				t.Fatalf("含角色列应整份拒收 400, got %d: %v", code, out)
			}
			msg := out["error"].(map[string]any)["message"].(string)
			if !strings.Contains(msg, col) || !strings.Contains(msg, "普通用户") {
				t.Fatalf("拒收理由应点名该列并说清只能建普通用户: %q", msg)
			}
			// 一行都不许落库
			_, dir := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
			for _, raw := range dir["users"].([]any) {
				if raw.(map[string]any)["account"] == "evil.admin" {
					t.Fatal("拒收的文件不该建出任何账号")
				}
			}
			// 拒收要留痕（这是一次批量提权尝试，不该只回一个 400 就完）
			if !usersAuditContains(t, h, "拒绝用户批量导入") {
				t.Fatal("拒收应落一条 security 审计")
			}
		})
	}

	// 纵深第二道：即便列名躲过识别（落进"未识别列"），建出来的也只能是普通用户。
	h := newUsersCSVServer(t)
	code, out := importUsers(t, h, adminToken(),
		"账号,姓名,rôle,管理员\nsneaky.one,绕道者,admin,是\n")
	if code != http.StatusOK {
		t.Fatalf("未识别列应被忽略而非拒收, got %d: %v", code, out)
	}
	_, dir := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	for _, raw := range dir["users"].([]any) {
		m := raw.(map[string]any)
		if m["account"] != "sneaky.one" {
			continue
		}
		if m["role"] == "admin" {
			t.Fatalf("导入建出来的账号恒为普通用户，实得 %v", m)
		}
	}
	// 该账号也确实没有管理员权限（用它的令牌调管理端点应 403）
	if code, _ := doJSON(t, h, "GET", "/api/v1/users", adminTokenFor("sneaky.one"), nil); code != http.StatusForbidden {
		t.Fatalf("导入账号即使自签 admin 令牌也应被现算角色拒掉, got %d", code)
	}
}

// 上限：行数与字节各一道，超限明确报错且一个账号都不建。
func TestUsersImportLimits(t *testing.T) {
	h := newUsersCSVServer(t)

	// ① 行数上限：501 行
	var b strings.Builder
	b.WriteString("账号,姓名\n")
	for i := 0; i < userImportMaxRows+1; i++ {
		b.WriteString("bulk.")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(",批量\n")
	}
	code, out := importUsers(t, h, adminToken(), b.String())
	if code != http.StatusBadRequest {
		t.Fatalf("超行数上限应 400, got %d: %v", code, out)
	}
	if msg := out["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "上限") {
		t.Fatalf("应说清是行数上限: %q", msg)
	}

	// ② 字节上限：撑到 1 MiB 以上（单元格填充，行数不必超）
	var big strings.Builder
	big.WriteString("账号,姓名\n")
	pad := strings.Repeat("填", 4096) // 每行约 12 KiB
	for i := 0; i < 120; i++ {
		big.WriteString("fat.")
		big.WriteString(strconv.Itoa(i))
		big.WriteString(",")
		big.WriteString(pad)
		big.WriteString("\n")
	}
	if big.Len() <= userImportMaxBytes {
		t.Fatalf("用例构造有误：只有 %d 字节，未超上限", big.Len())
	}
	code, out = importUsers(t, h, adminToken(), big.String())
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超字节上限应 413, got %d: %v", code, out)
	}

	// 两次超限都不该留下任何账号
	_, dir := doJSON(t, h, "GET", "/api/v1/users", adminToken(), nil)
	for _, raw := range dir["users"].([]any) {
		acct := raw.(map[string]any)["account"].(string)
		if strings.HasPrefix(acct, "bulk.") || strings.HasPrefix(acct, "fat.") {
			t.Fatalf("超限的导入不该建出账号: %s", acct)
		}
	}

	// ③ 空文件 / 只有表头 / 缺必填列，各自给能指导下一步的话
	for _, tc := range []struct{ body, want string }{
		{"", "为空"},
		{"账号,姓名\n", "只有表头"},
		{"姓名,邮箱\n张三,a@b.c\n", "账号"},
	} {
		code, out := importUsers(t, h, adminToken(), tc.body)
		if code != http.StatusBadRequest {
			t.Fatalf("%q 应 400, got %d", tc.body, code)
		}
		if msg := out["error"].(map[string]any)["message"].(string); !strings.Contains(msg, tc.want) {
			t.Fatalf("%q 的报错应含 %q，实得 %q", tc.body, tc.want, msg)
		}
	}
}

// 导出的文件能被导入侧认出来（表头别名 + BOM 剥离），只是角色列要先删掉。
func TestUsersExportImportRoundTrip(t *testing.T) {
	h := newUsersCSVServer(t)
	_, body := exportUsers(t, h, adminToken())
	// 原样回传：含"角色"列 → 拒收（这正是我们要的：导出是台账，不是导入模板）
	if code, _ := importUsers(t, h, adminToken(), body); code != http.StatusBadRequest {
		t.Fatalf("导出件原样回传应因角色列被拒, got %d", code)
	}
	// 删掉角色/管理员角色/状态三列后（模板形态），带 BOM 也能解析
	tpl := "\uFEFF" + "账号,姓名,组织ID,用户组,邮箱,初始口令\nround.trip,回环,dev,,rt@example.com,\n"
	code, out := importUsers(t, h, adminToken(), tpl)
	if code != http.StatusOK {
		t.Fatalf("模板形态应 200, got %d: %v", code, out)
	}
	if len(out["created"].([]any)) != 1 {
		t.Fatalf("应建出 1 个账号: %v", out)
	}
}

// ── 小工具 ──────────────────────────────────────────────────────────

// usersAuditContains 审计里是否有含该关键词的事件。
func usersAuditContains(t *testing.T, h http.Handler, keyword string) bool {
	t.Helper()
	_, out := doJSON(t, h, "GET", "/api/v1/audit", adminToken(), nil)
	logs, _ := out["logs"].([]any)
	for _, l := range logs {
		if ev, _ := l.(map[string]any)["event"].(string); strings.Contains(ev, keyword) {
			return true
		}
	}
	return false
}

// 畸形引号的**数据行**必须回 400 + 可读原因，而不是 panic 成 500。
//
// 回归背景：此前 FieldPos(0) 被放在判 err 之前，而解析失败那一轮它必然越界 panic
// （encoding/csv 的契约）。触发门槛只是「Excel 存出来的文件里有个落单引号」——
// 导入功能最常见的一类输入。更讽刺的是：写得最好的那句中文错误文案，
// 反倒只在表头畸形时才可达，数据行畸形一律 internal error。
func TestUsersImportMalformedQuotesNoPanic(t *testing.T) {
	h := newUsersCSVServer(t)
	for _, body := range []string{
		"账号,姓名\n\"abc,x\n",     // 引号未闭合
		"账号,姓名\nab\"c,x\n",     // 字段中间冒出引号
		"账号,姓名\n\"ab\"c\",x\n", // 引号嵌套不成对
	} {
		code, out := importUsers(t, h, adminToken(), body)
		if code != http.StatusBadRequest {
			t.Fatalf("畸形引号应回 400（不是 panic 成 500），实得 %d：%v", code, out)
		}
		msg, _ := out["error"].(map[string]any)["message"].(string)
		if !strings.Contains(msg, "解析失败") {
			t.Fatalf("错误文案应说明解析失败，实得 %q", msg)
		}
		if strings.Contains(msg, "第 0 行") {
			t.Fatalf("行号未从 ParseError 取到：%q", msg)
		}
	}
}
