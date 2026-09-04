package api

// 闲置自动锁定的「不可判定」边界回归。
//
// ★改造前的形态：RunIdleAutoLock 的循环只跳过 a.IsAdmin，对 a.NeverRecorded 一字不看。
// 而 NeverRecorded=true 的那一行，last_login 解析不出（外部目录建号那条 INSERT 写的是
// 占位 "—"，wave7 行动 8① 上线前的历史行也没有），IdleDays 是拿 created_at 估的
// **建号至今**。于是：一套装了一段时间的部署升级到带 last_login 写入的版本后，
// 库里既有账号的 last_login 仍是占位值（要等各人下次登录才刷新），管理员这时打开
// 「自动锁定」，一小时内的第一轮就会把「建号早于阈值、且升级后还没登录过」的人
// **整批**锁掉 + 数据面撤窗断隧道，而汇总审计写的是「闲置账号自动锁定（阈值 90 天）」,
// 读起来像这些人真的 90 天没登录。
//
// 手工路径早就照三态纪律做了（Users.vue 把这类行渲染成「无登录记录 · 建号 N 天」，
// 与「N 天未登录」分开由人判），执行方一侧此前零消费——`grep -rn NeverRecorded control/`
// 只有定义、赋值、注释和一条 store 层单测。

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// newIdleServerAtPath 同 newTestServerWithSrv，另回库文件路径——
// 「last_login 是占位符、建号在两年前」这种时间态没有生产写路径能造出来
// （建号那一刻 created_at 必然是当下），只能直连库摆好（devices_test.go 的 rawDB 同款）。
func newIdleServerAtPath(t *testing.T) (http.Handler, *Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "idle-unknown.db")
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	return auth.Middleware(testKeys, s.IsOpen)(s.Routes()), s, path
}

func TestIdleAutoLockSkipsAccountsWithoutLoginRecord(t *testing.T) {
	h, srv, path := newIdleServerAtPath(t)
	ctx := t.Context()

	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer db.Close()

	// li.fang：升级前建的号，last_login 还是建号占位符 "—"，建号在两年前。
	// 这正是"每周正常上班、只是还没在升级后登录过"的那批人在库里的形态。
	old := time.Now().AddDate(-2, 0, 0).Format("2006-01-02 15:04:05")
	if _, err := db.Exec(`UPDATE users SET last_login='—', created_at=? WHERE account='li.fang'`, old); err != nil {
		t.Fatalf("摆 li.fang 的时间态失败: %v", err)
	}
	// wang.qiang：对照组，last_login 真实可解析且确实很久没登录了。
	// ★必须有这个对照：只断言"li.fang 没被锁"的话，一个**整体停摆**的自动锁定
	//   （比如策略读错、清单读失败）也会让用例全绿。
	if _, err := db.Exec(`UPDATE users SET last_login=? WHERE account='wang.qiang'`, old); err != nil {
		t.Fatalf("摆 wang.qiang 的时间态失败: %v", err)
	}

	// 识别清单如实分开两类：li.fang 不可判定，wang.qiang 是真闲置。
	code, out := doJSON(t, h, "GET", "/api/v1/users/idle?days=90", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET 闲置清单 http %d", code)
	}
	byAcct := map[string]map[string]any{}
	for _, raw := range out["accounts"].([]any) {
		m := raw.(map[string]any)
		byAcct[m["account"].(string)] = m
	}
	if byAcct["li.fang"] == nil || byAcct["li.fang"]["neverRecorded"] != true {
		t.Fatalf("前置条件没成立：li.fang 应出现在清单里并标 neverRecorded，实得 %v", byAcct["li.fang"])
	}
	if byAcct["wang.qiang"] == nil || byAcct["wang.qiang"]["neverRecorded"] != false {
		t.Fatalf("前置条件没成立：wang.qiang 应是有登录记录的真闲置账号，实得 %v", byAcct["wang.qiang"])
	}

	if code, out := setIdlePolicy(t, h, 90, true); code != http.StatusOK {
		t.Fatalf("开启自动锁定 http %d: %v", code, out)
	}
	srv.RunIdleAutoLock(ctx)

	// ① 不可判定的那个**不许**被动：他可能昨天还在上班，只是没在升级后登录过。
	if got := statusOf(t, h, "li.fang"); got != "active" {
		t.Fatalf("没有登录记录的账号不该被自动锁定（那条闲置天数是按建号时间估的），li.fang 现在是 %q", got)
	}
	// ② 真闲置的那个必须被锁：证明这一轮确实跑起来了，①不是因为整体停摆才绿。
	if got := statusOf(t, h, "wang.qiang"); got != "locked" {
		t.Fatalf("有登录记录的真闲置账号应被锁定，wang.qiang 现在是 %q —— 说明本轮根本没动作，①的绿是假的", got)
	}

	// ③ 汇总审计必须**分开报**两类跳过：合成一个"跳过 N 个"的话，
	//    事后没法自证这一轮锁的是哪一批，也看不出"有 N 个账号因为没有登录记录而不可判定"。
	var summary string
	for _, e := range auditEvents(t, h) {
		if strings.HasPrefix(e, "闲置账号自动锁定") {
			summary = e
			break
		}
	}
	if summary == "" {
		t.Fatal("自动锁定真锁了人却没有汇总审计")
	}
	if !strings.Contains(summary, "无登录记录") {
		t.Fatalf("汇总审计必须点名跳过了几个无登录记录的账号，实得 %q", summary)
	}
}
