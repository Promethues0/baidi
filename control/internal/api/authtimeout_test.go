package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"baidi.dev/control/internal/authsrc"
	"baidi.dev/control/internal/store"
)

// slowPwAuth 一个睡到 ctx 超时才回的外部认证源（模拟装死/极慢的目录）。
type slowPwAuth struct{ nap time.Duration }

func (f slowPwAuth) Authenticate(ctx context.Context, _, _ string) (authsrc.Identity, error) {
	select {
	case <-time.After(f.nap):
		return authsrc.Identity{}, nil
	case <-ctx.Done():
		// 与 ldapsrc 同口径：超时归「认证源不可用」，不是「口令错误」。
		return authsrc.Identity{}, authsrc.ErrSourceUnavailable
	}
}
func (f slowPwAuth) Probe(context.Context) error { return nil }

func authAudits(t *testing.T, s *Server) []store.AuditEntry {
	t.Helper()
	st, ok := s.store.(*store.SQLiteStore)
	if !ok {
		t.Fatal("需要 SQLite 后端")
	}
	b, err := st.Audit(t.Context())
	if err != nil {
		t.Fatalf("读审计失败：%v", err)
	}
	var out []store.AuditEntry
	for _, e := range b.Logs {
		if e.Category == "auth" {
			out = append(out, e)
		}
	}
	return out
}

// 外部认证预算是这次改造的核心，而它与「给 handler 加 deadline」的**区别**
// 全在这条用例上：预算耗尽之后，登录 handler 剩下的动作必须照常完成。
//
// ★handler deadline 方案在这里会全线失守：deadline 一过期，后面每一个吃 ctx 的
// 动作都失败——审计写不进库（`/diag` 的 audit-write 会翻红并把运维指向磁盘可写性，
// 方向完全错）、锁定落不了库、stepUpDecision 的两次库读失败即 fail-closed 拒登录。
// 那等于把「目录慢」升级成「全员登录不了」，而用户看到的文案是「认证策略暂不可用」。
//
// 所以预算只包住 pa.Authenticate 那一次调用，其余一律用原 ctx。
func Test外部认证预算耗尽后审计仍然写得进去(t *testing.T) {
	s, h, _ := newFailServer(t)
	s.SetAuthTimeouts(150*time.Millisecond, 0, 0)

	aw, _ := s.store.(store.AuthSourceStore)
	if aw == nil {
		t.Fatal("需要 SQLite 后端")
	}
	if _, err := aw.SaveAuthSource(context.Background(), admitSrc(store.AdmitAuto, nil, nil)); err != nil {
		t.Fatalf("存认证源失败：%v", err)
	}
	// 目录睡得远超预算：认证必然在预算上被切断。
	s.testPasswordAuth = func(store.AuthSourceRec) (authsrc.PasswordAuthenticator, error) {
		return slowPwAuth{nap: 10 * time.Second}, nil
	}

	start := time.Now()
	w := httptest.NewRecorder()
	body := `{"username":"someone","password":"pw"}`
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/portal/login", strings.NewReader(body)))
	elapsed := time.Since(start)

	// ① 预算真的生效：整个请求不该被目录拖到 10s。
	if elapsed > 3*time.Second {
		t.Fatalf("登录耗时 %v，外部认证预算没有生效", elapsed)
	}

	// ② 文案是「认证源不可用」不是「密码错误」——把目录故障说成口令错，
	//    会让运维去查用户而不是查目录（既有纪律，api.go 的注释写着）。
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	msg, _ := resp["error"].(string)
	if msg == "" {
		msg, _ = resp["message"].(string)
	}
	if strings.Contains(msg, "口令错误") || strings.Contains(msg, "密码错误") {
		t.Fatalf("认证源超时被说成口令错误：%q", msg)
	}

	// ③ ★核心断言：审计照样落库了。
	auds := authAudits(t, s)
	var found bool
	for _, e := range auds {
		if strings.Contains(e.Event, "认证源不可用") {
			found = true
			if e.Verdict != "fail" {
				t.Fatalf("认证源不可用应落 fail，实得 %q", e.Verdict)
			}
		}
	}
	if !found {
		t.Fatalf("预算耗尽后审计没写进去——这正是 handler deadline 方案的失守点。实得 %d 条 auth 审计：%+v", len(auds), auds)
	}
	// ★耗时必须在审计正文里：NFR-PERF-03 的验收是「认证响应时延」，
	// 改造前这条链路零埋点——只加超时不加埋点的话，「连测量点都不存在」依然成立。
	var timed bool
	for _, e := range auds {
		if strings.Contains(e.Event, "外部认证耗时 ") && strings.HasSuffix(e.Event, "ms）") {
			timed = true
		}
	}
	if !timed {
		t.Fatalf("审计正文里没有外部认证耗时，时延在事后无从查证：%+v", auds)
	}

	// ④ 不计入爆破锁定：口令没错，用户不该被自己的目录故障锁掉。
	if _, locked := s.lockout.Check("someone", "127.0.0.1"); locked {
		t.Fatal("认证源故障被计入了爆破锁定——用户输的口令是对的")
	}
}

// 没问过外部源时不编造一个耗时（与「采不到的指标绝不补 0」同一条纪律）。
func Test本地认证不编造外部耗时(t *testing.T) {
	if got := extAuthTookZh(0); got != "外部认证未参与" {
		t.Fatalf("零耗时应如实说未参与，实得 %q", got)
	}
	if got := extAuthTookZh(-time.Second); got != "外部认证未参与" {
		t.Fatalf("负耗时同样不该编造数字，实得 %q", got)
	}
	if got := extAuthTookZh(1500 * time.Millisecond); got != "外部认证耗时 1500ms" {
		t.Fatalf("耗时文案不对：%q", got)
	}
}

// 预算 <=0 = 不设预算（逃生舱 / 测试栈），行为与改造前逐字一致。
func Test预算为零时不设deadline(t *testing.T) {
	s, _, _ := newFailServer(t)
	s.SetAuthTimeouts(0, 0, 0)
	ctx, cancel := s.authCtx(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("预算为 0 时不该给 ctx 挂 deadline")
	}
}

// 预算为正时才挂 deadline，且不超过预算。
func Test预算为正时挂上deadline(t *testing.T) {
	s, _, _ := newFailServer(t)
	s.SetAuthTimeouts(2*time.Second, 0, 0)
	ctx, cancel := s.authCtx(context.Background())
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("预算为正时应挂 deadline")
	}
	if left := time.Until(dl); left > 2*time.Second+time.Second {
		t.Fatalf("deadline 比预算宽：剩余 %v", left)
	}
}
