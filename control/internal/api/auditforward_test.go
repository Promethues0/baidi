package api

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/secret"
	"baidi.dev/control/internal/store"
)

// ── 审计外送端到端（PRD ch16 + ch21.6）──
//
// ★这些用例**不测格式化函数**：起一个真的 TCP syslog 接收端，让控制面
// 产生一条真的审计，跑一轮真的 pump，再从收到的 RFC 5424 报文里把
// seq/mac 抠出来与 `GET /api/v1/audit` 的那一条比对。
// 只测"报文长什么样"的话，「入队漏了 / pump 没跑 / 出队顺序错了」一条都发现不了。

type fwdFixture struct {
	srv *Server
	h   http.Handler
	st  *store.SQLiteStore
}

func newFwdFixture(t *testing.T) *fwdFixture {
	t.Helper()
	// 必须在第一次触碰 secret.Default() 之前指走主密钥路径，否则会在包目录下生成密钥文件。
	t.Setenv(secret.DefaultKeyPathEnv, filepath.Join(t.TempDir(), "psk.key"))
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "fwd.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	return &fwdFixture{srv: s, h: auth.Middleware(testKeys, s.IsOpen)(s.Routes()), st: st}
}

// ── 进程内 syslog 接收端（octet-counting 解帧）──

type syslogSink struct {
	addr  string
	mu    sync.Mutex
	msgs  []string
	ln    net.Listener
	close sync.Once
	done  chan struct{}
}

// startSyslogSink 在 addr 上起接收端；addr 为空时随机取端口。
func startSyslogSink(t *testing.T, addr string) *syslogSink {
	t.Helper()
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("接收端监听 %s 失败: %v", addr, err)
	}
	s := &syslogSink{addr: ln.Addr().String(), ln: ln, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(s.Close)
	return s
}

func (s *syslogSink) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		lenStr, err := br.ReadString(' ')
		if err != nil {
			return
		}
		n, cerr := strconv.Atoi(strings.TrimSpace(lenStr))
		if cerr != nil || n <= 0 {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		s.mu.Lock()
		s.msgs = append(s.msgs, string(buf))
		s.mu.Unlock()
	}
}

func (s *syslogSink) Close() {
	s.close.Do(func() {
		s.ln.Close()
		<-s.done
	})
}

func (s *syslogSink) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.msgs...)
}

// waitMessages 等到收到至少 n 条报文（接收端在别的 goroutine 里落盘）。
func (s *syslogSink) waitMessages(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.messages(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待 %d 条外送报文超时，实得 %d 条", n, len(s.messages()))
	return nil
}

// reserveAddr 占一个端口再立刻释放：用来构造一个"暂时连不上、稍后能起来"的对端。
func reserveAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("占端口失败: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// createSyslogTarget 建一个指向 addr 的 syslog 出口，返回 id。
func createSyslogTarget(t *testing.T, f *fwdFixture, tok, name, addr string, enabled bool) string {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	code, out := doJSON(t, f.h, "POST", "/api/v1/audit/forward", tok, map[string]any{
		"name": name, "kind": "syslog", "enabled": enabled,
		"config": map[string]any{"host": host, "port": port, "hostname": "ctl-test", "timeoutSec": 3},
	})
	if code != http.StatusOK {
		t.Fatalf("建出口 http %d: %v", code, out)
	}
	tgt, _ := out["target"].(map[string]any)
	if tgt == nil {
		t.Fatalf("响应缺少 target: %v", out)
	}
	if w, _ := out["warning"].(string); w != "" {
		t.Fatalf("配置应当可用，实得告警：%s", w)
	}
	return tgt["id"].(string)
}

// sdValue 从 RFC 5424 报文的 SD 里抠一个参数值。
func sdValue(msg, key string) string {
	i := strings.Index(msg, key+`="`)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(key)+2:]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// 端到端：真实审计 → 入队 → pump → 真 TCP 收到 RFC 5424 报文，
// 且报文里的 seq/mac 与 GET /api/v1/audit 的那一条**逐字相同**（三个出口同源）。
func TestAuditForwardEndToEndSyslog(t *testing.T) {
	f := newFwdFixture(t)
	sink := startSyslogSink(t, "")
	tok := adminToken()

	// 建出口这个动作本身就会落一条审计（"保存审计外送出口…"），它是第一条待外送记录。
	id := createSyslogTarget(t, f, tok, "SOC syslog", sink.addr, true)
	f.srv.PumpAuditForward(context.Background())

	msgs := sink.waitMessages(t, 1)
	var hit string
	for _, m := range msgs {
		if strings.Contains(m, "保存审计外送出口") {
			hit = m
		}
	}
	if hit == "" {
		t.Fatalf("外送报文里应含刚发生的那条审计，实得 %q", msgs)
	}
	if !strings.HasPrefix(hit, "<") || !strings.Contains(hit, ">1 ") {
		t.Errorf("应为 RFC 5424 报文（PRI + VERSION 1）：%q", hit)
	}
	seq, mac := sdValue(hit, "seq"), sdValue(hit, "mac")
	if seq == "" || mac == "" {
		t.Fatalf("外送必须带链 seq/mac（SIEM 侧独立验真的唯一依据）：%q", hit)
	}

	// 与 /audit 列表同源：同一条审计在两个出口的 seq/mac 必须一致。
	code, out := doJSON(t, f.h, "GET", "/api/v1/audit", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("读审计 http %d", code)
	}
	var listSeq, listMAC string
	for _, raw := range out["logs"].([]any) {
		l := raw.(map[string]any)
		if strings.Contains(l["event"].(string), "保存审计外送出口") {
			listSeq = strconv.FormatInt(int64(l["seq"].(float64)), 10)
			listMAC, _ = l["mac"].(string)
			break
		}
	}
	if listSeq != seq || listMAC != mac {
		t.Fatalf("同一条审计在列表与外送两个出口口径不一致：列表 seq=%s mac=%s，外送 seq=%s mac=%s",
			listSeq, listMAC, seq, mac)
	}

	// 队列应已排空，上次成功时间被真实写入。
	code, out = doJSON(t, f.h, "GET", "/api/v1/audit/forward", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("读出口清单 http %d", code)
	}
	tgt := out["targets"].([]any)[0].(map[string]any)
	if tgt["id"] != id {
		t.Fatalf("出口 id 不对: %v", tgt)
	}
	if int(tgt["queued"].(float64)) != 0 {
		t.Errorf("投递成功后队列应排空，实得 %v", tgt["queued"])
	}
	if tgt["lastStatus"] != "ok" || tgt["lastOkAt"] == nil {
		t.Errorf("应记下真实的上次成功时间：%v", tgt)
	}
	if out["queueMax"] == nil {
		t.Error("清单应下发队列上界，否则页面上的积压数看不出离丢弃还有多远")
	}
}

// 发送失败 → 整批留队 + 计次 + 记失败；对端恢复后原样送达，一条不丢。
func TestAuditForwardRetriesWithoutLoss(t *testing.T) {
	f := newFwdFixture(t)
	tok := adminToken()
	addr := reserveAddr(t) // 此刻没人监听
	id := createSyslogTarget(t, f, tok, "SOC syslog", addr, true)

	// 第一轮：对端不可达。审计已落库，队列必须留着，绝不丢弃。
	f.srv.PumpAuditForward(context.Background())
	code, out := doJSON(t, f.h, "GET", "/api/v1/audit/forward", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("读清单 http %d", code)
	}
	tgt := out["targets"].([]any)[0].(map[string]any)
	if int(tgt["queued"].(float64)) < 1 {
		t.Fatalf("发送失败时记录必须留在队列里，实得积压 %v", tgt["queued"])
	}
	if tgt["lastStatus"] != "fail" || tgt["lastDetail"] == "" {
		t.Errorf("失败必须如实记录（含原因），实得 %v", tgt)
	}
	if tgt["dropped"].(float64) != 0 {
		t.Errorf("发送失败不等于丢弃，dropped 应为 0，实得 %v", tgt["dropped"])
	}

	// 退避未到期时再 pump 一次：不该重试（也就不该产生新的失败记录）。
	f.srv.PumpAuditForward(context.Background())

	// 对端恢复。走「立即投递」清零退避——这正是管理员修好 SIEM 之后会点的那个按钮，
	// 用例不必真睡 5 秒，走的也是生产同一条路径。
	sink := startSyslogSink(t, addr)
	code, out = doJSON(t, f.h, "POST", "/api/v1/audit/forward/"+id+"/flush", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("立即投递 http %d: %v", code, out)
	}
	if int(out["reset"].(float64)) < 1 {
		t.Errorf("应清零至少一条退避，实得 %v", out["reset"])
	}
	msgs := sink.waitMessages(t, 1)
	if !strings.Contains(strings.Join(msgs, "\n"), "保存审计外送出口") {
		t.Fatalf("对端恢复后应把留队记录原样送达，实得 %q", msgs)
	}

	// 「立即投递」这个动作本身也落了一条审计（并因此入队）；再跑一轮把它送掉，
	// 队列才真正见底——这一步顺带证明了新审计仍在持续入队。
	f.srv.PumpAuditForward(context.Background())
	sink.waitMessages(t, 2)
	code, out = doJSON(t, f.h, "GET", "/api/v1/audit/forward", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("读清单 http %d", code)
	}
	tgt = out["targets"].([]any)[0].(map[string]any)
	if int(tgt["queued"].(float64)) != 0 {
		t.Errorf("送达后应出队，实得积压 %v", tgt["queued"])
	}
	if tgt["lastStatus"] != "ok" {
		t.Errorf("恢复后应记成功，实得 %v", tgt["lastStatus"])
	}
}

// 停用的出口：不入队、也不投递。
func TestAuditForwardDisabledStopsEnqueue(t *testing.T) {
	f := newFwdFixture(t)
	sink := startSyslogSink(t, "")
	tok := adminToken()
	id := createSyslogTarget(t, f, tok, "SOC syslog", sink.addr, false)

	// 触发几条审计。
	for i := 0; i < 3; i++ {
		if code, _ := doJSON(t, f.h, "GET", "/api/v1/audit/export", tok, nil); code != http.StatusOK {
			t.Fatalf("导出 http %d", code)
		}
	}
	f.srv.PumpAuditForward(context.Background())
	if got := sink.messages(); len(got) != 0 {
		t.Fatalf("停用的出口不该收到任何东西，实得 %q", got)
	}
	code, out := doJSON(t, f.h, "GET", "/api/v1/audit/forward", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("读清单 http %d", code)
	}
	tgt := out["targets"].([]any)[0].(map[string]any)
	if tgt["id"] != id || int(tgt["queued"].(float64)) != 0 {
		t.Fatalf("停用期间不该入队，实得 %v", tgt)
	}
}

// 测试按钮真发一条：失败/成功都是真实结果，且测试记录不冒充链上记录（seq=0）。
func TestAuditForwardTestButtonIsReal(t *testing.T) {
	f := newFwdFixture(t)
	tok := adminToken()
	dead := reserveAddr(t)
	id := createSyslogTarget(t, f, tok, "SOC syslog", dead, true)

	code, out := doJSON(t, f.h, "POST", "/api/v1/audit/forward/"+id+"/test", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("测试 http %d", code)
	}
	if out["ok"] != false {
		t.Fatalf("对端不可达时测试必须如实失败（假成功会让人再也不怀疑外送）：%v", out)
	}

	// 换成活着的对端。
	sink := startSyslogSink(t, "")
	host, portStr, _ := net.SplitHostPort(sink.addr)
	port, _ := strconv.Atoi(portStr)
	if code, out := doJSON(t, f.h, "POST", "/api/v1/audit/forward", tok, map[string]any{
		"id": id, "name": "SOC syslog", "kind": "syslog", "enabled": true,
		"config": map[string]any{"host": host, "port": port, "hostname": "ctl-test", "timeoutSec": 3},
	}); code != http.StatusOK {
		t.Fatalf("改配置 http %d: %v", code, out)
	}
	code, out = doJSON(t, f.h, "POST", "/api/v1/audit/forward/"+id+"/test", tok, nil)
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("对端可达时测试应成功：%d %v", code, out)
	}
	msgs := sink.waitMessages(t, 1)
	if !strings.Contains(msgs[0], "连通性测试") {
		t.Errorf("测试记录应明写它是测试：%q", msgs[0])
	}
	if got := sdValue(msgs[0], "seq"); got != "0" {
		t.Errorf("测试记录不在防篡改链上，seq 应为 0（否则 SIEM 会把它当断链），实得 %q", got)
	}
}

// syslog 出口没有凭据可设：收下一个永远不会被用到的 token 就是又一个假开关。
func TestAuditForwardSyslogRejectsSecret(t *testing.T) {
	f := newFwdFixture(t)
	tok := adminToken()
	id := createSyslogTarget(t, f, tok, "SOC syslog", reserveAddr(t), false)
	if code, _ := doJSON(t, f.h, "PUT", "/api/v1/audit/forward/"+id+"/secret", tok,
		map[string]any{"secret": "Bearer x"}); code != http.StatusBadRequest {
		t.Fatalf("syslog 出口设凭据应 400，实得 %d", code)
	}
}

// 未实现的类型保存时即拒（不许存下来再在真出审计时静默失败）。
func TestAuditForwardRejectsUnsupportedKind(t *testing.T) {
	f := newFwdFixture(t)
	if code, _ := doJSON(t, f.h, "POST", "/api/v1/audit/forward", adminToken(), map[string]any{
		"name": "kafka", "kind": "kafka", "enabled": true,
	}); code != http.StatusBadRequest {
		t.Fatalf("未实现的类型应 400，实得 %d", code)
	}
}

// 权限：外送归 PermSystem。普通用户与只持 audit 权的管理员都碰不到（读写都是）。
func TestAuditForwardRequiresSystemPerm(t *testing.T) {
	f := newFwdFixture(t)
	// 造一个只有 audit 权的管理员（审计管理员读得到日志，但改不了外送去向）。
	if code, out := doJSON(t, f.h, "POST", "/api/v1/admins", adminToken(), map[string]any{
		"account": "aud.wang", "name": "审计管理员王", "roleKey": "audit",
	}); code != http.StatusCreated {
		t.Fatalf("建审计管理员 http %d: %v", code, out)
	}
	for _, tok := range []string{userToken("li.fang"), adminTokenFor("aud.wang")} {
		if code, _ := doJSON(t, f.h, "GET", "/api/v1/audit/forward", tok, nil); code != http.StatusForbidden {
			t.Errorf("无 system 权读外送清单应 403，实得 %d", code)
		}
		if code, _ := doJSON(t, f.h, "POST", "/api/v1/audit/forward", tok, map[string]any{
			"name": "x", "kind": "syslog",
		}); code != http.StatusForbidden {
			t.Errorf("无 system 权建出口应 403，实得 %d", code)
		}
	}
}

// CSV 导出与外送同源：末尾两列就是链的 seq/mac，导出的那份也能被独立验真。
func TestAuditExportCarriesChainColumns(t *testing.T) {
	f := newFwdFixture(t)
	req := httptest.NewRequest("GET", "/api/v1/audit/export", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken())
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("导出 http %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "时间,类别,行为人,源IP,事件,判定,链序号,链MAC") {
		t.Fatalf("CSV 表头应在末尾追加链序号/链MAC：%q", firstLine(body))
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 2 {
		t.Fatal("应至少有一行数据（种子审计）")
	}
	cols := strings.Split(strings.TrimSpace(lines[1]), ",")
	if len(cols) < 8 {
		t.Fatalf("数据行应有 8 列，实得 %d：%q", len(cols), lines[1])
	}
	if n, err := strconv.Atoi(cols[6]); err != nil || n <= 0 {
		t.Errorf("链序号列应为正整数，实得 %q", cols[6])
	}
	if len(strings.TrimSpace(cols[7])) != 64 {
		t.Errorf("链MAC 列应为 HMAC-SM3 的 64 位十六进制，实得 %q", cols[7])
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
