package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"

	_ "modernc.org/sqlite"
)

// 业务告警端到端：**真实信号** → 评估 → 落库 → 列表/过滤/处置。
//
// 每类触发源都用「制造真实条件」的方式驱动（把网关心跳调旧、真的连错口令锁账号、
// 真的篡改审计行），而不是直接往 alerts 表里塞行——否则测的只是 CRUD，
// 而本模块最容易错的地方恰恰是"条件到底有没有被读出来"。

type alertEnv struct {
	h  http.Handler
	s  *Server
	st *store.SQLiteStore
	db *sql.DB // 旁路句柄：用来制造真实条件（灌指标、造授予、篡改审计行）
}

func newAlertEnv(t *testing.T) *alertEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alerts-api.db")
	st, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(st, st, testKeys, "test", t.TempDir(), nil, nil, true)
	t.Cleanup(s.Close)
	e := &alertEnv{h: auth.Middleware(testKeys, s.IsOpen)(s.Routes()), s: s, st: st, db: db}
	// ★先跑一轮把**种子库自带的真实异常**排掉：演示种子里有两个应用没关联受控资源
	// （a4 / a6），那是真阳性，不是测试噪声——评估一次让它们进冷却期，
	// 后续用例才能干净地断言"我制造的那个条件产生了几条"。
	e.evaluate(t)
	return e
}

// evaluate 跑一轮评估（含审计链自检），返回新增条数。
func (e *alertEnv) evaluate(t *testing.T) int {
	t.Helper()
	code, out := doJSON(t, e.h, "POST", "/api/v1/alerts/evaluate", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("evaluate http %d: %v", code, out)
	}
	created, _ := out["created"].([]any)
	return len(created)
}

// list 拉告警列表（带可选查询串）。
func (e *alertEnv) list(t *testing.T, query string) []map[string]any {
	t.Helper()
	code, out := doJSON(t, e.h, "GET", "/api/v1/alerts"+query, adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("list alerts http %d: %v", code, out)
	}
	raw, _ := out["alerts"].([]any)
	list := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		m, _ := it.(map[string]any)
		list = append(list, m)
	}
	return list
}

func (e *alertEnv) counts(t *testing.T) map[string]any {
	t.Helper()
	_, out := doJSON(t, e.h, "GET", "/api/v1/alerts", adminToken(), nil)
	c, _ := out["counts"].(map[string]any)
	return c
}

// byKind 找出某 kind 的告警。
func byKind(list []map[string]any, kind string) map[string]any {
	for _, a := range list {
		if a["kind"] == kind {
			return a
		}
	}
	return nil
}

// countKind 数某 kind 的告警条数。
func countKind(list []map[string]any, kind string) int {
	n := 0
	for _, a := range list {
		if a["kind"] == kind {
			n++
		}
	}
	return n
}

// pendingOf 数某 kind 的未处理告警条数。
func (e *alertEnv) pendingKind(t *testing.T, kind string) int {
	t.Helper()
	return countKind(e.list(t, "?status=pending"), kind)
}

// 设备异常：网关心跳超时 → 产生告警；冷却期内再评估不重复。
func TestAlertGatewayOfflineAndCooldown(t *testing.T) {
	e := newAlertEnv(t)
	// 基线已排空：此刻没有网关注册过，离线规则一条都不该产生。
	if n := e.evaluate(t); n != 0 {
		t.Fatalf("无新异常信号时不应产生告警，得到 %d 条：%v", n, e.list(t, ""))
	}
	// 制造真实条件：一台注册过、但心跳已经很旧的网关。
	e.s.mu.Lock()
	e.s.gateways["gw-east"] = GatewayInfo{ID: "gw-east", LastSeen: time.Now().Unix() - 3600}
	e.s.mu.Unlock()

	if n := e.evaluate(t); n != 1 {
		t.Fatalf("网关离线应产生 1 条告警，得到 %d 条", n)
	}
	a := byKind(e.list(t, ""), store.AlertKindGatewayOffline)
	if a == nil {
		t.Fatal("列表里应有 gateway_offline 告警")
	}
	if a["category"] != store.AlertCategoryDevice || a["status"] != store.AlertPending {
		t.Fatalf("类别应为设备异常、状态未处理，得到 %v", a)
	}
	if a["objectKey"] != "gw:gw-east" {
		t.Fatalf("对象键应标出是哪台网关，得到 %v", a["objectKey"])
	}
	// 条件仍成立，但在冷却期内：不得再产生一条。
	if n := e.evaluate(t); n != 0 {
		t.Fatalf("冷却期内不应重复产生（否则每轮刷一条，告警页当场不可用），得到 %d 条", n)
	}
	if got := e.pendingKind(t, store.AlertKindGatewayOffline); got != 1 {
		t.Fatalf("未处理的网关离线告警应为 1 条，得到 %d", got)
	}
}

// 设备异常②：资源水位。数据源没数据时如实回「等待数据面上报」且不触发；
// 灌进一条超阈值采样后立刻触发——这条规则不是死规则。
func TestAlertGatewayLoadDataSourceReadiness(t *testing.T) {
	e := newAlertEnv(t)
	code, out := doJSON(t, e.h, "GET", "/api/v1/alerts/rules", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("rules http %d: %v", code, out)
	}
	srcs, _ := out["sources"].([]any)
	if len(srcs) == 0 {
		t.Fatal("规则接口应回报数据源就绪状态")
	}
	src := srcs[0].(map[string]any)
	if src["ready"] != false || src["reason"] == "" {
		t.Fatalf("无指标时应如实回「等待数据面上报」而不是装作在监控，得到 %v", src)
	}
	if e.evaluate(t) != 0 {
		t.Fatal("数据源未就绪时不应产生资源水位告警")
	}

	// IF NOT EXISTS：表由设备状态指标上报那条链路建立，本用例只依赖本规则读的五列
	// （详见 store/alerts_sqlite_test.go 同一处说明）。
	if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS gateway_metrics (
  gateway_id TEXT, ts INTEGER, cpu REAL, mem REAL, disk REAL, load REAL, rx_bps REAL, tx_bps REAL,
  PRIMARY KEY(gateway_id, ts))`); err != nil {
		t.Fatalf("ensure gateway_metrics: %v", err)
	}
	if _, err := e.db.Exec(
		`INSERT INTO gateway_metrics(gateway_id,ts,cpu,mem,disk) VALUES('gw-hot',?,97,40,30)`,
		time.Now().Unix()); err != nil {
		t.Fatalf("insert metric: %v", err)
	}
	if n := e.evaluate(t); n != 1 {
		t.Fatalf("CPU 超阈值应产生 1 条告警，得到 %d 条", n)
	}
	if a := byKind(e.list(t, ""), store.AlertKindGatewayLoad); a == nil {
		t.Fatal("列表里应有 gateway_load 告警")
	}
}

// 授权信息：JIT 授予即将到期 / 已过期未回收，各一条。
func TestAlertJitGrants(t *testing.T) {
	e := newAlertEnv(t)
	now := time.Now().Unix()
	ins := func(id string, exp int64) {
		if _, err := e.db.Exec(`INSERT INTO jit_grants(id,usr,resource_id,resource_name,request_id,reason,granted_by,granted_at,expires_at,status,revoked_at,revoke_reason)
VALUES(?,?,?,?,?,?,?,?,?,'active',0,'')`, id, "li.fang", "res-fin", "财务系统", "req-1", "对账", "admin", now-600, exp); err != nil {
			t.Fatalf("insert grant: %v", err)
		}
	}
	ins("g-soon", now+600)  // 10 分钟后到期 → 命中"即将到期"（默认提前 30 分钟）
	ins("g-rot", now-3600)  // 过期一小时仍是 active → 命中"已过期未回收"
	ins("g-far", now+86400) // 一天后到期 → 都不命中

	if n := e.evaluate(t); n != 2 {
		t.Fatalf("应产生「即将到期」「已过期未回收」各一条，得到 %d 条：%v", n, e.list(t, ""))
	}
	list := e.list(t, "")
	if countKind(list, store.AlertKindGrantExpiring) != 1 || countKind(list, store.AlertKindGrantStale) != 1 {
		t.Fatalf("两类授权告警各应一条（一天后到期的那条不该命中），得到 %v", list)
	}
	// 类别过滤：两条都归"授权信息"（种子里未关联资源的应用同属该类，一并计入）。
	authz := e.list(t, "?category="+store.AlertCategoryAuthz)
	if countKind(authz, store.AlertKindGrantExpiring) != 1 || countKind(authz, store.AlertKindGrantStale) != 1 {
		t.Fatalf("按授权信息类别过滤应含这两条，得到 %v", authz)
	}
	if got := e.list(t, "?category="+store.AlertCategoryDevice); len(got) != 0 {
		t.Fatalf("设备异常类别下不该有授权告警，得到 %d 条", len(got))
	}
	if e.evaluate(t) != 0 {
		t.Fatal("冷却期内不应重复产生")
	}
}

// 授权信息③：应用未关联受控资源（与客户端剖面 warnings 同一条信号）。
func TestAlertAppUnlinked(t *testing.T) {
	e := newAlertEnv(t)
	code, out := doJSON(t, e.h, "POST", "/api/v1/apps", adminToken(), map[string]any{
		"name": "临时门户", "mode": "web", "addr": "10.9.9.9:80", "category": "office",
	})
	if code != http.StatusCreated {
		t.Fatalf("建应用 http %d: %v", code, out)
	}
	// 基线里种子那两个未关联应用已在冷却期内，这一轮的新增只能来自刚建的这个。
	if n := e.evaluate(t); n != 1 {
		t.Fatalf("新建的未关联应用应产生 1 条告警，得到 %d 条：%v", n, e.list(t, ""))
	}
	if a := byKind(e.list(t, ""), store.AlertKindAppUnlinked); a == nil {
		t.Fatal("列表里应有 app_unlinked 告警")
	}
	if e.evaluate(t) != 0 {
		t.Fatal("冷却期内不应重复产生")
	}
}

// 安全①：账号连续登录失败被锁 → 告警。走真实登录链路，不直接塞锁定记录。
func TestAlertAccountLockout(t *testing.T) {
	e := newAlertEnv(t)
	for i := 0; i < 5; i++ {
		doJSON(t, e.h, "POST", "/api/v1/portal/login", "", map[string]string{
			"username": "li.fang", "password": "wrong-pass",
		})
	}
	n := e.evaluate(t)
	list := e.list(t, "")
	if byKind(list, store.AlertKindAccountLockout) == nil {
		t.Fatalf("账号被爆破锁定应产生告警，本轮新增 %d 条：%v", n, list)
	}
	if e.evaluate(t) != 0 {
		t.Fatal("冷却期内不应重复产生")
	}
}

// 安全②：终端 posture 判 block → 告警。
func TestAlertPostureBlock(t *testing.T) {
	e := newAlertEnv(t)
	if err := e.st.SavePostureReport(t.Context(), store.PostureReport{
		User: "ext.zhao", Device: "dev-1", Platform: "macOS", Verdict: "block",
		Reasons: []string{"磁盘未加密"}, TS: time.Now().Unix(),
	}); err != nil {
		t.Fatalf("save posture: %v", err)
	}
	if n := e.evaluate(t); n != 1 {
		t.Fatalf("终端判 block 应产生 1 条告警（种子异常已在基线轮排空），得到 %d 条：%v", n, e.list(t, ""))
	}
	a := byKind(e.list(t, ""), store.AlertKindPostureBlock)
	if a == nil || a["severity"] != store.AlertSevCritical {
		t.Fatalf("posture 阻断应为 critical 告警，得到 %v", a)
	}
	if e.evaluate(t) != 0 {
		t.Fatal("冷却期内不应重复产生")
	}
}

// 安全③：审计防篡改链自检。
//
// ★这条是本组最有价值的一条：防篡改链没人定期查，就等于没有。
// 用例真的去改一行审计记录，断言周期自检把它抓出来。
func TestAlertAuditChainBroken(t *testing.T) {
	e := newAlertEnv(t)
	if a := byKind(e.list(t, ""), store.AlertKindAuditChain); a != nil {
		t.Fatalf("链完好时不应告警，得到 %v", a)
	}
	if _, err := e.db.Exec(
		`UPDATE audit_log SET event='（被就地改写）' WHERE id=(SELECT MIN(id) FROM audit_log)`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if n := e.evaluate(t); n != 1 {
		t.Fatalf("篡改一行审计后应产生 1 条告警，得到 %d 条：%v", n, e.list(t, ""))
	}
	a := byKind(e.list(t, ""), store.AlertKindAuditChain)
	if a == nil || a["category"] != store.AlertCategorySecurity {
		t.Fatalf("应产生安全类的审计链告警，得到 %v", a)
	}
	if e.evaluate(t) != 0 {
		t.Fatal("冷却期内不应重复产生")
	}
}

// 处置状态机 + 未处理计数 + 状态过滤。
func TestAlertIgnoreHandleAndCounts(t *testing.T) {
	e := newAlertEnv(t)
	e.s.mu.Lock()
	e.s.gateways["gw-a"] = GatewayInfo{ID: "gw-a", LastSeen: time.Now().Unix() - 3600}
	e.s.gateways["gw-b"] = GatewayInfo{ID: "gw-b", LastSeen: time.Now().Unix() - 3600}
	e.s.mu.Unlock()
	if n := e.evaluate(t); n != 2 {
		t.Fatalf("两台网关离线应各成一条（去重按对象而不只按规则），得到 %d 条", n)
	}
	var gw []map[string]any
	for _, a := range e.list(t, "") {
		if a["kind"] == store.AlertKindGatewayOffline {
			gw = append(gw, a)
		}
	}
	if len(gw) != 2 {
		t.Fatalf("应有两条网关离线告警，得到 %d 条", len(gw))
	}
	idA, idB := gw[0]["id"].(string), gw[1]["id"].(string)

	code, out := doJSON(t, e.h, "POST", "/api/v1/alerts/"+idA+"/ignore", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("ignore http %d: %v", code, out)
	}
	code, out = doJSON(t, e.h, "POST", "/api/v1/alerts/"+idB+"/handle", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("handle http %d: %v", code, out)
	}
	alert, _ := out["alert"].(map[string]any)
	if alert["status"] != store.AlertHandled || alert["handledBy"] == "" {
		t.Fatalf("处置应记下处置人，得到 %v", alert)
	}
	// 二次处置回 409。
	if code, _ := doJSON(t, e.h, "POST", "/api/v1/alerts/"+idB+"/handle", adminToken(), nil); code != http.StatusConflict {
		t.Fatalf("重复处置应回 409，得到 %d", code)
	}
	if code, _ := doJSON(t, e.h, "POST", "/api/v1/alerts/al-nope/ignore", adminToken(), nil); code != http.StatusNotFound {
		t.Fatalf("处置不存在的告警应回 404，得到 %d", code)
	}
	// 计数不受列表过滤影响，且忽略/处理各记一条（基线里种子的两条仍未处理）。
	c := e.counts(t)
	if c["ignored"].(float64) != 1 || c["handled"].(float64) != 1 {
		t.Fatalf("忽略/处理计数应各为 1，得到 %v", c)
	}
	if got := e.list(t, "?status=ignored"); len(got) != 1 || got[0]["id"] != idA {
		t.Fatalf("按状态过滤失败，得到 %v", got)
	}
	if got := e.pendingKind(t, store.AlertKindGatewayOffline); got != 0 {
		t.Fatalf("两条网关告警都已处置，未处理里不该再有，得到 %d 条", got)
	}
	// 非法过滤值明确拒绝（静默忽略会让人以为筛过了）。
	if code, _ := doJSON(t, e.h, "GET", "/api/v1/alerts?status=whatever", adminToken(), nil); code != http.StatusBadRequest {
		t.Fatalf("非法 status 应回 400，得到 %d", code)
	}
}

// 权限：读=任意管理员（普通用户不行）；写=PermSecurity（审计管理员读得到、处置不了）。
func TestAlertPermissions(t *testing.T) {
	e := newAlertEnv(t)
	e.s.mu.Lock()
	e.s.gateways["gw-a"] = GatewayInfo{ID: "gw-a", LastSeen: time.Now().Unix() - 3600}
	e.s.mu.Unlock()
	e.evaluate(t)
	id := byKind(e.list(t, ""), store.AlertKindGatewayOffline)["id"].(string)

	if code, _ := doJSON(t, e.h, "GET", "/api/v1/alerts", userToken("li.fang"), nil); code != http.StatusForbidden {
		t.Fatalf("普通用户不应读到告警，得到 %d", code)
	}
	audTok := makeAdmin(t, e.h, "aud.admin", "audit")
	secTok := makeAdmin(t, e.h, "sec.admin", "security")
	if code, _ := doJSON(t, e.h, "GET", "/api/v1/alerts", audTok, nil); code != http.StatusOK {
		t.Fatalf("审计管理员应读得到告警（网关离线、链断裂对他同样是待办），得到 %d", code)
	}
	if code, _ := doJSON(t, e.h, "POST", "/api/v1/alerts/"+id+"/ignore", audTok, nil); code != http.StatusForbidden {
		t.Fatalf("审计权是只读的，处置应 403，得到 %d", code)
	}
	if code, _ := doJSON(t, e.h, "POST", "/api/v1/alerts/"+id+"/handle", secTok, nil); code != http.StatusOK {
		t.Fatalf("安全管理员应能处置告警，得到 %d", code)
	}
	if code, _ := doJSON(t, e.h, "DELETE", "/api/v1/alerts/rules/ar-gateway-offline", audTok, nil); code != http.StatusForbidden {
		t.Fatalf("审计管理员不应能删规则，得到 %d", code)
	}
}

// 规则 CRUD：阈值改了要**真的**换判据；未知阈值键与未知 kind 拒收；
// 停用的规则不再产生告警（页面上的开关必须是真开关）。
func TestAlertRuleCRUDTakesEffect(t *testing.T) {
	e := newAlertEnv(t)
	e.s.mu.Lock()
	e.s.gateways["gw-a"] = GatewayInfo{ID: "gw-a", LastSeen: time.Now().Unix() - 300} // 5 分钟前
	e.s.mu.Unlock()

	// 把超时阈值放宽到 1 小时 → 这台不再算离线。
	code, out := doJSON(t, e.h, "POST", "/api/v1/alerts/rules", adminToken(), map[string]any{
		"id": "ar-gateway-offline", "kind": store.AlertKindGatewayOffline, "name": "网关心跳超时离线",
		"enabled": true, "threshold": map[string]float64{store.ThreshOfflineSec: 3600}, "cooldownSec": 600,
	})
	if code != http.StatusOK {
		t.Fatalf("save rule http %d: %v", code, out)
	}
	if n := e.evaluate(t); n != 0 {
		t.Fatalf("阈值放宽后不应告警，得到 %d 条：%v", n, e.list(t, ""))
	}
	_ = out
	// 收紧到 60 秒 → 立刻命中。
	doJSON(t, e.h, "POST", "/api/v1/alerts/rules", adminToken(), map[string]any{
		"id": "ar-gateway-offline", "kind": store.AlertKindGatewayOffline, "name": "网关心跳超时离线",
		"enabled": true, "threshold": map[string]float64{store.ThreshOfflineSec: 60}, "cooldownSec": 600,
	})
	if n := e.evaluate(t); n != 1 {
		t.Fatalf("阈值收紧后应告警，得到 %d 条", n)
	}
	// 停用规则 → 冷却过后也不再产生。
	doJSON(t, e.h, "POST", "/api/v1/alerts/rules", adminToken(), map[string]any{
		"id": "ar-gateway-offline", "kind": store.AlertKindGatewayOffline, "name": "网关心跳超时离线",
		"enabled": false, "threshold": map[string]float64{store.ThreshOfflineSec: 60}, "cooldownSec": 60,
	})
	if n := e.evaluate(t); n != 0 {
		t.Fatalf("停用的规则不应产生告警，得到 %d 条", n)
	}
	// 未知阈值键 / 未知 kind 一律拒收（静默丢弃会让管理员以为自己调了阈值）。
	if code, _ := doJSON(t, e.h, "POST", "/api/v1/alerts/rules", adminToken(), map[string]any{
		"kind": store.AlertKindGatewayOffline, "threshold": map[string]float64{"bogus": 1},
	}); code != http.StatusBadRequest {
		t.Fatalf("未知阈值键应回 400，得到 %d", code)
	}
	if code, _ := doJSON(t, e.h, "POST", "/api/v1/alerts/rules", adminToken(), map[string]any{
		"kind": "made_up_signal",
	}); code != http.StatusBadRequest {
		t.Fatalf("未知规则种类应回 400（它背后没有任何真实信号），得到 %d", code)
	}
}

// 通知：一条消息通道都没配时，规则不许点名通道——不留"配了却永远发不出去"的形态。
func TestAlertRuleRejectsUnknownChannel(t *testing.T) {
	e := newAlertEnv(t)
	code, out := doJSON(t, e.h, "POST", "/api/v1/alerts/rules", adminToken(), map[string]any{
		"id": "ar-gateway-offline", "kind": store.AlertKindGatewayOffline,
		"enabled": true, "channels": []string{"nc-nonexistent"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("点名不存在的通道应回 400，得到 %d: %v", code, out)
	}
	// 通道未配置时，规则接口如实说明"不会外发"。
	_, out = doJSON(t, e.h, "GET", "/api/v1/alerts/rules", adminToken(), nil)
	n, _ := out["notify"].(map[string]any)
	if n["wired"] != false || n["reason"] == "" {
		t.Fatalf("无可用通道时应如实说明不会外发，得到 %v", n)
	}
}

// 条件**永久成立**的规则不得无界增长：只要那条告警还挂着未处置，冷却期过了也不再产生新行。
//
// ★grant_stale 是最典型的一条：过期的 JIT 授予在库里永远标着 active（全系统没有回收
// 动作，那正是这条规则要报的事实）。只按时间冷却的话，每条陈旧授予每 30 分钟产出
// 一行新告警 + 一次通知 + 一两条审计，48 行/天/对象、只增不减，而 alerts 表此前
// 没有任何清理。处置之后条件仍成立则如常再报——压制不是永久静默。
func TestAlertPendingSuppressesUnboundedRegrowth(t *testing.T) {
	e := newAlertEnv(t)
	now := time.Now().Unix()
	if _, err := e.db.Exec(`INSERT INTO jit_grants(id,usr,resource_id,resource_name,request_id,reason,granted_by,granted_at,expires_at,status,revoked_at,revoke_reason)
VALUES('g-rot','li.fang','res-fin','财务系统','req-1','对账','admin',?,?,'active',0,'')`,
		now-7200, now-3600); err != nil {
		t.Fatalf("insert grant: %v", err)
	}
	if n := e.evaluate(t); n != 1 {
		t.Fatalf("过期未回收的授予应产生 1 条告警，得到 %d 条", n)
	}

	// 把冷却期"走完"（直接把这条告警的触发时刻推到很久以前），再评估若干轮。
	for i := 0; i < 3; i++ {
		if _, err := e.db.Exec(`UPDATE alerts SET triggered_at=? WHERE kind=?`,
			time.Now().Add(-24*time.Hour).Unix(), store.AlertKindGrantStale); err != nil {
			t.Fatalf("推老触发时刻: %v", err)
		}
		if n := e.evaluate(t); n != 0 {
			t.Fatalf("第 %d 轮：该对象上还挂着未处置的告警，不该再产生新行（实得 %d 条）", i+1, n)
		}
	}
	if got := e.pendingKind(t, store.AlertKindGrantStale); got != 1 {
		t.Fatalf("陈旧授予应始终只有 1 条待办，实得 %d 条", got)
	}

	// 处置掉它：条件仍成立（授予还在库里标 active），冷却期已过 → 必须能再报。
	a := byKind(e.list(t, "?status=pending"), store.AlertKindGrantStale)
	if code, out := doJSON(t, e.h, "POST", "/api/v1/alerts/"+a["id"].(string)+"/handle", adminToken(), nil); code != http.StatusOK {
		t.Fatalf("处置 http %d: %v", code, out)
	}
	if _, err := e.db.Exec(`UPDATE alerts SET triggered_at=? WHERE kind=?`,
		time.Now().Add(-24*time.Hour).Unix(), store.AlertKindGrantStale); err != nil {
		t.Fatalf("推老触发时刻: %v", err)
	}
	if n := e.evaluate(t); n != 1 {
		t.Fatalf("处置完且冷却期已过、条件仍成立时必须再报一条，实得 %d 条", n)
	}
}

// 单轮通知有预算：告警**全部落库**，但同步外发不超过 alertNotifyBudget 条，
// 且差额如实落审计。
//
// ★没有预算的话，一轮产出上百条候选时（升级后首轮评估、一次性接入几十台网关），
// notifyAlert 是同步发送 × 每通道 SMTP 默认 15s 超时，POST /alerts/evaluate 这个
// handler 会挂住几十分钟。
func TestAlertNotifyBudgetPerRound(t *testing.T) {
	e := newAlertEnv(t)
	// 一条真的 webhook 通道：数它到底收到几次。
	url, got := hookServer(t, http.StatusOK)
	code, out := doJSON(t, e.h, "POST", "/api/v1/notify/channels", adminToken(), map[string]any{
		"name": "SOC webhook", "kind": "webhook", "enabled": true,
		"config": map[string]any{"url": url, "timeoutSec": 5},
	})
	if code != http.StatusOK {
		t.Fatalf("建通道 http %d: %v", code, out)
	}
	// 造 alertNotifyBudget+5 个未关联受控资源的应用（每个各成一条 app_unlinked 告警）。
	want := alertNotifyBudget + 5
	for i := 0; i < want; i++ {
		code, out := doJSON(t, e.h, "POST", "/api/v1/apps", adminToken(), map[string]any{
			"name": fmt.Sprintf("临时门户%02d", i), "mode": "web",
			"addr": fmt.Sprintf("10.9.9.%d:80", i+1), "category": "office",
		})
		if code != http.StatusCreated {
			t.Fatalf("建应用 %d http %d: %v", i, code, out)
		}
	}
	if n := e.evaluate(t); n != want {
		t.Fatalf("应产生 %d 条告警（一条都不能少落库），实得 %d 条", want, n)
	}
	if n := len(got()); n != alertNotifyBudget {
		t.Fatalf("单轮外发应止于预算 %d 条，实得 %d 条", alertNotifyBudget, n)
	}
	if !auditHasEvent(t, e.h, "超过单轮通知预算") {
		t.Fatal("超预算未逐条外发这件事必须落审计（措辞只说已发生的事实）")
	}
}
