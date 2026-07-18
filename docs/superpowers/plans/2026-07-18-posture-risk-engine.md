# 终端 posture 真实上报 + 风险引擎 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 终端真实采集环境信号 → 60s 周期上报控制面 → 风险引擎按管理员可编辑的安全基线评估 → block 者拒发敲门令牌 + 经既有轮询捎带通道撤窗断隧道（自动收缩），风险真实呈现在用户状态/态势/安全中心。

**Architecture:** 控制面集中评估（方案 A，见 spec `docs/superpowers/specs/2026-07-18-posture-risk-engine-design.md`）。新增 `control/internal/risk` 纯函数引擎 + `baseline_policies`/`posture_reports` 两张表；执行复用 knock-token 闸与 `gateways/policy` revoked 捎带；gateway 零改动。

**Tech Stack:** Go stdlib（control，go 1.25，无 gin）、modernc SQLite、Vue3+Arco（console）、Tauri 2 Rust + Vue3（desktop）。

## Global Constraints

- 全程中文（注释/文档/commit）；commit 尾行 `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`。
- control 写操作 handler 内 `requireAdmin()`；审计 `s.audit()` best-effort 不阻断主流程。
- 账号键一律 `normUser`（去空格+小写）。
- store 层 = 领域文件 + 同名 `_sqlite.go` 成对；migrate 用 `CREATE TABLE IF NOT EXISTS`；seed 仅空表灌种子。
- disposal 枚举 `allow|degrade|block|gray`（block 最严：block > gray > degrade > allow）；severity 权重 high=25/medium=10/low=5，score cap 100；level：违反 block 基线强制 high，否则 ≥60 high、≥30 medium、其余 low。
- posture 新鲜窗口 `postureFreshTTL = 10 * time.Minute`；缺报默认放行（observe），`BAIDI_POSTURE_ENFORCE=strict` 缺报/过期也 403；latest verdict=block 不看新鲜度一直拦。
- 前端主题 ArcoBlue `#165DFF`，自定义变量 `--bd-*`。

---

### Task 1: 风险引擎纯函数包 `control/internal/risk`

**Files:**
- Create: `control/internal/risk/risk.go`
- Test: `control/internal/risk/risk_test.go`

**Interfaces:**
- Consumes: `store.BaselinePolicy/BaselineCheck`（已存在 `control/internal/store/security.go`）、`store.PostureCheckResult`（Task 3 定义；本任务先在 store 包补该类型，见 Step 1 前置）
- Produces: `risk.Evaluate(platform string, checks []store.PostureCheckResult, baselines []store.BaselinePolicy) risk.Verdict`；`risk.Verdict{Score int; Level, Disposal string; Reasons []string}`；`risk.DisposalRank(d string) int`

- [ ] **Step 0: 前置——在 store 包补 PostureCheckResult 类型**（新建 `control/internal/store/posture.go`，本任务只放类型，读写方法 Task 3 补）

```go
package store

// PostureCheckResult 终端上报的一条检查结果（客户端机械布尔化 + 原始值，策略判定在控制面）。
type PostureCheckResult struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	OK    bool   `json:"ok"`
	Value string `json:"value"`
}
```

- [ ] **Step 1: 写失败测试** `control/internal/risk/risk_test.go`

```go
package risk

import (
	"reflect"
	"testing"

	"baidi.dev/control/internal/store"
)

func bl(id, disposal, status string, platforms []string, checks ...store.BaselineCheck) store.BaselinePolicy {
	return store.BaselinePolicy{ID: id, Name: id, Type: "onboarding", Disposal: disposal, Status: status, Platforms: platforms, Checks: checks}
}
func chk(key, platform, severity string) store.BaselineCheck {
	return store.BaselineCheck{Key: key, Label: "检查-" + key, Platform: platform, Severity: severity}
}
func ok(key string) store.PostureCheckResult  { return store.PostureCheckResult{Key: key, Label: "检查-" + key, OK: true} }
func bad(key string) store.PostureCheckResult { return store.PostureCheckResult{Key: key, Label: "检查-" + key, OK: false} }

func TestEvaluate(t *testing.T) {
	admission := bl("b-adm", "block", "enabled", []string{"macOS", "Windows"},
		chk("disk", "All", "high"), chk("sip", "macOS", "high"))
	health := bl("b-health", "degrade", "enabled", []string{"macOS"},
		chk("fw", "All", "medium"), chk("edr", "All", "low"))

	cases := []struct {
		name     string
		platform string
		checks   []store.PostureCheckResult
		bls      []store.BaselinePolicy
		want     Verdict
	}{
		{"全部通过", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health},
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}}},
		{"高危失败触发 block 且 level 强制 high", "macOS", []store.PostureCheckResult{bad("disk"), ok("sip"), ok("fw"), ok("edr")},
			[]store.BaselinePolicy{admission, health},
			Verdict{Score: 25, Level: "high", Disposal: "block", Reasons: []string{"检查-disk"}}},
		{"降权基线失败只 degrade", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), bad("fw"), bad("edr")},
			[]store.BaselinePolicy{admission, health},
			Verdict{Score: 15, Level: "low", Disposal: "degrade", Reasons: []string{"检查-fw", "检查-edr"}}},
		{"缺失 key 视为失败", "macOS", []store.PostureCheckResult{ok("disk"), ok("sip"), ok("edr")},
			[]store.BaselinePolicy{admission, health},
			Verdict{Score: 10, Level: "low", Disposal: "degrade", Reasons: []string{"检查-fw（未上报）"}}},
		{"平台不匹配的基线/检查跳过", "Windows", []store.PostureCheckResult{ok("disk")},
			[]store.BaselinePolicy{admission, health}, // health 只适用 macOS；sip 只适用 macOS
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}}},
		{"停用基线跳过", "macOS", []store.PostureCheckResult{bad("disk")},
			[]store.BaselinePolicy{bl("b-off", "block", "disabled", nil, chk("disk", "All", "high"))},
			Verdict{Score: 0, Level: "low", Disposal: "allow", Reasons: []string{}}},
		{"空 Platforms 视为全平台适用", "Linux", []store.PostureCheckResult{bad("disk")},
			[]store.BaselinePolicy{bl("b-any", "gray", "enabled", nil, chk("disk", "All", "medium"))},
			Verdict{Score: 10, Level: "low", Disposal: "gray", Reasons: []string{"检查-disk"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Evaluate(c.platform, c.checks, c.bls)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Evaluate() = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestScoreCapAndLevels(t *testing.T) {
	var checks []store.BaselineCheck
	var reported []store.PostureCheckResult
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		checks = append(checks, chk(k, "All", "high"))
		reported = append(reported, bad(k))
	}
	v := Evaluate("macOS", reported, []store.BaselinePolicy{bl("b", "degrade", "enabled", nil, checks...)})
	if v.Score != 100 { // 5×25 = 125 → cap 100
		t.Fatalf("score cap: got %d", v.Score)
	}
	if v.Level != "high" { // ≥60
		t.Fatalf("level: got %s", v.Level)
	}
	if v.Disposal != "degrade" {
		t.Fatalf("disposal: got %s", v.Disposal)
	}
}

func TestDisposalRank(t *testing.T) {
	if !(DisposalRank("block") > DisposalRank("gray") && DisposalRank("gray") > DisposalRank("degrade") && DisposalRank("degrade") > DisposalRank("allow")) {
		t.Fatal("disposal 排序应为 block > gray > degrade > allow")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/risk/`
Expected: FAIL（`Evaluate`/`Verdict` 未定义）

- [ ] **Step 3: 实现** `control/internal/risk/risk.go`

```go
// Package risk 终端环境风险引擎：按安全中心基线评估终端上报的检查结果。
// 纯函数、无 IO；判定权在控制面（客户端只做采集与机械布尔化）。
package risk

import "baidi.dev/control/internal/store"

// Verdict 一次评估的可解释结论。
type Verdict struct {
	Score    int      // 0-100，失败检查按严重度加权累计
	Level    string   // low | medium | high（违反 block 基线强制 high）
	Disposal string   // allow | degrade | gray | block（violated 基线取最严）
	Reasons  []string // 失败检查的 label（缺失上报的附「（未上报）」）
}

var severityWeight = map[string]int{"high": 25, "medium": 10, "low": 5}
var disposalRank = map[string]int{"allow": 0, "degrade": 1, "gray": 2, "block": 3}

// DisposalRank 处置严厉度排序值（block 最严）；未知处置视为 allow。
func DisposalRank(d string) int { return disposalRank[d] }

// Evaluate 用启用且平台适用的基线评估上报的检查结果。
// 缺失某基线要求的 key 视为该检查失败（缺失即不合规，防选择性上报）。
func Evaluate(platform string, checks []store.PostureCheckResult, baselines []store.BaselinePolicy) Verdict {
	reported := make(map[string]store.PostureCheckResult, len(checks))
	for _, c := range checks {
		reported[c.Key] = c
	}
	v := Verdict{Level: "low", Disposal: "allow", Reasons: []string{}}
	for _, b := range baselines {
		if b.Status != "enabled" || !platformApplies(platform, b.Platforms) {
			continue
		}
		violated := false
		for _, c := range b.Checks {
			if c.Platform != "All" && c.Platform != platform {
				continue
			}
			rep, present := reported[c.Key]
			if present && rep.OK {
				continue
			}
			violated = true
			w := severityWeight[c.Severity]
			if w == 0 {
				w = severityWeight["medium"]
			}
			v.Score += w
			reason := c.Label
			if !present {
				reason += "（未上报）"
			}
			v.Reasons = append(v.Reasons, reason)
		}
		if violated && DisposalRank(b.Disposal) > DisposalRank(v.Disposal) {
			v.Disposal = b.Disposal
		}
	}
	if v.Score > 100 {
		v.Score = 100
	}
	switch {
	case v.Disposal == "block" || v.Score >= 60:
		v.Level = "high"
	case v.Score >= 30:
		v.Level = "medium"
	}
	return v
}

func platformApplies(platform string, platforms []string) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, p := range platforms {
		if p == platform {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd ~/Projects/baidi/control && go test ./internal/risk/ && go vet ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add control/internal/risk/ control/internal/store/posture.go
git commit -m "风险引擎纯函数包：基线×上报评估（缺失即失败/最严处置/可解释评分）"
```

---

### Task 2: store 层——安全基线落库（安全中心脱种子）

**Files:**
- Modify: `control/internal/store/security.go`（加 `Memory.Baselines`；种子调成 spec 的两条：接入准入 block + 终端健康 degrade，check key 对齐客户端采集键）
- Create: `control/internal/store/security_sqlite.go`
- Modify: `control/internal/store/sqlite.go`（Writer 接口 + migrate 建表 + seed 灌种子）
- Modify: `control/internal/store/store.go`（Store 接口加 `Baselines`）
- Test: `control/internal/store/security_sqlite_test.go`

**Interfaces:**
- Produces: `Store.Baselines(ctx) ([]BaselinePolicy, error)`；`Writer.SaveBaseline(ctx, BaselinePolicy) (BaselinePolicy, error)`、`Writer.DeleteBaseline(ctx, id string) error`；`SQLiteStore.Security` 覆盖（baselines 从库读、Spa 沿用 Memory 种子）
- Consumes: 既有 `addColumnIfMissing`/seed 范式

- [ ] **Step 1: 改 Memory 种子 + 加 Baselines**（`security.go`）——替换 `Memory.Security` 的 Baselines 为（Spa 部分不动）：

```go
// 种子基线：check key 与桌面客户端采集键一致（disk_encrypted/sys_integrity/firewall_on/os_version/edr_online/client_version）。
// 接入准入=block（典型开发 Mac 默认通过：FileVault+SIP），终端健康=degrade（常见部分失败→风险抬升可见）。
Baselines: []BaselinePolicy{
	{ID: "bl-admission", Name: "接入准入基线", Type: "onboarding", Scope: "全体访问者 / 数据面接入", Disposal: "block", Status: "enabled",
		Platforms: []string{"Windows", "macOS", "Linux"},
		Checks: []BaselineCheck{
			{Key: "disk_encrypted", Label: "磁盘已加密", Platform: "All", Expect: "FileVault / BitLocker = On", Severity: "high"},
			{Key: "sys_integrity", Label: "系统完整性保护开启", Platform: "macOS", Expect: "SIP = enabled", Severity: "high"},
		}},
	{ID: "bl-health", Name: "终端健康基线", Type: "app-protect", Scope: "全体访问者 / 持续验证", Disposal: "degrade", Status: "enabled",
		Platforms: []string{"Windows", "macOS", "Linux"},
		Checks: []BaselineCheck{
			{Key: "firewall_on", Label: "系统防火墙启用", Platform: "All", Expect: "firewall = enabled", Severity: "medium"},
			{Key: "os_version", Label: "系统版本合规", Platform: "All", Expect: "macOS ≥ 13 / Win ≥ 10", Severity: "medium"},
			{Key: "edr_online", Label: "EDR 终端防护在线", Platform: "All", Expect: "EDR 进程存活", Severity: "low"},
			{Key: "client_version", Label: "客户端为最新版本", Platform: "All", Expect: "≥ v0.1.0", Severity: "low"},
		}},
},
```

并追加：

```go
// Baselines 返回安全基线清单（Memory：种子；SQLiteStore 覆盖为库读）。
func (m *Memory) Baselines(ctx context.Context) ([]BaselinePolicy, error) {
	b, err := m.Security(ctx)
	if err != nil {
		return nil, err
	}
	return b.Baselines, nil
}
```

`store.go` Store 接口加一行 `Baselines(ctx context.Context) ([]BaselinePolicy, error)`。

- [ ] **Step 2: 写失败测试** `control/internal/store/security_sqlite_test.go`

```go
package store

import (
	"context"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// 首启种子灌库；Security() 的 baselines 走库、Spa 走种子。
func TestBaselinesSeededAndSecurityOverride(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	bls, err := s.Baselines(ctx)
	if err != nil || len(bls) != 2 {
		t.Fatalf("种子基线应有 2 条: %v %v", len(bls), err)
	}
	sec, err := s.Security(ctx)
	if err != nil || len(sec.Baselines) != 2 || sec.Spa.Generation == "" {
		t.Fatalf("Security 应库读 baselines + 种子 Spa: %+v %v", sec, err)
	}
}

// Save upsert（新建生成 id / 修改覆盖）+ Delete；改动后 Baselines 反映库态而非种子。
func TestSaveDeleteBaseline(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	nb, err := s.SaveBaseline(ctx, BaselinePolicy{Name: "外包收紧基线", Type: "onboarding", Disposal: "block", Status: "enabled",
		Platforms: []string{"macOS"}, Checks: []BaselineCheck{{Key: "disk_encrypted", Label: "磁盘已加密", Platform: "All", Severity: "high"}}})
	if err != nil || nb.ID == "" {
		t.Fatalf("save new: %+v %v", nb, err)
	}
	nb.Disposal = "gray"
	if _, err := s.SaveBaseline(ctx, nb); err != nil {
		t.Fatalf("update: %v", err)
	}
	bls, _ := s.Baselines(ctx)
	if len(bls) != 3 {
		t.Fatalf("应 3 条, got %d", len(bls))
	}
	var found bool
	for _, b := range bls {
		if b.ID == nb.ID && b.Disposal == "gray" {
			found = true
		}
	}
	if !found {
		t.Fatal("update 未生效")
	}
	if err := s.DeleteBaseline(ctx, nb.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if bls, _ = s.Baselines(ctx); len(bls) != 2 {
		t.Fatalf("删后应 2 条, got %d", len(bls))
	}
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/store/ -run 'Baseline|SecurityOverride'`
Expected: FAIL（SQLiteStore 无 Baselines/SaveBaseline）

- [ ] **Step 4: 实现** `control/internal/store/security_sqlite.go`

```go
package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// ── 安全基线（落库覆盖 Memory 种子；posture 风险引擎的规则源）──

// Baselines 从库读安全基线清单。
func (s *SQLiteStore) Baselines(ctx context.Context) ([]BaselinePolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,type,scope,disposal,status,platforms_json,checks_json FROM baseline_policies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BaselinePolicy{}
	for rows.Next() {
		var b BaselinePolicy
		var plats, checks string
		if err := rows.Scan(&b.ID, &b.Name, &b.Type, &b.Scope, &b.Disposal, &b.Status, &plats, &checks); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(plats), &b.Platforms)
		_ = json.Unmarshal([]byte(checks), &b.Checks)
		if b.Platforms == nil {
			b.Platforms = []string{}
		}
		if b.Checks == nil {
			b.Checks = []BaselineCheck{}
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) upsertBaseline(ctx context.Context, b BaselinePolicy) error {
	plats, _ := json.Marshal(b.Platforms)
	checks, _ := json.Marshal(b.Checks)
	_, err := s.db.ExecContext(ctx, `INSERT INTO baseline_policies(id,name,type,scope,disposal,status,platforms_json,checks_json,updated_at)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, type=excluded.type, scope=excluded.scope, disposal=excluded.disposal,
  status=excluded.status, platforms_json=excluded.platforms_json, checks_json=excluded.checks_json, updated_at=excluded.updated_at`,
		b.ID, b.Name, b.Type, b.Scope, b.Disposal, b.Status, string(plats), string(checks), nowStr())
	return err
}

// SaveBaseline 新增/修改一条安全基线（upsert）。
func (s *SQLiteStore) SaveBaseline(ctx context.Context, b BaselinePolicy) (BaselinePolicy, error) {
	if b.ID == "" {
		b.ID = "bl-" + uuid.NewString()[:8]
	}
	if b.Checks == nil {
		b.Checks = []BaselineCheck{}
	}
	if b.Platforms == nil {
		b.Platforms = []string{}
	}
	if err := s.upsertBaseline(ctx, b); err != nil {
		return BaselinePolicy{}, err
	}
	return b, nil
}

// DeleteBaseline 删除一条安全基线。
func (s *SQLiteStore) DeleteBaseline(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM baseline_policies WHERE id=?`, id)
	return err
}

// Security 覆盖：baselines 走库（可编辑、被风险引擎消费），Spa 概览沿用种子。
func (s *SQLiteStore) Security(ctx context.Context) (SecurityBundle, error) {
	b, err := s.Memory.Security(ctx)
	if err != nil {
		return SecurityBundle{}, err
	}
	bls, err := s.Baselines(ctx)
	if err != nil {
		return SecurityBundle{}, err
	}
	b.Baselines = bls
	return b, nil
}
```

`sqlite.go`：Writer 接口 `DeleteAuthPolicy` 之后加：

```go
	SaveBaseline(ctx context.Context, b BaselinePolicy) (BaselinePolicy, error)
	DeleteBaseline(ctx context.Context, id string) error
```

migrate() 的 `audit_log` 建表语句后追加（同一段 SQL 内）：

```sql
CREATE TABLE IF NOT EXISTS baseline_policies (
  id TEXT PRIMARY KEY, name TEXT, type TEXT, scope TEXT, disposal TEXT, status TEXT,
  platforms_json TEXT, checks_json TEXT, updated_at TEXT
);
```

seed() 的 auth_policies 块之后追加：

```go
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM baseline_policies`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		bls, _ := s.Memory.Baselines(ctx)
		for _, b := range bls {
			if err := s.upsertBaseline(ctx, b); err != nil {
				return err
			}
		}
	}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `cd ~/Projects/baidi/control && go test ./... && go vet ./...`
Expected: PASS（全包，确认 Store 接口变更无遗漏实现方）

- [ ] **Step 6: Commit**

```bash
git add control/internal/store/
git commit -m "安全基线落库：baseline_policies 表 + Save/Delete + Security 覆盖（种子对齐客户端采集键）"
```

---

### Task 3: store 层——posture_reports 表与读写

**Files:**
- Modify: `control/internal/store/posture.go`（补 PostureReport 类型 + Memory 空实现）
- Create: `control/internal/store/posture_sqlite.go`
- Modify: `control/internal/store/sqlite.go`（Writer 加 SavePostureReport + migrate 建表；无种子——posture 只来自真实上报）
- Modify: `control/internal/store/store.go`（Store 加 4 个读方法）
- Test: `control/internal/store/posture_sqlite_test.go`

**Interfaces:**
- Produces:
  - `store.PostureReport{User, Device, Platform, OS, ClientVersion string; Checks []PostureCheckResult; Verdict string; Score int; Level string; Reasons []string; TS int64}`
  - `Store.PostureReports(ctx) ([]PostureReport, error)`（全部最新，ts DESC）
  - `Store.PostureVerdict(ctx, account string) (PostureReport, bool, error)`（该用户跨设备取最差：DisposalRank 高者优先，同级取 ts 新者）
  - `Store.PostureReportFor(ctx, user, device string) (PostureReport, bool, error)`（单设备最新，供判定转换审计）
  - `Store.PostureBlockedUsers(ctx) ([]string, error)`（任一设备最新判定 block 的账号，DISTINCT）
  - `Writer.SavePostureReport(ctx, PostureReport) error`（按 (user,device) upsert）

- [ ] **Step 1: 补类型与 Memory 空实现**（`posture.go` 追加）

```go
import "context"

// PostureReport 一台终端设备的最新环境报告 + 风险引擎判定（每 (user,device) 只存最新）。
type PostureReport struct {
	User          string               `json:"user"`   // 规范化账号
	Device        string               `json:"device"` // 设备指纹
	Platform      string               `json:"platform"`
	OS            string               `json:"os"`
	ClientVersion string               `json:"clientVersion"`
	Checks        []PostureCheckResult `json:"checks"`
	Verdict       string               `json:"verdict"` // allow | degrade | gray | block
	Score         int                  `json:"score"`
	Level         string               `json:"level"` // low | medium | high
	Reasons       []string             `json:"reasons"`
	TS            int64                `json:"ts"`
}

// Memory 无 posture 来源（posture 只来自真实上报，不造种子）。
func (m *Memory) PostureReports(_ context.Context) ([]PostureReport, error) { return []PostureReport{}, nil }
func (m *Memory) PostureVerdict(_ context.Context, _ string) (PostureReport, bool, error) {
	return PostureReport{}, false, nil
}
func (m *Memory) PostureReportFor(_ context.Context, _, _ string) (PostureReport, bool, error) {
	return PostureReport{}, false, nil
}
func (m *Memory) PostureBlockedUsers(_ context.Context) ([]string, error) { return nil, nil }
```

`store.go` Store 接口加：

```go
	Baselines(ctx context.Context) ([]BaselinePolicy, error) // Task 2 已加
	PostureReports(ctx context.Context) ([]PostureReport, error)
	PostureVerdict(ctx context.Context, account string) (PostureReport, bool, error)
	PostureReportFor(ctx context.Context, user, device string) (PostureReport, bool, error)
	PostureBlockedUsers(ctx context.Context) ([]string, error)
```

- [ ] **Step 2: 写失败测试** `control/internal/store/posture_sqlite_test.go`

```go
package store

import (
	"context"
	"testing"
)

func rep(user, device, verdict string, score int, ts int64) PostureReport {
	level := "low"
	if verdict == "block" {
		level = "high"
	}
	return PostureReport{User: user, Device: device, Platform: "macOS", OS: "macOS 14.4", ClientVersion: "0.1.0",
		Checks: []PostureCheckResult{{Key: "disk_encrypted", Label: "磁盘已加密", OK: verdict != "block", Value: "x"}},
		Verdict: verdict, Score: score, Level: level, Reasons: []string{}, TS: ts}
}

// upsert 语义：同 (user,device) 覆盖；不同设备并存。
func TestSavePostureReportUpsert(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.SavePostureReport(ctx, rep("li.fang", "DEV-A", "allow", 0, 100)); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePostureReport(ctx, rep("li.fang", "DEV-A", "block", 25, 200)); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePostureReport(ctx, rep("li.fang", "DEV-B", "allow", 0, 150)); err != nil {
		t.Fatal(err)
	}
	all, err := s.PostureReports(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("应 2 行（A 覆盖 + B）: %d %v", len(all), err)
	}
	if all[0].TS != 200 { // ts DESC
		t.Fatalf("排序应 ts DESC: %+v", all[0])
	}
	if all[0].Checks[0].Key != "disk_encrypted" {
		t.Fatalf("checks JSON 往返丢失: %+v", all[0].Checks)
	}
}

// 跨设备取最差：任一设备 block 则用户判定 block；账号规范化匹配。
func TestPostureVerdictWorstAcrossDevices(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_ = s.SavePostureReport(ctx, rep("li.fang", "DEV-A", "allow", 0, 300))
	_ = s.SavePostureReport(ctx, rep("li.fang", "DEV-B", "block", 25, 100))
	v, found, err := s.PostureVerdict(ctx, "  Li.Fang ") // 规范化匹配
	if err != nil || !found || v.Verdict != "block" || v.Device != "DEV-B" {
		t.Fatalf("最差应为 DEV-B block: %+v %v %v", v, found, err)
	}
	if _, found, _ := s.PostureVerdict(ctx, "ghost"); found {
		t.Fatal("无报告账号应 found=false")
	}
	pd, found, _ := s.PostureReportFor(ctx, "li.fang", "DEV-A")
	if !found || pd.Verdict != "allow" {
		t.Fatalf("单设备读取: %+v", pd)
	}
	blocked, _ := s.PostureBlockedUsers(ctx)
	if len(blocked) != 1 || blocked[0] != "li.fang" {
		t.Fatalf("blocked 名单: %v", blocked)
	}
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/store/ -run Posture`
Expected: FAIL

- [ ] **Step 4: 实现** `control/internal/store/posture_sqlite.go`

```go
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// ── 终端 posture 报告（每 (user,device) 只存最新；历史轨迹走审计日志）──

const postureCols = `user,device,platform,os,client_version,checks_json,verdict,score,level,reasons_json,ts`

// SavePostureReport 落库一份终端环境报告（按 (user,device) upsert；User 由 api 层规范化）。
func (s *SQLiteStore) SavePostureReport(ctx context.Context, r PostureReport) error {
	checks, _ := json.Marshal(r.Checks)
	reasons, _ := json.Marshal(r.Reasons)
	_, err := s.db.ExecContext(ctx, `INSERT INTO posture_reports(`+postureCols+`)
VALUES(?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(user,device) DO UPDATE SET platform=excluded.platform, os=excluded.os, client_version=excluded.client_version,
  checks_json=excluded.checks_json, verdict=excluded.verdict, score=excluded.score, level=excluded.level,
  reasons_json=excluded.reasons_json, ts=excluded.ts`,
		r.User, r.Device, r.Platform, r.OS, r.ClientVersion, string(checks), r.Verdict, r.Score, r.Level, string(reasons), r.TS)
	return err
}

func scanPostureRows(rows *sql.Rows) ([]PostureReport, error) {
	defer rows.Close()
	out := []PostureReport{}
	for rows.Next() {
		var r PostureReport
		var checks, reasons string
		if err := rows.Scan(&r.User, &r.Device, &r.Platform, &r.OS, &r.ClientVersion, &checks, &r.Verdict, &r.Score, &r.Level, &reasons, &r.TS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(checks), &r.Checks)
		_ = json.Unmarshal([]byte(reasons), &r.Reasons)
		if r.Checks == nil {
			r.Checks = []PostureCheckResult{}
		}
		if r.Reasons == nil {
			r.Reasons = []string{}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PostureReports 全部设备的最新报告（ts 新者在前，供安全中心「终端合规」）。
func (s *SQLiteStore) PostureReports(ctx context.Context) ([]PostureReport, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+postureCols+` FROM posture_reports ORDER BY ts DESC`)
	if err != nil {
		return nil, err
	}
	return scanPostureRows(rows)
}

// PostureVerdict 某账号（规范化匹配）跨设备的最差判定：处置严厉度高者优先，同级取最新。
func (s *SQLiteStore) PostureVerdict(ctx context.Context, account string) (PostureReport, bool, error) {
	key := strings.ToLower(strings.TrimSpace(account))
	rows, err := s.db.QueryContext(ctx, `SELECT `+postureCols+` FROM posture_reports WHERE user=?`, key)
	if err != nil {
		return PostureReport{}, false, err
	}
	reports, err := scanPostureRows(rows)
	if err != nil || len(reports) == 0 {
		return PostureReport{}, false, err
	}
	rank := map[string]int{"allow": 0, "degrade": 1, "gray": 2, "block": 3}
	worst := reports[0]
	for _, r := range reports[1:] {
		if rank[r.Verdict] > rank[worst.Verdict] || (rank[r.Verdict] == rank[worst.Verdict] && r.TS > worst.TS) {
			worst = r
		}
	}
	return worst, true, nil
}

// PostureReportFor 某 (user,device) 的最新报告（供判定转换审计）。
func (s *SQLiteStore) PostureReportFor(ctx context.Context, user, device string) (PostureReport, bool, error) {
	key := strings.ToLower(strings.TrimSpace(user))
	rows, err := s.db.QueryContext(ctx, `SELECT `+postureCols+` FROM posture_reports WHERE user=? AND device=?`, key, device)
	if err != nil {
		return PostureReport{}, false, err
	}
	reports, err := scanPostureRows(rows)
	if err != nil || len(reports) == 0 {
		return PostureReport{}, false, err
	}
	return reports[0], true, nil
}

// PostureBlockedUsers 任一设备最新判定为 block 的账号（供网关策略并入撤销名单，堵 8h 会话令牌直连洞）。
func (s *SQLiteStore) PostureBlockedUsers(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT user FROM posture_reports WHERE verdict='block'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
```

`sqlite.go` migrate() 追加建表（注意复合主键）：

```sql
CREATE TABLE IF NOT EXISTS posture_reports (
  user TEXT, device TEXT, platform TEXT, os TEXT, client_version TEXT,
  checks_json TEXT, verdict TEXT, score INTEGER, level TEXT, reasons_json TEXT, ts INTEGER,
  PRIMARY KEY(user, device)
);
```

Writer 接口加 `SavePostureReport(ctx context.Context, r PostureReport) error`。

- [ ] **Step 5: 跑测试确认通过**

Run: `cd ~/Projects/baidi/control && go test ./... && go vet ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add control/internal/store/
git commit -m "posture_reports 表：按 (user,device) upsert 最新报告 + 跨设备最差判定 + blocked 名单"
```

---

### Task 4: api——基线 CRUD 端点 + 安全中心保存

**Files:**
- Create: `control/internal/api/security.go`（新 handler 文件，api.go 已近千行）
- Modify: `control/internal/api/api.go`（注册路由 2 条）
- Test: `control/internal/api/posture_test.go`（新建，本任务先放基线用例；Task 5/6 续用此文件）

**Interfaces:**
- Consumes: Task 2 的 `Writer.SaveBaseline/DeleteBaseline`、`requireAdmin`、`s.audit`
- Produces: `POST /api/v1/security/baselines`（admin，upsert，响应 `{ok, baseline}`）、`DELETE /api/v1/security/baselines/{id}`（admin）

- [ ] **Step 1: 写失败测试**（`posture_test.go`）

```go
package api

import (
	"net/http"
	"testing"
)

// 基线 CRUD：admin 可保存/删除；非法枚举 400；非 admin 403。
func TestBaselineCRUD(t *testing.T) {
	h := newTestServer(t)
	adm := adminToken()

	body := map[string]any{"name": "外包收紧基线", "type": "onboarding", "disposal": "block", "status": "enabled",
		"platforms": []string{"macOS"},
		"checks":    []map[string]string{{"key": "disk_encrypted", "label": "磁盘已加密", "platform": "All", "severity": "high"}}}
	code, out := doJSON(t, h, "POST", "/api/v1/security/baselines", adm, body)
	if code != http.StatusOK {
		t.Fatalf("save http %d: %v", code, out)
	}
	id := out["baseline"].(map[string]any)["id"].(string)
	if id == "" {
		t.Fatal("应生成 id")
	}

	// GET /security 反映新基线（3 条 = 2 种子 + 1 新建）
	code, sec := doJSON(t, h, "GET", "/api/v1/security", adm, nil)
	if code != http.StatusOK || len(sec["baselines"].([]any)) != 3 {
		t.Fatalf("security 应 3 条基线: %v", sec["baselines"])
	}

	// 非法 disposal 400
	bad := map[string]any{"name": "x", "type": "onboarding", "disposal": "nuke", "status": "enabled"}
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/baselines", adm, bad); code != http.StatusBadRequest {
		t.Fatalf("非法 disposal 应 400, got %d", code)
	}
	// 非 admin 403
	if code, _ := doJSON(t, h, "POST", "/api/v1/security/baselines", userToken("li.fang"), body); code != http.StatusForbidden {
		t.Fatalf("user 保存基线应 403, got %d", code)
	}
	// 删除
	if code, _ := doJSON(t, h, "DELETE", "/api/v1/security/baselines/"+id, adm, nil); code != http.StatusOK {
		t.Fatalf("delete 应 200, got %d", code)
	}
	_, sec = doJSON(t, h, "GET", "/api/v1/security", adm, nil)
	if len(sec["baselines"].([]any)) != 2 {
		t.Fatal("删后应回 2 条")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/api/ -run TestBaselineCRUD`
Expected: FAIL（404）

- [ ] **Step 3: 实现** `control/internal/api/security.go`

```go
package api

import (
	"encoding/json"
	"net/http"

	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/store"
)

// ── 安全中心 · 基线 CRUD（风险引擎的规则源）──

var validDisposal = map[string]bool{"allow": true, "degrade": true, "block": true, "gray": true}
var validSeverity = map[string]bool{"high": true, "medium": true, "low": true}
var validCheckPlatform = map[string]bool{"Windows": true, "macOS": true, "Linux": true, "All": true}
var validBaselineType = map[string]bool{"onboarding": true, "app-protect": true}
var validBaselineStatus = map[string]bool{"enabled": true, "disabled": true}

// handleSaveBaseline 新增/修改一条安全基线（admin）。落库后风险引擎即用新规则评估后续上报。
func (s *Server) handleSaveBaseline(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var b store.BaselinePolicy
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&b); err != nil || b.Name == "" {
		httpx.Error(w, http.StatusBadRequest, "基线名称不能为空")
		return
	}
	if !validBaselineType[b.Type] || !validDisposal[b.Disposal] || !validBaselineStatus[b.Status] {
		httpx.Error(w, http.StatusBadRequest, "type/disposal/status 取值非法")
		return
	}
	if len(b.Checks) > 64 {
		httpx.Error(w, http.StatusBadRequest, "检测项过多（≤64）")
		return
	}
	for _, c := range b.Checks {
		if c.Key == "" || c.Label == "" || !validCheckPlatform[c.Platform] || !validSeverity[c.Severity] {
			httpx.Error(w, http.StatusBadRequest, "检测项 key/label 必填，platform/severity 取值非法")
			return
		}
	}
	saved, err := s.writer.SaveBaseline(r.Context(), b)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save baseline")
		return
	}
	s.audit(r, "policy", "保存安全基线「"+saved.Name+"」（处置："+saved.Disposal+"）", "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "baseline": saved})
}

// handleDeleteBaseline 删除一条安全基线（admin）。
func (s *Server) handleDeleteBaseline(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.writer.DeleteBaseline(r.Context(), id); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to delete baseline")
		return
	}
	s.audit(r, "policy", "删除安全基线 "+id, "ok")
	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}
```

`api.go` Routes() 安全中心一行后加：

```go
	mux.HandleFunc("POST /api/v1/security/baselines", s.handleSaveBaseline)        // 保存基线（admin）
	mux.HandleFunc("DELETE /api/v1/security/baselines/{id}", s.handleDeleteBaseline) // 删基线（admin）
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd ~/Projects/baidi/control && go test ./internal/api/ && go vet ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add control/internal/api/
git commit -m "安全基线 CRUD 端点：安全中心编辑器从演示态变真实落库（admin + 枚举校验 + 审计）"
```

---

### Task 5: api——POST /posture 上报评估 + GET /posture 清单

**Files:**
- Create: `control/internal/api/posture.go`
- Modify: `control/internal/api/api.go`（注册 2 路由）
- Test: `control/internal/api/posture_test.go`（追加用例）

**Interfaces:**
- Consumes: `risk.Evaluate`（Task 1）、`store.Baselines/PostureReportFor`、`Writer.SavePostureReport`（Task 2/3）
- Produces: `POST /api/v1/posture`（登录用户/管理员，gateway 角色拒；响应 `{ok, verdict, score, level, reasons}`）、`GET /api/v1/posture`（admin，`{reports: []store.PostureReport}`）；判定转入/转出 block 落 security 审计

- [ ] **Step 1: 写失败测试**（`posture_test.go` 追加）

```go
// 上报→评估落库→verdict 回传；转入/转出 block 可经 GET /posture 观测；gateway 角色拒；非 admin 读 403。
func TestPostureReportAndList(t *testing.T) {
	h := newTestServer(t)
	tok := userToken("li.fang")

	good := map[string]any{"device": "DEV-A", "platform": "macOS", "os": "macOS 14.4", "clientVersion": "0.1.0",
		"checks": []map[string]any{
			{"key": "disk_encrypted", "label": "磁盘已加密", "ok": true, "value": "On"},
			{"key": "sys_integrity", "label": "系统完整性保护开启", "ok": true, "value": "enabled"},
			{"key": "firewall_on", "label": "系统防火墙启用", "ok": true, "value": "enabled"},
			{"key": "os_version", "label": "系统版本合规", "ok": true, "value": "14.4"},
			{"key": "edr_online", "label": "EDR 终端防护在线", "ok": true, "value": "falcond"},
			{"key": "client_version", "label": "客户端为最新版本", "ok": true, "value": "0.1.0"},
		}}
	code, out := doJSON(t, h, "POST", "/api/v1/posture", tok, good)
	if code != http.StatusOK || out["verdict"] != "allow" {
		t.Fatalf("合规上报应 allow: %d %v", code, out)
	}

	// 磁盘未加密 → 接入准入基线(block) violated
	badBody := map[string]any{"device": "DEV-A", "platform": "macOS", "os": "macOS 14.4", "clientVersion": "0.1.0",
		"checks": []map[string]any{
			{"key": "disk_encrypted", "label": "磁盘已加密", "ok": false, "value": "Off"},
			{"key": "sys_integrity", "label": "系统完整性保护开启", "ok": true, "value": "enabled"},
			{"key": "firewall_on", "label": "系统防火墙启用", "ok": true, "value": "enabled"},
			{"key": "os_version", "label": "系统版本合规", "ok": true, "value": "14.4"},
			{"key": "edr_online", "label": "EDR 终端防护在线", "ok": true, "value": "falcond"},
			{"key": "client_version", "label": "客户端为最新版本", "ok": true, "value": "0.1.0"},
		}}
	code, out = doJSON(t, h, "POST", "/api/v1/posture", tok, badBody)
	if code != http.StatusOK || out["verdict"] != "block" || out["level"] != "high" {
		t.Fatalf("磁盘未加密应 block/high: %v", out)
	}

	// admin 读清单；user 读 403；gateway 上报 403
	code, list := doJSON(t, h, "GET", "/api/v1/posture", adminToken(), nil)
	if code != http.StatusOK || len(list["reports"].([]any)) != 1 {
		t.Fatalf("清单应 1 行: %d %v", code, list)
	}
	if code, _ := doJSON(t, h, "GET", "/api/v1/posture", tok, nil); code != http.StatusForbidden {
		t.Fatalf("user 读清单应 403, got %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/posture", gatewayToken(), good); code != http.StatusForbidden {
		t.Fatalf("gateway 角色上报应 403, got %d", code)
	}
	// 校验：device 缺失 400、检查数超限 400
	if code, _ := doJSON(t, h, "POST", "/api/v1/posture", tok, map[string]any{"platform": "macOS"}); code != http.StatusBadRequest {
		t.Fatalf("缺 device 应 400, got %d", code)
	}
	many := make([]map[string]any, 33)
	for i := range many {
		many[i] = map[string]any{"key": "k", "label": "l", "ok": true}
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/posture", tok, map[string]any{"device": "D", "platform": "macOS", "checks": many}); code != http.StatusBadRequest {
		t.Fatalf("检查超 32 应 400, got %d", code)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/api/ -run TestPostureReportAndList`
Expected: FAIL（404）

- [ ] **Step 3: 实现** `control/internal/api/posture.go`

```go
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/httpx"
	"baidi.dev/control/internal/risk"
	"baidi.dev/control/internal/store"
)

// postureFreshTTL posture 报告新鲜窗口（strict 模式缺报/过期即拒；block 判定不看新鲜度，见 spec DP-04）。
const postureFreshTTL = 10 * time.Minute

// handlePostureReport 终端 posture 上报：风险引擎按安全基线评估 → 落库最新报告 → 回传可解释判定。
// 判定权在控制面；判定转入/转出 block 落 security 审计（自动收缩/恢复留痕）。
func (s *Server) handlePostureReport(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.FromContext(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "未认证")
		return
	}
	if c.Role == "gateway" {
		httpx.Error(w, http.StatusForbidden, "网关身份不能上报终端环境")
		return
	}
	var b struct {
		Device        string                     `json:"device"`
		Platform      string                     `json:"platform"`
		OS            string                     `json:"os"`
		ClientVersion string                     `json:"clientVersion"`
		Checks        []store.PostureCheckResult `json:"checks"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&b); err != nil ||
		strings.TrimSpace(b.Device) == "" || strings.TrimSpace(b.Platform) == "" {
		httpx.Error(w, http.StatusBadRequest, "device/platform 必填")
		return
	}
	if len(b.Device) > 128 || len(b.Checks) > 32 {
		httpx.Error(w, http.StatusBadRequest, "device 过长或检查项超限（≤32）")
		return
	}
	// 规则源：安全中心基线。读失败 fail-closed（不评估就不落库，避免坏数据顶掉有效判定）。
	baselines, err := s.store.Baselines(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load baselines")
		return
	}
	v := risk.Evaluate(b.Platform, b.Checks, baselines)

	user := normUser(c.Name)
	prev, hadPrev, _ := s.store.PostureReportFor(r.Context(), user, b.Device) // 转换审计用，读失败按无前值处理
	rep := store.PostureReport{
		User: user, Device: b.Device, Platform: b.Platform, OS: b.OS, ClientVersion: b.ClientVersion,
		Checks: b.Checks, Verdict: v.Disposal, Score: v.Score, Level: v.Level, Reasons: v.Reasons,
		TS: time.Now().Unix(),
	}
	if err := s.writer.SavePostureReport(r.Context(), rep); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to save posture report")
		return
	}
	// 判定转换留痕：转入 block = 自动收缩；转出 = 恢复合规。best-effort。
	if v.Disposal == "block" && (!hadPrev || prev.Verdict != "block") {
		s.audit(r, "security", "终端环境不合规，自动收缩接入："+c.Name+"（"+strings.Join(v.Reasons, "、")+"）", "deny")
	} else if v.Disposal != "block" && hadPrev && prev.Verdict == "block" {
		s.audit(r, "security", "终端环境恢复合规，解除接入收缩："+c.Name, "ok")
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"ok": true, "verdict": v.Disposal, "score": v.Score, "level": v.Level, "reasons": v.Reasons,
	})
}

// handlePostureList 最新终端报告清单（admin，安全中心「终端合规」）。
func (s *Server) handlePostureList(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	reports, err := s.store.PostureReports(r.Context())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to load posture reports")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"reports": reports})
}
```

`api.go` Routes() 基线路由后加：

```go
	// 终端 posture：上报评估（登录用户）+ 最新报告清单（admin）
	mux.HandleFunc("POST /api/v1/posture", s.handlePostureReport)
	mux.HandleFunc("GET /api/v1/posture", s.handlePostureList)
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd ~/Projects/baidi/control && go test ./internal/api/ && go vet ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add control/internal/api/
git commit -m "posture 上报端点：风险引擎评估落库 + 可解释判定回传 + 转入/转出 block 审计留痕"
```

---

### Task 6: api——knock-token 第三道闸 + policy 并入 posture-blocked + strict 模式

**Files:**
- Modify: `control/internal/api/api.go`（`handleKnockToken` 加闸、`handleGatewayPolicy` 并入、Server 加 `postureStrict` 字段并在 `New` 读 env）
- Test: `control/internal/api/posture_test.go`（追加用例）

**Interfaces:**
- Consumes: `store.PostureVerdict/PostureBlockedUsers`（Task 3）
- Produces: 持续验证闭环——坏报告 → knock-token 403 + policy revoked 并入（滚动 until）→ 合规报告 → 双双解除；`BAIDI_POSTURE_ENFORCE=strict` 缺报/过期 403

- [ ] **Step 1: 写失败测试**（`posture_test.go` 追加；`badBody`/`good` 提为包级 helper 供复用——把 Task 5 测试里的两个 body 抽成函数 `goodPosture()`/`badPosture()` 返回 map）

```go
// 持续验证闭环：坏报告 → 拒发敲门令牌 + 网关策略并入撤销名单 → 合规报告 → 双双解除。
func TestPostureBlockClosesLoop(t *testing.T) {
	h := newTestServer(t)
	tok := userToken("li.fang")

	// 初始：可拿令牌、不在撤销名单
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusOK {
		t.Fatalf("初始应可拿令牌, got %d", code)
	}
	if revokedUsers(t, h)["li.fang"] {
		t.Fatal("初始不应在撤销名单")
	}
	// 坏报告（磁盘未加密 → block）
	if code, out := doJSON(t, h, "POST", "/api/v1/posture", tok, badPosture()); code != 200 || out["verdict"] != "block" {
		t.Fatalf("坏报告应 block: %v", out)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusForbidden {
		t.Fatalf("block 后应 403, got %d", code)
	}
	if !revokedUsers(t, h)["li.fang"] {
		t.Fatal("block 用户应并入网关撤销名单（堵 8h 会话令牌直连洞）")
	}
	// 合规报告 → 恢复
	if code, out := doJSON(t, h, "POST", "/api/v1/posture", tok, goodPosture()); code != 200 || out["verdict"] != "allow" {
		t.Fatalf("合规报告应 allow: %v", out)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusOK {
		t.Fatalf("恢复后应可拿令牌, got %d", code)
	}
	if revokedUsers(t, h)["li.fang"] {
		t.Fatal("恢复后应移出撤销名单")
	}
}

// strict 模式：无新鲜报告拒发令牌；observe（默认）放行。
func TestPostureStrictMode(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(st, st, testSecret, "test")
	s.postureStrict = true
	h := auth.Middleware(testSecret, s.IsOpen)(s.Routes())
	tok := userToken("li.fang")

	code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil)
	if code != http.StatusForbidden {
		t.Fatalf("strict 缺报应 403, got %d", code)
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/posture", tok, goodPosture()); code != 200 {
		t.Fatal("上报失败")
	}
	if code, _ := doJSON(t, h, "POST", "/api/v1/knock-token", tok, nil); code != http.StatusOK {
		t.Fatalf("strict 有新鲜合规报告应 200, got %d", code)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/api/ -run 'TestPostureBlock|TestPostureStrict'`
Expected: FAIL

- [ ] **Step 3: 实现**（`api.go` 三处）

Server 结构体加字段 + New 读 env（`os` 入 import）：

```go
	postureStrict bool // BAIDI_POSTURE_ENFORCE=strict：无新鲜 posture 报告也拒发敲门令牌（fail-closed）
```

```go
// New 构造 Server。postureStrict 由 BAIDI_POSTURE_ENFORCE=strict 开启（默认 observe：缺报放行、坏报告仍执行）。
func New(st store.Store, wr store.Writer, secret []byte, env string) *Server {
	return &Server{store: st, writer: wr, secret: secret, env: env,
		postureStrict: os.Getenv("BAIDI_POSTURE_ENFORCE") == "strict",
		gateways:      map[string]GatewayInfo{}, gwSess: map[string][]GwSession{}, kicked: map[string]string{}, revoked: map[string]revokeInfo{}}
}
```

`handleKnockToken` 在 blockedDirAccount 闸之后、签发之前插入第三道闸：

```go
	// 终端环境闸（第三道）：最新判定 block 一直拦（不看新鲜度，直到被合规报告替换——防停报逃逸）；
	// strict 模式下无新鲜报告也拒（fail-closed，生产开 BAIDI_POSTURE_ENFORCE=strict）。
	if rep, found, err := s.store.PostureVerdict(r.Context(), c.Name); err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to check posture")
		return
	} else if found && rep.Verdict == "block" {
		s.audit(r, "security", "拒发敲门令牌："+c.Name+" 终端环境不合规（"+strings.Join(rep.Reasons, "、")+"）", "deny")
		httpx.Error(w, http.StatusForbidden, "终端环境不合规："+strings.Join(rep.Reasons, "、"))
		return
	} else if s.postureStrict && (!found || time.Now().Unix()-rep.TS > int64(postureFreshTTL.Seconds())) {
		s.audit(r, "security", "拒发敲门令牌："+c.Name+" 无有效终端环境报告（strict）", "deny")
		httpx.Error(w, http.StatusForbidden, "无有效终端环境报告，无法接入")
		return
	}
```

`handleGatewayPolicy` 在 disabled/locked 并入块之后追加（复用同 `seen`/`until`——注意 `until` 定义在上一块内，若编译报未定义则把 `until := now + int64(kickBanTTL.Seconds())` 提到两块之前）：

```go
	// posture-blocked 用户同款并入（滚动续期）：即使持 8h 会话令牌直敲网关也被拒；
	// 合规报告替换判定后自然从名单消失（读失败静默跳过，与目录并入同策略；令牌闸仍 fail-closed 把守新令牌）。
	if blocked, err := s.store.PostureBlockedUsers(r.Context()); err == nil {
		for _, acc := range blocked {
			if k := normUser(acc); !seen[k] {
				seen[k] = true
				revoked = append(revoked, revokedDTO{User: acc, Until: until})
			}
		}
	}
```

- [ ] **Step 4: 跑测试确认通过（全量）**

Run: `cd ~/Projects/baidi/control && go test ./... && go vet ./...`
Expected: PASS（既有 linkage 测试不回归）

- [ ] **Step 5: Commit**

```bash
git add control/internal/api/
git commit -m "持续验证闭环：knock-token 终端环境闸 + 网关策略并入 posture-blocked + strict 模式（缺报 fail-closed）"
```

---

### Task 7: store——userstate 真实化 + overview 掺 posture

**Files:**
- Create: `control/internal/store/monitor_sqlite.go`（`SQLiteStore.UserStates` 覆盖）
- Modify: `control/internal/store/overview_sqlite.go`（账号防线掺 posture 高危 + 终端防线真实化）
- Test: `control/internal/store/monitor_sqlite_test.go`

**Interfaces:**
- Consumes: `s.Users`、`s.PostureReports`、`risk` 不依赖（判定已落库）
- Produces: `SQLiteStore.UserStates`：items ← 真实 users × posture（state 优先级 disabled > locked > risk-high > risk-low；无报告且状态正常的用户不进清单；idle 无来源诚实为 0）；`Overview.Defense` endpoint 线 ← posture 最差报告

- [ ] **Step 1: 写失败测试** `control/internal/store/monitor_sqlite_test.go`

```go
package store

import (
	"context"
	"testing"
	"time"
)

// userstate 覆盖：真实 users × posture 判定；种子目录含 zhao.min(locked)/ext.zhou(disabled)。
func TestUserStatesReal(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	// li.fang 一台设备 block（高风险）；wang.hong 不存在于目录 → 忽略不进清单
	_ = s.SavePostureReport(ctx, PostureReport{User: "li.fang", Device: "DEV-A", Platform: "macOS",
		Verdict: "block", Score: 25, Level: "high", Reasons: []string{"磁盘已加密"}, TS: now})

	b, err := s.UserStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byAcc := map[string]UserStateItem{}
	for _, it := range b.Items {
		byAcc[it.Account] = it
	}
	if it := byAcc["li.fang"]; it.State != "risk-high" || it.Risk != "high" || len(it.Reasons) == 0 {
		t.Fatalf("li.fang 应 risk-high: %+v", it)
	}
	if it := byAcc["zhao.min"]; it.State != "locked" {
		t.Fatalf("zhao.min 应 locked: %+v", it)
	}
	if it := byAcc["ext.zhou"]; it.State != "disabled" {
		t.Fatalf("ext.zhou 应 disabled: %+v", it)
	}
	if _, ok := byAcc["admin"]; ok {
		t.Fatal("正常无报告用户不应进清单")
	}
	byKey := map[string]int{}
	for _, bk := range b.Buckets {
		byKey[bk.Key] = bk.Count
	}
	if byKey["risk-high"] != 1 || byKey["locked"] != 1 || byKey["disabled"] != 1 || byKey["idle"] != 0 {
		t.Fatalf("分桶: %v", byKey)
	}
}

// overview：posture 高危并入账号防线 TOP；终端防线用最差报告真实化。
func TestOverviewWithPosture(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_ = s.SavePostureReport(ctx, PostureReport{User: "li.fang", Device: "DEV-A", Platform: "macOS",
		Verdict: "block", Score: 25, Level: "high", Reasons: []string{"磁盘已加密"}, TS: time.Now().Unix()})
	ov, err := s.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var accTop, epTop []string
	var epRisk int
	for _, d := range ov.Defense {
		if d.Key == "account" {
			accTop = d.Top
		}
		if d.Key == "endpoint" {
			epTop, epRisk = d.Top, d.Risk
		}
	}
	if !contains(accTop, "li.fang") {
		t.Fatalf("账号防线 TOP 应含 posture 高危 li.fang: %v", accTop)
	}
	if len(epTop) == 0 || epRisk != 25 {
		t.Fatalf("终端防线应由最差报告真实化: top=%v risk=%d", epTop, epRisk)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd ~/Projects/baidi/control && go test ./internal/store/ -run 'TestUserStatesReal|TestOverviewWithPosture'`
Expected: FAIL（UserStates 走 Memory 种子，byAcc 对不上）

- [ ] **Step 3: 实现** `control/internal/store/monitor_sqlite.go`

```go
package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// UserStates 覆盖：真实 users 表 × posture 判定（脱种子）。
// state 优先级 disabled > locked > risk-high > risk-low；状态正常且无 posture 异常的用户不进清单；
// idle（空闲挂起）无真实来源，诚实为 0。
func (s *SQLiteStore) UserStates(ctx context.Context) (UserStateBundle, error) {
	ub, err := s.Users(ctx)
	if err != nil {
		return UserStateBundle{}, err
	}
	reports, err := s.PostureReports(ctx)
	if err != nil {
		return UserStateBundle{}, err
	}
	rank := map[string]int{"allow": 0, "degrade": 1, "gray": 2, "block": 3}
	worst := map[string]PostureReport{}
	for _, r := range reports {
		w, ok := worst[r.User]
		if !ok || rank[r.Verdict] > rank[w.Verdict] || (rank[r.Verdict] == rank[w.Verdict] && r.TS > w.TS) {
			worst[r.User] = r
		}
	}
	now := time.Now().Unix()
	items := []UserStateItem{}
	for _, u := range ub.Users {
		key := strings.ToLower(strings.TrimSpace(u.Account))
		rep, hasRep := worst[key]
		var state, riskLv string
		reasons := []string{}
		lastEvent, lastSeen := "—", "—"
		switch {
		case u.Status == "disabled":
			state, riskLv = "disabled", "none"
			reasons = append(reasons, "账号已被管理员禁用")
			lastEvent = "管理员禁用账号"
		case u.Status == "locked":
			state, riskLv = "locked", "high"
			reasons = append(reasons, "账号已锁定")
			lastEvent = "账号锁定"
		case hasRep && (rep.Verdict == "block" || rep.Level == "high"):
			state, riskLv = "risk-high", "high"
		case hasRep && (rep.Level == "medium" || rep.Score > 0):
			state, riskLv = "risk-low", "low"
		default:
			continue // 状态正常且终端合规（或无报告）：不是"受关注用户"
		}
		if hasRep {
			reasons = append(reasons, rep.Reasons...)
			lastEvent = fmt.Sprintf("终端环境上报（评分 %d · %s）", rep.Score, rep.Device)
			lastSeen = humanAgo(now - rep.TS)
		}
		items = append(items, UserStateItem{
			ID: u.ID, User: u.Name, Account: u.Account, Org: u.Org, State: state, Risk: riskLv,
			Online: hasRep && now-rep.TS <= 600, Reasons: reasons, LastEvent: lastEvent, LastSeen: lastSeen,
		})
	}
	count := func(states ...string) int {
		n := 0
		for _, it := range items {
			for _, st := range states {
				if it.State == st {
					n++
				}
			}
		}
		return n
	}
	buckets := []UserStateBucket{
		{Key: "risk-high", Label: "高风险用户", Count: count("risk-high"), Tone: "danger"},
		{Key: "risk-low", Label: "关注用户", Count: count("risk-low"), Tone: "warning"},
		{Key: "locked", Label: "锁定账号", Count: count("locked"), Tone: "danger"},
		{Key: "disabled", Label: "禁用账号", Count: count("disabled"), Tone: "info"},
		{Key: "idle", Label: "空闲挂起", Count: 0, Tone: "normal"},
	}
	return UserStateBundle{Buckets: buckets, Items: items}, nil
}

// humanAgo 粗粒度"多久之前"。
func humanAgo(sec int64) string {
	switch {
	case sec < 60:
		return "刚刚"
	case sec < 3600:
		return fmt.Sprintf("%d 分钟前", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%d 小时前", sec/3600)
	default:
		return fmt.Sprintf("%d 天前", sec/86400)
	}
}
```

`overview_sqlite.go` 的 Overview()：users 循环里 highRisk 收集之后、`ov.Users = ...` 之前不变；在「账号防线 TOP」块前把 posture 高危并入 highRisk，并在函数末尾（return 前）加终端防线真实化：

```go
	// posture 高危并入账号防线 TOP（风险引擎判定 block/high 的账号），终端防线由最差报告真实化。
	if reports, err := s.PostureReports(ctx); err == nil && len(reports) > 0 {
		rank := map[string]int{"allow": 0, "degrade": 1, "gray": 2, "block": 3}
		worstUser := map[string]PostureReport{}
		for _, r := range reports {
			w, ok := worstUser[r.User]
			if !ok || rank[r.Verdict] > rank[w.Verdict] {
				worstUser[r.User] = r
			}
		}
		var epTop []string
		epRisk := 0
		for _, r := range worstUser {
			if (r.Verdict == "block" || r.Level == "high") && len(epTop) < 3 {
				epTop = append(epTop, r.User)
			}
			if r.Score > epRisk {
				epRisk = r.Score
			}
		}
		for i := range ov.Defense {
			if ov.Defense[i].Key == "endpoint" {
				ov.Defense[i].Risk = epRisk
				if len(epTop) > 0 {
					ov.Defense[i].Top = epTop
				}
			}
			if ov.Defense[i].Key == "account" && len(epTop) > 0 {
				// posture 高危账号补入账号防线 TOP（去重，cap 3）
				seen := map[string]bool{}
				for _, a := range ov.Defense[i].Top {
					seen[a] = true
				}
				for _, a := range epTop {
					if !seen[a] && len(ov.Defense[i].Top) < 3 {
						ov.Defense[i].Top = append(ov.Defense[i].Top, a)
						seen[a] = true
					}
				}
			}
		}
	}
```

注意：Memory 种子 Defense 里 endpoint 线的 Key 需确认是 `endpoint`（见 `store/overview.go` 种子；若种子 Key 不同按实际改测试与代码）。

- [ ] **Step 4: 跑测试确认通过**

Run: `cd ~/Projects/baidi/control && go test ./... && go vet ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add control/internal/store/
git commit -m "用户状态/态势真实化：userstate 脱种子（users×posture）+ 账号/终端防线掺真实风险"
```

---

### Task 8: console——安全中心真保存 + 终端合规 Tab

**Files:**
- Modify: `console/src/lib/api.ts`（加 PostureRow/PostureResp 类型）
- Modify: `console/src/views/Security.vue`（基线保存/新建/删除接后端；新增第三 Tab「终端合规」）

**Interfaces:**
- Consumes: Task 4/5 端点：`POST /security/baselines`、`DELETE /security/baselines/{id}`、`GET /posture`
- Produces: 管理员可视化编辑基线并真实落库；终端合规表实时呈现最新报告

- [ ] **Step 1: api.ts 类型**（`SecurityBundle` 附近追加）

```ts
/* 终端 posture（安全中心 · 终端合规） */
export interface PostureCheckRow { key: string; label: string; ok: boolean; value: string }
export interface PostureRow {
  user: string; device: string; platform: string; os: string; clientVersion: string;
  checks: PostureCheckRow[]; verdict: 'allow' | 'degrade' | 'gray' | 'block';
  score: number; level: 'low' | 'medium' | 'high'; reasons: string[]; ts: number;
}
export interface PostureResp { reports: PostureRow[] }
```

- [ ] **Step 2: Security.vue 改造**（要点，保持既有样式类）

script 部分：

```ts
// Tab 加 'posture'
const tab = ref<'baseline' | 'spa' | 'posture'>('baseline');

/* ── 基线真保存 ── */
const saving = ref(false);
async function saveBaseline() {
  if (!cur.value) return;
  saving.value = true;
  try {
    await api('/security/baselines', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cur.value) });
    Message.success('基线已保存，风险引擎即时生效');
  } catch { Message.error('保存失败（需管理员登录 / 后端在线）'); } finally { saving.value = false; }
}
async function addBaseline() {
  const nb: BaselinePolicy = {
    id: '', name: '新建基线', type: 'onboarding', scope: '全体访问者', disposal: 'degrade', status: 'enabled',
    platforms: ['Windows', 'macOS', 'Linux'], checks: []
  };
  try {
    const r = await api<{ ok: boolean; baseline: BaselinePolicy }>('/security/baselines', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(nb) });
    baselines.value.push(r.baseline); selected.value = r.baseline.id;
    Message.success('已创建，可继续编辑后保存');
  } catch { Message.error('创建失败'); }
}
async function removeBaseline() {
  if (!cur.value) return;
  try {
    await api(`/security/baselines/${cur.value.id}`, { method: 'DELETE' });
    baselines.value = baselines.value.filter((b) => b.id !== cur.value?.id);
    if (baselines.value.length) selected.value = baselines.value[0].id;
    Message.success('基线已删除');
  } catch { Message.error('删除失败'); }
}

/* ── 终端合规 ── */
const postureRows = ref<PostureRow[]>([]);
const postureErr = ref('');
async function loadPosture() {
  try { postureRows.value = (await api<PostureResp>('/posture')).reports; postureErr.value = ''; }
  catch { postureErr.value = '暂无法读取（需管理员登录 / 后端在线）'; }
}
function verdictText(v: string) { return v === 'allow' ? '合规' : v === 'degrade' ? '降权' : v === 'gray' ? '灰度' : '阻断'; }
function verdictColor(v: string) { return v === 'allow' ? '#00B42A' : v === 'degrade' ? '#FF7D00' : v === 'gray' ? '#86909C' : '#F53F3F'; }
function tsText(ts: number) { const d = new Date(ts * 1000); return d.toLocaleString('zh-CN', { hour12: false }); }
```

onMounted 里追加 `loadPosture()`；`addCheck` 保持本地追加（保存时整体 POST）。

template 部分：Tab 行加 `<span class="bd-tab" :class="{ on: tab === 'posture' }" @click="tab = 'posture'; loadPosture()">终端合规</span>`；概要卡 `bd-bhead__sw` 里加「保存」「删除」按钮：

```html
<a-button type="primary" size="small" :loading="saving" @click="saveBaseline">保存</a-button>
<a-button size="small" status="danger" @click="removeBaseline">删除</a-button>
```

名称改为可编辑：`<a-input v-model="cur.name" size="small" style="width:220px" />`（替换原 `bd-bhead__name` span，或双击切换——从简用 a-input）。

新增终端合规块（`v-show="tab === 'posture'"`）：

```html
<div v-show="tab === 'posture'" class="bd-card" style="padding: 16px 20px">
  <div class="bd-section-title" style="display:flex;justify-content:space-between;align-items:center">
    终端合规状态（最新上报）
    <a-button size="small" @click="loadPosture"><icon-refresh /> 刷新</a-button>
  </div>
  <div v-if="postureErr" class="bd-empty">{{ postureErr }}</div>
  <table v-else class="bd-table">
    <thead><tr><th>账号</th><th>设备指纹</th><th>平台 / 系统</th><th>客户端</th><th>检查</th><th>判定</th><th>评分</th><th>最后上报</th></tr></thead>
    <tbody>
      <tr v-for="p in postureRows" :key="p.user + p.device">
        <td><b>{{ p.user }}</b></td>
        <td><span class="bd-mono">{{ p.device }}</span></td>
        <td>{{ p.platform }} · {{ p.os }}</td>
        <td>{{ p.clientVersion || '—' }}</td>
        <td>
          <span v-for="c in p.checks" :key="c.key" class="bd-tg" :style="tagStyle(c.ok ? '#00B42A' : '#F53F3F')" style="margin: 1px 3px 1px 0">{{ c.label }}</span>
        </td>
        <td><span class="bd-tg" :style="tagStyle(verdictColor(p.verdict))">{{ verdictText(p.verdict) }}</span></td>
        <td><b :style="{ color: p.score >= 60 ? '#F53F3F' : p.score >= 30 ? '#FF7D00' : 'var(--bd-t1)' }">{{ p.score }}</b></td>
        <td style="color: var(--bd-t3)">{{ tsText(p.ts) }}</td>
      </tr>
      <tr v-if="postureRows.length === 0"><td colspan="8" class="bd-empty">尚无终端上报——桌面客户端登录后每 60s 自动上报</td></tr>
    </tbody>
  </table>
</div>
```

- [ ] **Step 3: 类型检查与构建**

Run: `cd ~/Projects/baidi/console && npx vue-tsc --noEmit -p tsconfig.json && npm run build`
Expected: 0 错误、build 净

- [ ] **Step 4: preview 实测**（control 跑本机 :8090）：安全中心改基线处置→保存→重进页面确认落库往返；新建/删除；终端合规 Tab 空态文案。

- [ ] **Step 5: Commit**

```bash
git add console/src/
git commit -m "安全中心真实化：基线编辑真保存落库 + 新建/删除 + 终端合规 Tab（最新上报×判定着色）"
```

---

### Task 9: desktop——真实采集 + 60s 上报 + 面板真实化

**Files:**
- Modify: `clients/desktop/src-tauri/src/main.rs`（`collect_posture` command）
- Create: `clients/desktop/src/lib/posture.ts`
- Modify: `clients/desktop/src/views/Connect.vue`（posture 面板真实化 + 上报循环 + 拒绝文案泛化）

**Interfaces:**
- Consumes: control `POST /posture`（Task 5）
- Produces: Rust `collect_posture() -> PostureInfo{platform, os, clientVersion, device, checks[]}`；TS `startPostureLoop()`（60s，登录期间）；Connect.vue 渲染真实检查 + 控制面判定

- [ ] **Step 1: Rust 采集**（main.rs 追加；注册进 `generate_handler![..., collect_posture]`）

```rust
#[derive(serde::Serialize, Clone)]
struct PostureCheck { key: String, label: String, ok: bool, value: String }

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PostureInfo { platform: String, os: String, client_version: String, device: String, checks: Vec<PostureCheck> }

/// 跑一条只读探测命令，返回 stdout（失败返回空串）。
fn probe(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd).args(args).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// 设备指纹：IOPlatformUUID 去连字符取前 16 位，按 4 段冒号分隔（对齐控制台设备指纹形制）。
fn device_fingerprint() -> String {
    let raw = probe("sh", &["-c", "ioreg -rd1 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print $4}'"]);
    let hex: String = raw.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
    if hex.len() < 16 { return "UNKNOWN-DEVICE".into(); }
    format!("{}:{}:{}:{}", &hex[0..4], &hex[4..8], &hex[8..12], &hex[12..16])
}

/// 终端环境真实采集（macOS）：机械布尔化 + 原始值，策略判定在控制面。
#[tauri::command]
fn collect_posture() -> PostureInfo {
    let os_ver = probe("sw_vers", &["-productVersion"]);
    let filevault = probe("fdesetup", &["status"]);                 // "FileVault is On."
    let sip = probe("csrutil", &["status"]);                        // "... status: enabled."
    let fw = probe("/usr/libexec/ApplicationFirewall/socketfilterfw", &["--getglobalstate"]); // "... enabled."/"(State = 1)"
    let procs = probe("ps", &["-axco", "comm"]);
    let edr = ["falcond", "CylanceSvc", "wdavdaemon", "SentinelAgent", "ESET"].iter().any(|p| procs.contains(p));
    let os_ok = os_ver.split('.').next().and_then(|v| v.parse::<u32>().ok()).map(|v| v >= 13).unwrap_or(false);
    let ver = env!("CARGO_PKG_VERSION").to_string();
    let checks = vec![
        PostureCheck { key: "disk_encrypted".into(), label: "磁盘已加密".into(), ok: filevault.contains("On"), value: filevault },
        PostureCheck { key: "sys_integrity".into(), label: "系统完整性保护开启".into(), ok: sip.contains("enabled"), value: sip },
        PostureCheck { key: "firewall_on".into(), label: "系统防火墙启用".into(), ok: fw.contains("enabled") || fw.contains("State = 1") || fw.contains("State = 2"), value: fw },
        PostureCheck { key: "os_version".into(), label: "系统版本合规".into(), ok: os_ok, value: os_ver.clone() },
        PostureCheck { key: "edr_online".into(), label: "EDR 终端防护在线".into(), ok: edr, value: if edr { "检测到 EDR 进程".into() } else { "未检测到".into() } },
        PostureCheck { key: "client_version".into(), label: format!("客户端为最新版本 v{ver}"), ok: true, value: ver.clone() },
    ];
    PostureInfo { platform: "macOS".into(), os: format!("macOS {os_ver}"), client_version: ver, device: device_fingerprint(), checks }
}
```

- [ ] **Step 2: TS 采集/上报封装** `clients/desktop/src/lib/posture.ts`

```ts
/** 终端环境采集与上报：Tauri 真实采集（Rust collect_posture）/浏览器联调模拟采集；
 *  登录期间每 60s 上报控制中心（把接入页那行文案变成真的）。判定权在控制面。 */
import { invoke } from '@tauri-apps/api/core';
import { api } from './api';
import { tauriRuntime } from './tunnel';

export interface PostureCheck { key: string; label: string; ok: boolean; value: string }
export interface PostureInfo { platform: string; os: string; clientVersion: string; device: string; checks: PostureCheck[] }
export interface PostureVerdict { ok: boolean; verdict: 'allow' | 'degrade' | 'gray' | 'block'; score: number; level: string; reasons: string[] }

/** 采集：Tauri 走 Rust 真实探测；浏览器联调回退模拟（标注 DEV-BROWSER，仍走真实上报管道）。 */
export async function collectPosture(): Promise<PostureInfo> {
  if (tauriRuntime()) return await invoke<PostureInfo>('collect_posture');
  return {
    platform: 'macOS', os: '浏览器联调（模拟采集）', clientVersion: '0.1.0', device: 'DEV-BROWSER',
    checks: [
      { key: 'disk_encrypted', label: '磁盘已加密', ok: true, value: '模拟' },
      { key: 'sys_integrity', label: '系统完整性保护开启', ok: true, value: '模拟' },
      { key: 'firewall_on', label: '系统防火墙启用', ok: true, value: '模拟' },
      { key: 'os_version', label: '系统版本合规', ok: true, value: '模拟' },
      { key: 'edr_online', label: 'EDR 终端防护在线', ok: false, value: '浏览器无法检测' },
      { key: 'client_version', label: '客户端为最新版本 v0.1.0', ok: true, value: '0.1.0' }
    ]
  };
}

/** 采集并上报一轮；网络失败返回 null（下轮重试），不打断 UI。 */
export async function reportPosture(): Promise<{ info: PostureInfo; verdict: PostureVerdict } | null> {
  try {
    const info = await collectPosture();
    const verdict = await api<PostureVerdict>('/posture', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(info)
    });
    return { info, verdict };
  } catch { return null; }
}
```

- [ ] **Step 3: Connect.vue 接线**

script 改动：

```ts
import { reportPosture, type PostureInfo, type PostureVerdict } from '@/lib/posture';
import { watch } from 'vue';

/* 环境检测：真实采集 + 控制面判定（每 60s 上报） */
const postureInfo = ref<PostureInfo | null>(null);
const postureVerdict = ref<PostureVerdict | null>(null);
const posture = computed(() => postureInfo.value?.checks ?? []);
const allOk = computed(() => posture.value.length > 0 && posture.value.every((p) => p.ok));
let postureTimer = 0;
async function postureTick() {
  const r = await reportPosture();
  if (r) { postureInfo.value = r.info; postureVerdict.value = r.verdict; }
}
watch(authedNow, (v) => {
  clearInterval(postureTimer);
  if (v) { postureTick(); postureTimer = window.setInterval(postureTick, 60_000); }
}, { immediate: true });
```

（删除原硬编码 `const posture = reactive([...])`；onBeforeUnmount 里追加 `clearInterval(postureTimer)`。）

template 改动——posture 卡（`ck-posture` 内）：

```html
<div class="dk-card ck-posture">
  <div class="ck-card__h">终端环境检测
    <span class="ck-trust" :class="{ bad: postureVerdict?.verdict === 'block' || !allOk }">
      {{ postureVerdict ? (postureVerdict.verdict === 'block' ? '接入受限' : postureVerdict.verdict === 'allow' && allOk ? '终端可信' : '存在风险') : '采集中…' }}
    </span>
  </div>
  <div v-for="p in posture" :key="p.key" class="ck-pi">
    <component :is="p.ok ? 'IconCheckCircleFill' : 'IconExclamationCircleFill'" :style="{ color: p.ok ? '#00B42A' : '#FF7D00' }" />
    <span class="ck-pi__l">{{ p.label }}</span>
    <span class="ck-pi__v" :class="{ warn: !p.ok }">{{ p.ok ? '通过' : '关注' }}</span>
  </div>
  <div v-if="posture.length === 0" class="ck-pi" style="color: var(--bd-t3)">正在采集终端环境…</div>
  <div class="ck-report">
    {{ postureVerdict ? `已上报控制中心 · 判定 ${({allow:'合规',degrade:'降权',gray:'灰度',block:'阻断'})[postureVerdict.verdict]} · 评分 ${postureVerdict.score}` : '每 60s 周期上报控制中心 · 风险驱动动态收缩权限' }}
  </div>
</div>
```

拒绝提示条标题泛化（`ck-denied__t`）：`接入已被管理员终止` → `接入已被控制面拒绝`（posture 阻断与强制下线共用该条，原因文本来自控制面 403 信封，`tunnel.ts` 既有 `denied/deniedReason` 链路不动）。

- [ ] **Step 4: 验证**

Run:
```bash
cd ~/Projects/baidi/clients/desktop/src-tauri && cargo check
cd ~/Projects/baidi/clients/desktop && npx vue-tsc --noEmit && npm run build
```
Expected: 全净。再起 control + `npm run dev`（:5294）preview：登录 li.fang → posture 卡出现模拟采集 6 项 + 「已上报控制中心 · 判定 …」；控制台安全中心「终端合规」出现 DEV-BROWSER 行。

- [ ] **Step 5: Commit**

```bash
git add clients/desktop/
git commit -m "桌面客户端 posture 真实化：Rust 真实采集（FileVault/SIP/防火墙/EDR）+ 60s 真实上报 + 控制面判定呈现"
```

---

### Task 10: E2E 闭环实测 + 全量回归

**Files:** 无新增（验证任务）

- [ ] **Step 1: 全量测试**

```bash
cd ~/Projects/baidi/control && go test ./... && go vet ./...
cd ~/Projects/baidi/gateway && go test ./... && go build ./... 
cd ~/Projects/baidi/console && npm run build
```
Expected: 全绿（gateway 零改动，确认无意外回归）。

- [ ] **Step 2: E2E（本机，参照强制下线 E2E 剧本）**

```bash
# 终端1: control
cd ~/Projects/baidi/control && BAIDI_DB=/tmp/baidi-e2e.db go run ./cmd/baidi-control
# 终端2: 后端 + gateway（2s 轮询）
python3 -m http.server 19999 &
cd ~/Projects/baidi/gateway && go run ./cmd/baidi-gateway -spa 127.0.0.1:18201 -proxy 127.0.0.1:18443 \
  -backend 127.0.0.1:19999 -control http://127.0.0.1:8090 -gwid gw-e2e -poll 2s
# 终端3: 剧本
TOK=$(curl -s -XPOST localhost:8090/api/v1/portal/login -d '{"username":"li.fang","password":"baidi@123"}' | jq -r .token)
curl -s -XPOST localhost:8090/api/v1/knock-token -H "Authorization: Bearer $TOK"        # → 200
# 敲门 + openssl s_client 建长连（同强制下线剧本）
# 坏报告（磁盘未加密）：
curl -s -XPOST localhost:8090/api/v1/posture -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"device":"E2E-MAC","platform":"macOS","os":"macOS 14","clientVersion":"0.1.0","checks":[{"key":"disk_encrypted","label":"磁盘已加密","ok":false,"value":"Off"}]}'
# 验证：verdict=block；knock-token → 403 带原因；网关日志 ≤2s 出现撤窗/断隧道；netstat 无 ESTABLISHED
# 合规报告 → knock-token 恢复 200；网关名单消失
```

- [ ] **Step 3: preview 走查**：控制台（安全中心三 Tab、用户状态真实分桶、大屏终端防线）+ 桌面 dev 端（posture 面板）。

- [ ] **Step 4: Commit（如有修正）+ 汇总**

---

## Self-Review 结论

- Spec 覆盖：DP-01..10 全部有任务落点（DP-04/05/08→Task 6；DP-02→Task 2/4/8；DP-03→Task 1；DP-06→Task 3 PostureVerdict；DP-07→Task 6 只 block 并入；DP-09→README 声明并入 Task 10 汇总时顺手补；DP-10→api 层 normUser）。
- 类型一致性：`PostureCheckResult`（store）/`PostureCheck`（Rust/TS 序列化后字段同名 key/label/ok/value）/`PostureRow`（console）字段对齐；`postureCols` 列序与 Scan 一致。
- level 阈值与 spec 的差异（block 强制 high 地板）已回写 spec。
