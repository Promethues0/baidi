package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"baidi.dev/control/internal/store"
)

// natErrStore 让 NATPolicies 报错，其余方法透传——模拟 `database is locked`
// 那类**临时**读失败（modernc SQLite 单写者，而 gateway_metrics 每网关 15s 一条、
// 审计/攻击源/告警多条循环并发写，这不是罕见形态）。
type natErrStore struct {
	store.NATStore
	fail bool
}

func (n *natErrStore) NATPolicies(ctx context.Context) ([]store.NATPolicy, error) {
	if n.fail {
		return nil, errors.New("database is locked")
	}
	return n.NATStore.NATPolicies(ctx)
}

// 下发 NAT 策略是**三态**，不是两态（同 gwMetrics/Ifaces/Stealth 的 nil 判定、
// posture 的 unknown）：
//   ① 字段缺席 = 不可判定 → 网关保持内核规则现状；
//   ② nat: []  = 本网关确实无策略 → 网关清空规则；
//   ③ 有策略   = 按清单灌。
//
// ★改造前读库失败也走 ②（"本轮按空集下发"），而网关侧 natPresent = (r.NAT != nil)
// 对 JSON 的 `[]` 判 present=true → natfw n==0 → `nft delete table ip baidi_nat`
// **整表删除**：SNAT 没了内网整段断外网、DNAT 没了对外业务全部不可达，
// 连隧道/敲门排除规则也一并消失。错误持续多久就断多久，恢复后自动重灌——
// 表现为「偶发、几十秒、无法复现」的出口断网。
func TestNATPolicyReadFailureOmitsField(t *testing.T) {
	f := newIsoFixture(t)
	ns, ok := any(f.st).(store.NATStore)
	if !ok {
		t.Skip("该后端不支持 NAT")
	}
	stub := &natErrStore{NATStore: ns}
	f.s.nat = stub

	fetch := func() (map[string]json.RawMessage, int) {
		req := httptest.NewRequest("GET", "/api/v1/gateways/policy", nil)
		req.Header.Set("Authorization", "Bearer "+gatewayToken())
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		var out map[string]json.RawMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out, rec.Code
	}

	// ② 正常读取：字段必须在（哪怕是空集）——网关据此清空，语义明确。
	out, code := fetch()
	if code != http.StatusOK {
		t.Fatalf("正常路径应 200，实得 %d", code)
	}
	if _, has := out["nat"]; !has {
		t.Error("正常读取时必须下发 nat 字段：缺席会被网关读成「不可判定」而保留旧规则")
	}

	// ① 读失败：**绝不能**下发空集，否则网关会删掉整张 NAT 表。
	stub.fail = true
	out, code = fetch()
	if code != http.StatusOK {
		t.Fatalf("读 NAT 失败不该让整个策略下发失败（资源与撤销名单仍要发），实得 %d", code)
	}
	if raw, has := out["nat"]; has {
		t.Errorf("NAT 读取失败时必须**省略** nat 字段（网关保持现状），实得 nat=%s —— "+
			"下发空集等于让所有正在轮询的网关一起执行 nft delete table，当场断网", raw)
	}
	// 同一响应里其余字段必须照常下发：一次 NAT 读失败不该连累资源授权与强制下线。
	for _, k := range []string{"resources", "revoked"} {
		if _, has := out[k]; !has {
			t.Errorf("NAT 读失败不该影响 %s 的下发", k)
		}
	}
}
