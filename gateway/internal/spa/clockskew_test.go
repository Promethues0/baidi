package spa

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"baidi.dev/gateway/internal/auth"
	"baidi.dev/gateway/internal/knock"
	"baidi.dev/gateway/internal/secevent"
)

// ── wave11 行动 11-①：时钟超窗与「重放」必须分得开 ──
//
// ★缺陷形态不是措辞不准，是**归因反了**：客户端保活每 15s 敲一次、每轮敲全部落点，
// 一台时钟偏了 31 秒的正常员工机一天稳定产出几千次超窗拒绝 → 安全概览的
// 「攻击源 TOP」第一名，而类别中文名逐字写着「敲门信封无效/重放」→ 管理员去封员工。
//
// ★为什么用例落在 handler 上而不是 knock.Open：Open 回什么错误是内部约定，
// 真正决定页面上那行字的是**上报了哪个类别**。把分类逻辑留在 Serve 的无限循环里
// 就没有任何用例够得着它——改错了照样编译通过、集成/e2e 全绿。

// recorder 记下 Reporter 收到的每一条上报。
type recorder struct {
	cats    []string
	details []string
}

func newHandler(rec *recorder) *handler {
	rep := secevent.New(func(cat, src, detail string, count int, allow bool) {
		rec.cats = append(rec.cats, cat)
		rec.details = append(rec.details, detail)
	})
	// 装一把 HS256 兼容密钥只为造出一个可用的 Verifier：本组用例的令牌全是占位串，
	// 验签必失败（那正是「过了信封闸」的可观测证据），密钥内容无所谓。
	v, err := auth.NewVerifier("", []byte("test-only"), true)
	if err != nil {
		panic(err)
	}
	return &handler{v: v, ttl: time.Minute, al: NewAllowlist(), strict: true,
		knockMaxTTL: 5 * time.Minute, rep: rep, cache: knock.NewCache()}
}

// sealAt 造一个时间戳为 ts、nonce 为 n 的敲门信封（不经 knock.Seal，那只会用当前时间）。
func sealAt(t *testing.T, ts int64, n string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"t": "dummy.jwt.token", "ts": ts, "n": n})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestClockSkewReportedAsItsOwnCategory 时间戳超窗必须单列成 knock-clockskew。
//
// ★变异实测：把 spa.handle 里 `errors.Is(err, knock.ErrClockSkew)` 那个分支删掉
// （让它落回 knock-envelope），本用例两条断言同时变红。
func TestClockSkewReportedAsItsOwnCategory(t *testing.T) {
	for _, tc := range []struct {
		name string
		off  time.Duration // 相对当前时间的偏移（正 = 时钟快，负 = 时钟慢）
		want string        // 期望在 detail 里出现的方向词
	}{
		// 时钟慢：包内时间戳偏早。也可能是延迟到达的旧包，故文案要写两种可能。
		{"终端时钟慢", -(skew + 10*time.Second), "早"},
		// 时钟快：包内时间戳在未来。**只可能**是时钟快——重放者手里是捕获的旧包，
		// 造不出未来时间戳，所以这一档的文案可以下确定结论。
		{"终端时钟快", skew + 10*time.Second, "晚"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			h := newHandler(rec)
			h.handle(sealAt(t, time.Now().Add(tc.off).Unix(), "bm9uY2Ux"), "203.0.113.9")

			if len(rec.cats) != 1 || rec.cats[0] != "knock-clockskew" {
				t.Fatalf("时钟超窗应上报 knock-clockskew（不是「信封无效/重放」），得 %v", rec.cats)
			}
			if !strings.Contains(rec.details[0], tc.want) {
				t.Fatalf("拒绝正文必须说清偏移方向（含「%s」），得 %q", tc.want, rec.details[0])
			}
			// 偏移量必须报出来：只说「时间戳无效」的话，管理员既不知道差多少也不知道往哪调。
			if !strings.Contains(rec.details[0], "40 秒") {
				t.Fatalf("拒绝正文必须报出实测偏移秒数，得 %q", rec.details[0])
			}
		})
	}
}

// TestNonceReplayStaysAttackSignal 被动重放（同一 nonce 再来一次）仍是真信号，
// 不得被顺手一起摘出去——它与时钟无关。
func TestNonceReplayStaysAttackSignal(t *testing.T) {
	rec := &recorder{}
	h := newHandler(rec)
	pkt := sealAt(t, time.Now().Unix(), "cmVwbGF5")

	h.handle(pkt, "203.0.113.9") // 第一次：nonce 通过，落到验签失败（knock-token）
	h.handle(pkt, "203.0.113.9") // 第二次：整包重放 → nonce 重复

	if len(rec.cats) != 2 {
		t.Fatalf("两次敲门应各上报一条，得 %v", rec.cats)
	}
	if rec.cats[0] != "knock-token" {
		t.Fatalf("首次应过信封闸并卡在验签，得 %q", rec.cats[0])
	}
	if rec.cats[1] != "knock-envelope" {
		t.Fatalf("nonce 重复是被动重放，应留在 knock-envelope（计入攻击源），得 %q", rec.cats[1])
	}
}

// TestMissingNonceStaysEnvelope nonce 缺失（信封不合规）同样留在 knock-envelope。
func TestMissingNonceStaysEnvelope(t *testing.T) {
	rec := &recorder{}
	h := newHandler(rec)
	h.handle(sealAt(t, time.Now().Unix(), ""), "203.0.113.9")

	if len(rec.cats) != 1 || rec.cats[0] != "knock-envelope" {
		t.Fatalf("nonce 缺失应上报 knock-envelope，得 %v", rec.cats)
	}
}
