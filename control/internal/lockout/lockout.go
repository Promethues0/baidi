// Package lockout 实现登录防爆破（PRD ch5 FR-MON-17/18 + ch20 NFR-SEC-06）：
// 账号与源 IP 两个维度的滑动窗失败计数 + 限时自动锁定。
//
// 职责边界：
//   - 判定权全在控制面登录链路（/auth/login、/portal/login、WebAuthn 断言），数据面零改动；
//   - 失败计数只在内存——进程重启丢计数无伤大雅（顶多让攻击者多试几次）；
//   - 锁定记录必须经 Store 落库——重启不丢锁定，否则重启控制面就成了攻击者的解锁按钮；
//   - 认证源故障不计数（故障 ≠ 密码错误，见 api/login_authsrc.go 的既有约定），
//     这由调用方保证：Fail 只在「用户提交的凭据确实被拒」时调用。
package lockout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"baidi.dev/control/internal/store"
)

// settingKey 运行时配置在 settings 表里的键。
const settingKey = "lockout_config"

// Store 是本包需要的持久化能力（*store.SQLiteStore 实现）。抽小接口而非直依赖，
// 与 api/login_authsrc.go 的 authSourceStore 同一姿态：单测塞假实现即可。
type Store interface {
	SaveLockout(ctx context.Context, l store.Lockout) error
	DeleteLockout(ctx context.Context, kind, key string) (bool, error)
	ActiveLockouts(ctx context.Context) ([]store.Lockout, error)
	Setting(ctx context.Context, k string) (string, bool, error)
	SetSetting(ctx context.Context, k, v string) error
}

// Config 防爆破参数。环境变量 BAIDI_LOCKOUT_* 给默认值，settings 表的运行时覆盖优先
// （管理台「策略管理 · 防暴力破解」页可改，改完即时生效且重启保留）。
type Config struct {
	Threshold      int  `json:"threshold"`      // 窗口内失败次数阈值（默认 5：第 5 次失败即锁）
	WindowSec      int  `json:"windowSec"`      // 滑动窗口（秒，默认 600）
	DurationSec    int  `json:"durationSec"`    // 锁定时长（秒，默认 900）
	IPEnabled      bool `json:"ipEnabled"`      // 源 IP 维度开关
	AccountEnabled bool `json:"accountEnabled"` // 账号维度开关
}

// Validate 校验配置边界（FromEnv 与管理台 PUT 共用同一口径）。
func (c Config) Validate() error {
	if c.Threshold < 1 || c.Threshold > 100 {
		return errors.New("threshold 须在 1-100 之间")
	}
	if c.WindowSec < 60 || c.WindowSec > 86400 {
		return errors.New("windowSec 须在 60-86400（1 分钟到 24 小时）之间")
	}
	if c.DurationSec < 60 || c.DurationSec > 86400 {
		return errors.New("durationSec 须在 60-86400（1 分钟到 24 小时）之间")
	}
	return nil
}

// FromEnv 从环境变量读默认配置。非法取值告警并回落默认——防爆破是安全闸，
// 配置错了应当以更严（默认值）而不是关闭告终。
func FromEnv() Config {
	c := Config{Threshold: 5, WindowSec: 600, DurationSec: 900, IPEnabled: true, AccountEnabled: true}
	if v := os.Getenv("BAIDI_LOCKOUT_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 100 {
			c.Threshold = n
		} else {
			slog.Warn("BAIDI_LOCKOUT_THRESHOLD 非法，沿用默认 5", "value", v)
		}
	}
	c.WindowSec = envDurationSec("BAIDI_LOCKOUT_WINDOW", c.WindowSec)
	c.DurationSec = envDurationSec("BAIDI_LOCKOUT_DURATION", c.DurationSec)
	return c
}

func envDurationSec(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Minute || d > 24*time.Hour {
		slog.Warn("锁定时长环境变量非法（须 1m-24h 的 Go duration），沿用默认", "name", name, "value", v)
		return def
	}
	return int(d / time.Second)
}

// Guard 防爆破守卫：内存滑动窗计数 + 内存锁定表（Store 持久化镜像）。
// 运行期以内存为准（落库失败锁定仍生效——fail-closed 方向）；启动时从库装回未到期锁定。
type Guard struct {
	st  Store            // 可为 nil（纯内存，仅测试 / Memory 后端），nil 时重启即丢锁定
	now func() time.Time // 可注入时钟（单测滑动窗口用）

	mu    sync.Mutex
	cfg   Config
	fails map[string][]int64       // kind␀key → 窗口内失败时间戳
	locks map[string]store.Lockout // kind␀key → 生效锁定
}

func lockKey(kind, key string) string { return kind + "\x00" + key }

// New 构造守卫：环境变量默认 → settings 运行时覆盖 → 装回库中未到期锁定。
func New(st Store) *Guard {
	g := &Guard{st: st, now: time.Now, cfg: FromEnv(),
		fails: map[string][]int64{}, locks: map[string]store.Lockout{}}
	if st == nil {
		return g
	}
	ctx := context.Background()
	if raw, ok, err := st.Setting(ctx, settingKey); err != nil {
		slog.Warn("读取登录防爆破运行时配置失败，沿用环境变量默认", "err", err.Error())
	} else if ok {
		var c Config
		if jerr := json.Unmarshal([]byte(raw), &c); jerr == nil && c.Validate() == nil {
			g.cfg = c
		} else {
			slog.Warn("已存的登录防爆破配置无效，沿用环境变量默认", "raw", raw)
		}
	}
	if ls, err := st.ActiveLockouts(ctx); err != nil {
		slog.Warn("装载既有登录锁定失败（库中未到期的锁定本次启动不生效）", "err", err.Error())
	} else {
		for _, l := range ls {
			g.locks[lockKey(l.Kind, l.Key)] = l
		}
	}
	return g
}

// Config 返回当前生效配置。
func (g *Guard) Config() Config {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cfg
}

// SetConfig 校验并应用新配置：先落 settings（重启保留），再切内存生效值。
func (g *Guard) SetConfig(ctx context.Context, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if g.st != nil {
		raw, _ := json.Marshal(c)
		if err := g.st.SetSetting(ctx, settingKey, string(raw)); err != nil {
			return err
		}
	}
	g.mu.Lock()
	g.cfg = c
	g.mu.Unlock()
	return nil
}

// Check 报告账号或源 IP 是否处于锁定期（懒清理到期项，账号锁优先返回）。
// 维度开关关闭时该维度不拦——开关的语义就是「这道闸要不要」，关了还拦等于假开关的反面。
func (g *Guard) Check(account, ip string) (store.Lockout, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now().Unix()
	if g.cfg.AccountEnabled && account != "" {
		if l, ok := g.activeLocked(store.LockKindAccount, account, now); ok {
			return l, true
		}
	}
	if g.cfg.IPEnabled && ip != "" {
		if l, ok := g.activeLocked(store.LockKindIP, ip, now); ok {
			return l, true
		}
	}
	return store.Lockout{}, false
}

// activeLocked 须持锁调用。
func (g *Guard) activeLocked(kind, key string, now int64) (store.Lockout, bool) {
	l, ok := g.locks[lockKey(kind, key)]
	if !ok {
		return store.Lockout{}, false
	}
	if now >= l.Until {
		delete(g.locks, lockKey(kind, key)) // 到期即自动解锁
		return store.Lockout{}, false
	}
	return l, true
}

// Fail 登记一次登录失败（口令错 / WebAuthn 断言失败）。窗口内累计达到阈值即创建锁定并落库，
// 返回本次新建的锁定清单——调用方据此写审计（只记确实发生了的锁定）。
// ★认证源故障不要调这里：那是运维故障不是用户失败（api 层负责区分）。
func (g *Guard) Fail(ctx context.Context, account, ip string) []store.Lockout {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var created []store.Lockout
	if g.cfg.AccountEnabled && account != "" {
		if l, ok := g.fail1(ctx, store.LockKindAccount, account, now); ok {
			created = append(created, l)
		}
	}
	if g.cfg.IPEnabled && ip != "" {
		if l, ok := g.fail1(ctx, store.LockKindIP, ip, now); ok {
			created = append(created, l)
		}
	}
	return created
}

// fail1 须持锁调用：单维度计数，达阈值即建锁并清计数。
func (g *Guard) fail1(ctx context.Context, kind, key string, now time.Time) (store.Lockout, bool) {
	kk := lockKey(kind, key)
	cut := now.Unix() - int64(g.cfg.WindowSec)
	win := make([]int64, 0, len(g.fails[kk])+1)
	for _, ts := range g.fails[kk] {
		if ts > cut { // 窗口外的历史失败滑出，不累计
			win = append(win, ts)
		}
	}
	win = append(win, now.Unix())
	if len(win) < g.cfg.Threshold {
		g.fails[kk] = win
		return store.Lockout{}, false
	}
	delete(g.fails, kk)
	l := store.Lockout{
		Kind: kind, Key: key,
		Until:     now.Unix() + int64(g.cfg.DurationSec),
		Reason:    fmt.Sprintf("%s内连续 %d 次登录失败", humanDur(g.cfg.WindowSec), g.cfg.Threshold),
		CreatedAt: now.Format("2006-01-02 15:04:05"),
	}
	g.locks[kk] = l
	if g.st != nil {
		if err := g.st.SaveLockout(ctx, l); err != nil {
			// 内存锁定照常生效（本进程内依旧拦），只是重启会丢——记错误留痕，不因存储抖动放行爆破。
			slog.Error("登录锁定落库失败（本进程内仍生效，重启后将丢失）", "kind", kind, "key", key, "err", err.Error())
		}
	}
	return l, true
}

// Success 登录成功，清零该账号的失败计数。
// ★刻意不清源 IP 计数：攻击者只要混入一次自己账号的成功登录就能重置 IP 维度，等于白给绕过。
func (g *Guard) Success(account string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.fails, lockKey(store.LockKindAccount, account))
}

// Unlock 管理员解锁：删内存锁定 + 删库中记录 + 清残余失败计数（解锁即既往不咎）。
// 返回是否真的解掉了一条生效锁定。
func (g *Guard) Unlock(ctx context.Context, kind, key string) (bool, error) {
	kk := lockKey(kind, key)
	g.mu.Lock()
	l, mem := g.locks[kk]
	if mem && g.now().Unix() >= l.Until {
		mem = false // 已到期的不算「解锁」，只是顺手清理
	}
	delete(g.locks, kk)
	delete(g.fails, kk)
	g.mu.Unlock()
	removed := mem
	if g.st != nil {
		db, err := g.st.DeleteLockout(ctx, kind, key)
		if err != nil {
			return removed, err
		}
		removed = removed || db
	}
	return removed, nil
}

// Active 返回当前生效的锁定清单（懒清理到期项；kind、key 排序保证 UI 稳定）。
func (g *Guard) Active() []store.Lockout {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now().Unix()
	out := []store.Lockout{}
	for kk, l := range g.locks {
		if now >= l.Until {
			delete(g.locks, kk)
			continue
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// humanDur 秒数的中文可读形态（整小时 → 小时，整分钟 → 分钟，否则秒）。
func humanDur(sec int) string {
	switch {
	case sec%3600 == 0:
		return fmt.Sprintf("%d 小时", sec/3600)
	case sec%60 == 0:
		return fmt.Sprintf("%d 分钟", sec/60)
	default:
		return fmt.Sprintf("%d 秒", sec)
	}
}
