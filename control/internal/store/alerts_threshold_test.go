package store

import (
	"errors"
	"strings"
	"testing"
)

// 告警阈值取值区间的回归。
//
// ★改造前的形态：NormalizeThresholds **只校验键认不认识、完全不看值**。
// 控制台那个阈值输入框被清空的瞬间（Arco InputNumber emit change(undefined)，
// 前端兜成 `Number(nv ?? 0)`）就把 0 落库，接口回 200、toast 说
// 「规则「网关离线」已保存」、绿色「已启用」开关一字不变，而规则的行为已经翻到另一端：
//   · expireDays 15 → 0：License 到期前不再有任何提醒；
//   · beforeMinutes 30 → 0：JIT 将到期提醒永不触发；
//   · offlineSec 120 → 0：每台在线网关每轮都判离线，冷却一到就刷一条告警加一封邮件。
// 两个方向（永不触发 / 每轮都触发）都不报错。
//
// 前端已改成"清空即不提交"，但客户端不是唯一入口（API 可以直接 POST），
// 且下一次改前端的人不一定记得这条——判据必须在执行侧也成立。

func TestNormalizeThresholdsRejectsDegenerateValues(t *testing.T) {
	// 每条都是"清空输入框"能真实造出来的 0，以及它落库后规则会变成什么样。
	cases := []struct {
		kind, key string
		bad       float64
		why       string
	}{
		{AlertKindGatewayOffline, ThreshOfflineSec, 0, "0 秒超时会让每台在线网关每轮都判成离线"},
		{AlertKindGatewayLoad, ThreshCPUPercent, 0, "0% 表示任何占用都超标，规则恒触发"},
		{AlertKindGrantExpiring, ThreshBeforeMin, 0, "提前量 0 = 窗口为空，「即将到期」永不触发"},
		{AlertKindClockSkew, ThreshSkewSec, 0, "0 秒偏差会让每台网关每轮都报"},
		{AlertKindLicenseExpiry, ThreshExpireDays, 0, "0 天 = 没有任何到期前预警"},
		{AlertKindLicenseSeats, ThreshSeatPercent, 0, "0% 表示任何占用都算将满"},
		{AlertKindAuditForwardFail, ThreshWithinMin, 0, "0 分钟会让「持续投不出去」那一支永不触发"},
		{AlertKindAuditForwardFail, ThreshBacklogPercent, 0, "0% 表示队列里有一条待发就算积压"},
	}
	for _, c := range cases {
		_, err := NormalizeThresholds(c.kind, map[string]float64{c.key: c.bad})
		if !errors.Is(err, ErrThresholdRange) {
			t.Fatalf("%s/%s = %v 应被拒（%s），实得 err=%v", c.kind, c.key, c.bad, c.why, err)
		}
		// 错误正文要说得出是哪一项、越了哪一边、后果是什么——只说"不合法"
		// 管理员会反复换数字试（IPSec peer 拒收 FQDN 那条同款纪律）。
		spec, _ := AlertKindSpecOf(c.kind)
		if zh := spec.ThresholdZh[c.key]; zh != "" && !strings.Contains(err.Error(), zh) {
			t.Fatalf("400 正文必须点名是页面上哪一栏（「%s」），实得 %q", zh, err.Error())
		}
	}
}

// 上界同理：超过 100% 的占用率阈值让条件永远不成立，规则看着是启用的却永不触发。
func TestNormalizeThresholdsRejectsAbovePercentCeiling(t *testing.T) {
	for _, key := range []string{ThreshCPUPercent, ThreshMemPercent, ThreshDiskPercent} {
		if _, err := NormalizeThresholds(AlertKindGatewayLoad,
			map[string]float64{key: 101}); !errors.Is(err, ErrThresholdRange) {
			t.Fatalf("%s = 101%% 应被拒（超过上界后该条件永远不成立），实得 err=%v", key, err)
		}
	}
}

// ★不是所有 0 都该拒：宽限期 0 在 alerting 里判的是 overdue < grace，
// 即「过期即报、不留宽限」——一条**合法**配置。一刀切下界会把它一起拒掉，
// 而管理员会以为是自己填错了。谁能取 0 必须逐个照着 internal/alerting 读出来。
func TestNormalizeThresholdsAllowsLegitimateZero(t *testing.T) {
	out, err := NormalizeThresholds(AlertKindGrantStale, map[string]float64{ThreshGraceMinutes: 0})
	if err != nil {
		t.Fatalf("宽限期 0（过期即报）是合法配置，不该被拒：%v", err)
	}
	if out[ThreshGraceMinutes] != 0 {
		t.Fatalf("宽限期 0 应原样落库，实得 %v", out[ThreshGraceMinutes])
	}
}

// 各 kind 的出厂默认值必须落在自己的区间内——否则「什么都不改直接保存」就会被拒，
// 而那正是管理员打开页面第一件会做的事。
func TestAlertKindDefaultsWithinBounds(t *testing.T) {
	for _, spec := range AlertKindSpecs() {
		if _, err := NormalizeThresholds(spec.Kind, spec.Thresholds); err != nil {
			t.Fatalf("规则 %s 的出厂默认阈值 %v 落在区间外：%v", spec.Kind, spec.Thresholds, err)
		}
	}
}

// 每个登记在 alertKindSpecs 里的阈值键都必须有区间登记：checkThresholdRange 对
// 未登记的键放行（保持可用），所以漏登记是**静默**的——这条用例是它唯一的守卫。
func TestEveryThresholdKeyHasBounds(t *testing.T) {
	for _, spec := range AlertKindSpecs() {
		for key := range spec.Thresholds {
			if _, ok := thresholdBounds[key]; !ok {
				t.Fatalf("阈值键 %s（规则 %s）没有登记取值区间：清空输入框落 0 又会一路进库", key, spec.Kind)
			}
		}
	}
}
