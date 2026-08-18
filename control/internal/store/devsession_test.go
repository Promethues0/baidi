package store

import "testing"

// ── wave8 行动 13-①：接入策略纯判定（FR-POLICY-29/30）──
//
// 判定写成纯函数的理由与 alerting.Evaluate 相同：条件写反在集成环境里与
// 「一切正常」无法区分（没人被拒 = 规则没触发 = 看起来很正常），只有纯函数测得住。

func sess(fp, plat string, lastKnock int64, opts ...func(*DeviceSession)) DeviceSession {
	d := DeviceSession{Account: "li.fang", Fingerprint: fp, Platform: plat,
		FirstSeen: lastKnock, LastKnock: lastKnock, State: DevSessionActive}
	for _, o := range opts {
		o(&d)
	}
	return d
}

func withActive(ts int64) func(*DeviceSession) {
	return func(d *DeviceSession) { d.LastActive, d.ActivityKnown = ts, true }
}

const now int64 = 1_700_000_000

func TestAccessDisabledPolicyAllowsEverything(t *testing.T) {
	p := AccessPolicy{} // 两条规则都关
	me := sess("fp1", "Windows", now)
	all := []DeviceSession{me, sess("fp2", "Windows", now), sess("fp3", "Windows", now)}
	if d := EvaluateAccess(p, all, me, true, now, 90); !d.Allowed {
		t.Fatalf("两条规则都关时不该拒任何人，得到 %+v", d)
	}
}

// TestConcurrencyLimit 同时在线设备上限（FR-POLICY-29）。
func TestConcurrencyLimit(t *testing.T) {
	p := AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 2}
	a, b := sess("fp-a", "Windows", now), sess("fp-b", "Windows", now)
	newDev := sess("fp-c", "Windows", now)

	// 两台已在线 + 第三台来 → 拒。
	if d := EvaluateAccess(p, []DeviceSession{a, b, newDev}, newDev, false, now, 90); d.Allowed {
		t.Fatal("已达上限时第三台必须被拒")
	} else if d.Rule != "concurrency" {
		t.Fatalf("规则名应是 concurrency，得到 %q", d.Rule)
	}
	// ★已在名额内的那台**续期**必须放行。否则用满名额后每 15s 保活都会把自己挤下去，
	// 表现为「明明只开了 2 台，却轮流掉线」。
	if d := EvaluateAccess(p, []DeviceSession{a, b}, a, true, now, 90); !d.Allowed {
		t.Fatalf("已在名额内的终端续期不该被拒：%+v", d)
	}
	// 早就不再敲门的那台不占名额（onlineWindow 之外）。
	stale := sess("fp-old", "Windows", now-1000)
	if d := EvaluateAccess(p, []DeviceSession{a, stale, newDev}, newDev, false, now, 90); !d.Allowed {
		t.Fatalf("离线终端不该继续占名额：%+v", d)
	}
	// 已注销的那台也不占名额。
	ended := sess("fp-end", "Windows", now, func(d *DeviceSession) { d.State = DevSessionTimeout })
	if d := EvaluateAccess(p, []DeviceSession{a, ended, newDev}, newDev, false, now, 90); !d.Allowed {
		t.Fatalf("已注销的会话不该继续占名额：%+v", d)
	}
}

// TestConcurrencyZeroMeansForbidden PRD 原文：0 = 禁止登录。
func TestConcurrencyZeroMeansForbidden(t *testing.T) {
	p := AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 0}
	me := sess("fp1", "Windows", now)
	d := EvaluateAccess(p, []DeviceSession{me}, me, false, now, 90)
	if d.Allowed {
		t.Fatal("上限 0 = 禁止接入（PRD FR-POLICY-29 原文）")
	}
	// ★但**没启用**时的 0 必须放行——否则存量库里那一列的零值等于全员禁止接入。
	if d := EvaluateAccess(AccessPolicy{MaxDevices: 0}, []DeviceSession{me}, me, false, now, 90); !d.Allowed {
		t.Fatal("未启用该规则时，MaxDevices 的零值绝不能被解读成「禁止接入」——" +
			"那会让升级重启那一刻全员被挡在门外，而配置页看起来一切正常")
	}
}

// TestConcurrencySplitPlatform 区分 PC / 移动端分别计数。
func TestConcurrencySplitPlatform(t *testing.T) {
	p := AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 1, MaxDevicesMobile: 2, SplitPlatform: true}
	pc := sess("fp-pc", "Windows", now)
	phone1, phone2 := sess("fp-m1", "iOS", now), sess("fp-m2", "Android", now)
	phone3 := sess("fp-m3", "iOS", now)

	// PC 已占满 1 台，手机来第一台 → 放行（各算各的）。
	if d := EvaluateAccess(p, []DeviceSession{pc, phone1}, phone1, false, now, 90); !d.Allowed {
		t.Fatalf("分平台计数时移动端不该被 PC 占满：%+v", d)
	}
	// 手机 2 台已满，第三台 → 拒，且文案要点名是移动端。
	all := []DeviceSession{pc, phone1, phone2, phone3}
	d := EvaluateAccess(p, all, phone3, false, now, 90)
	if d.Allowed {
		t.Fatal("移动端已达上限应拒")
	}
	if !hasSub(d.Reason, "移动端") {
		t.Fatalf("拒绝文案要点名是哪一类名额满了，得到 %q", d.Reason)
	}
	// 第二台 PC → 拒，文案说 PC 端。
	pc2 := sess("fp-pc2", "macOS", now)
	d = EvaluateAccess(p, []DeviceSession{pc, pc2}, pc2, false, now, 90)
	if d.Allowed || !hasSub(d.Reason, "PC 端") {
		t.Fatalf("PC 端已达上限应拒且文案点名，得到 %+v", d)
	}
	// ★平台不可判定（没报过 posture）按 PC 计——算成移动端的话，一台从没上报过的
	// Windows 机会去挤移动端名额，而页面上显示的是 PC 名额还空着。
	unknown := sess("fp-?", "", now)
	if d := EvaluateAccess(p, []DeviceSession{pc, unknown}, unknown, false, now, 90); d.Allowed {
		t.Fatal("平台不可判定应按 PC 计（PC 名额已满 → 拒）")
	}
}

// TestIdleLogoutNeedsRealActivitySignal 活跃时刻不可判定时**绝不**注销。
//
// ★这是本项最要紧的一条。判据缺席就把人踢下线，等于拿"探不到"当确定结论——
// 旧网关不报活跃时刻的部署里，开启这条规则会把全体在线用户一起断掉。
func TestIdleLogoutNeedsRealActivitySignal(t *testing.T) {
	p := AccessPolicy{IdleEnabled: true, IdleMinutes: 5}
	// 接入两小时、网关从没报过活跃时刻 → ActivityKnown=false → 不判。
	me := sess("fp1", "Windows", now)
	me.FirstSeen = now - 7200
	// existed=true：这台机器已经接入两小时了（不是刚来的），空闲判定该对它生效——
	// 传 false 的话整条 idle 分支根本不执行，用例就变成了什么也没验。
	if d := EvaluateAccess(p, []DeviceSession{me}, me, true, now, 90); !d.Allowed {
		t.Fatalf("没有任何网关报过活跃时刻时不得注销（判据缺席≠没有流量）：%+v", d)
	}
}

// TestIdleLogout 有真实活跃信号时才注销（FR-POLICY-30）。
func TestIdleLogout(t *testing.T) {
	p := AccessPolicy{IdleEnabled: true, IdleMinutes: 5}
	// 10 分钟前有过业务流量 → 超 5 分钟 → 注销。
	idle := sess("fp1", "Windows", now, withActive(now-600))
	d := EvaluateAccess(p, []DeviceSession{idle}, idle, true, now, 90)
	if d.Allowed {
		t.Fatal("超过空闲时长应注销")
	}
	if d.Rule != "idle" || !hasSub(d.Reason, "业务流量") {
		t.Fatalf("要说清是「无业务流量」而不是「掉线」：%+v", d)
	}
	// 1 分钟前有流量 → 不注销。
	busy := sess("fp1", "Windows", now, withActive(now-60))
	if d := EvaluateAccess(p, []DeviceSession{busy}, busy, true, now, 90); !d.Allowed {
		t.Fatalf("仍在活跃的会话不该被注销：%+v", d)
	}
	// 网关明确报「从未有业务连接」（lastActive=0 且 known）→ 从接入时刻起算。
	never := sess("fp1", "Windows", now, withActive(0))
	never.FirstSeen = now - 600
	if d := EvaluateAccess(p, []DeviceSession{never}, never, true, now, 90); d.Allowed {
		t.Fatal("网关明确报「从未有业务连接」时，应从接入时刻起算空闲——这与「网关不报」不是一回事")
	}
	// 关掉规则 → 不再注销新的会话。
	if d := EvaluateAccess(AccessPolicy{}, []DeviceSession{idle}, idle, true, now, 90); !d.Allowed {
		t.Fatalf("规则关闭后不该继续注销：%+v", d)
	}
}

// TestTimeoutStateStickyUntilRelogin 已注销的会话必须重新登录才能恢复。
//
// ★这一条独立于 IdleEnabled：管理员事后关掉规则，不该让已经注销的会话在下一个
// 15s 保活里自己活过来——那等于"注销"从未发生过。
func TestTimeoutStateStickyUntilRelogin(t *testing.T) {
	ended := sess("fp1", "Windows", now, func(d *DeviceSession) {
		d.State, d.EndedReason = DevSessionTimeout, "无业务流量超时"
	})
	for _, p := range []AccessPolicy{{IdleEnabled: true, IdleMinutes: 5}, {}} {
		d := EvaluateAccess(p, []DeviceSession{ended}, ended, true, now, 90)
		if d.Allowed {
			t.Fatalf("已注销的会话在 policy=%+v 下仍被放行——重新登录才是唯一恢复途径", p)
		}
		if !hasSub(d.Reason, "重新登录") {
			t.Fatalf("要告诉用户怎么恢复，得到 %q", d.Reason)
		}
	}
}

func hasSub(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestAccessPolicyValidate 边界（PRD：0~1000 台，5 分钟~365 天）。
func TestAccessPolicyValidate(t *testing.T) {
	bad := []AccessPolicy{
		{MaxDevices: -1},
		{MaxDevices: 1001},
		{MaxDevicesMobile: 1001},
		{IdleEnabled: true, IdleMinutes: 4},
		{IdleEnabled: true, IdleMinutes: MaxIdleMinutes + 1},
	}
	for _, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("越界配置应被拒：%+v", p)
		}
	}
	ok := []AccessPolicy{
		{}, {DeviceLimitEnabled: true, MaxDevices: 0}, {MaxDevices: 1000},
		{IdleEnabled: true, IdleMinutes: MinIdleMinutes},
		{IdleEnabled: true, IdleMinutes: MaxIdleMinutes},
		// 规则没开时，IdleMinutes 的零值不该被判成越界（否则默认配置存不进去）。
		{IdleMinutes: 0},
	}
	for _, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("合法配置被拒：%+v → %v", p, err)
		}
	}
}

// TestParseAccessPolicyFallsBackToInert 坏数据一律回落成「不生效」。
func TestParseAccessPolicyFallsBackToInert(t *testing.T) {
	for _, raw := range []string{"", "{", `{"maxDevices":-5,"deviceLimitEnabled":true}`} {
		p := ParseAccessPolicy(raw, raw != "")
		if p.DeviceLimitEnabled || p.IdleEnabled {
			t.Fatalf("坏数据 %q 不能回落成「更严的策略」——回落成 maxDevices=0+启用 就是全员禁止接入，得到 %+v", raw, p)
		}
	}
}

// TestConcurrencyLoweredLimitTakesEffect 上限调小后，超出的终端必须真的被挤掉。
//
// ★这是「已在线就一律放行」那种写法的判据。那样写的话，管理员把上限从 5 改到 2，
// 已在线的 5 台各自靠 15s 保活无限续期，新上限**永远不会生效**——
// 一条改了却不起作用的安全配置，而页面上显示着「已启用 · 2 台」。
func TestConcurrencyLoweredLimitTakesEffect(t *testing.T) {
	p := AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 2}
	// 三台按接入先后：a(最早) < b < c。
	a := sess("fp-a", "Windows", now, func(d *DeviceSession) { d.FirstSeen = now - 3000 })
	b := sess("fp-b", "Windows", now, func(d *DeviceSession) { d.FirstSeen = now - 2000 })
	c := sess("fp-c", "Windows", now, func(d *DeviceSession) { d.FirstSeen = now - 1000 })
	all := []DeviceSession{a, b, c}
	for _, keep := range []DeviceSession{a, b} {
		if d := EvaluateAccess(p, all, keep, true, now, 90); !d.Allowed {
			t.Fatalf("先到的 %s 应保住名额：%+v", keep.Fingerprint, d)
		}
	}
	if d := EvaluateAccess(p, all, c, true, now, 90); d.Allowed {
		t.Fatal("上限调小后，最晚接入的那台必须被挤掉，否则新上限永远不生效")
	}
}

// TestConcurrencyNewcomerNeverPreemptsOnline 同一秒接入时，新来的不许把已在线的挤掉。
//
// ★纯按 (first_seen, 指纹) 排名会让一台新终端凭字典序抢走名额，被挤掉的那台
// 要到下一个保活周期才发现，而「是谁把我挤掉的」在任何日志里都看不出来。
func TestConcurrencyNewcomerNeverPreemptsOnline(t *testing.T) {
	p := AccessPolicy{DeviceLimitEnabled: true, MaxDevices: 1}
	// 指纹刻意让新来者排在前面（'!' < 'z'）。
	held := sess("zzz-online", "Windows", now)
	newbie := sess("!!!-new", "Windows", now)
	if d := EvaluateAccess(p, []DeviceSession{held, newbie}, newbie, false, now, 90); d.Allowed {
		t.Fatal("新终端不该凭指纹字典序抢走已在线终端的名额")
	}
	// 被拒的新终端不会在表里留下行（api.accessSessionGate 回滚记账），
	// 于是已在线的那台在下一轮里照常保住名额。
	if d := EvaluateAccess(p, []DeviceSession{held}, held, true, now, 90); !d.Allowed {
		t.Fatal("已在线的那台不该被新来者挤掉")
	}
}
