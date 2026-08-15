// 终端资产分类的准入用例（wave7 行动 15，PRD ch9 FR-EP-06~09）。
//
// 这一批用例守的是一件事：**资产分类是设备维度的判定，不能溢出到账号维度**。
// 本项目里最接近的既有机制（风险降权 disposal=degrade）恰恰是账号维度的，
// 顺手复用它就会把同一个人的企业机一起误伤——那种误伤在页面上完全看不出来
// （设备页显示企业机"已授信"，用户却打不开高敏应用）。
package api

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"baidi.dev/control/internal/auth"
	"baidi.dev/control/internal/store"
)

// ── 测试助手 ──

// setDeviceAsset 标注一台设备的资产分类与标签。
func setDeviceAsset(t *testing.T, h http.Handler, account, fingerprint, class string, tags []string) map[string]any {
	t.Helper()
	d := findDevice(t, h, account, fingerprint)
	code, out := doJSON(t, h, "PUT", "/api/v1/devices/"+d["id"].(string)+"/asset", adminToken(),
		map[string]any{"assetClass": class, "tags": tags})
	if code != http.StatusOK {
		t.Fatalf("标注资产分类 %s http %d: %v", class, code, out)
	}
	return out
}

// savePersonalPolicy 保存准入设置（含个人资产策略）。
func savePersonalPolicy(t *testing.T, h http.Handler, mode, personalPolicy string) {
	t.Helper()
	code, out := doJSON(t, h, "PUT", "/api/v1/devices/settings", adminToken(),
		map[string]any{"mode": mode, "bindMethod": store.DeviceBindApproval, "staleDays": 30,
			"personalPolicy": personalPolicy})
	if code != http.StatusOK {
		t.Fatalf("保存个人资产策略 %s http %d: %v", personalPolicy, code, out)
	}
}

// enrollTrusted 上报 + 批准一台设备，返回可用的会话令牌。
func enrollTrusted(t *testing.T, h http.Handler, sess, account, fp string) {
	t.Helper()
	if code, out := reportPosture(t, h, sess, fp); code != http.StatusOK {
		t.Fatalf("上报 %s http %d: %v", fp, code, out)
	}
	approveDevice(t, h, account, fp)
}

// ── ① 默认值与回填后的既有行为 ──

// 新登记的设备是企业资产、无标签；默认个人资产策略是 inherit（= 行为与本功能上线前一致）。
func TestDeviceDefaultsToEnterpriseAsset(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-ASSET-DEF"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}
	d := findDevice(t, h, "li.fang", "FP-ASSET-DEF")
	if d["assetClass"] != store.AssetClassEnterprise {
		t.Fatalf("新设备应默认企业资产, got %v", d["assetClass"])
	}
	tags, ok := d["tags"].([]any)
	if !ok || len(tags) != 0 {
		t.Fatalf("新设备的标签应是空数组而不是 null, got %#v", d["tags"])
	}
	code, out := doJSON(t, h, "GET", "/api/v1/devices", adminToken(), nil)
	if code != http.StatusOK {
		t.Fatalf("GET /devices http %d", code)
	}
	set, _ := out["settings"].(map[string]any)
	if set["personalPolicy"] != store.PersonalPolicyInherit {
		t.Fatalf("默认个人资产策略必须是 inherit（上线不改变任何既有行为）, got %v", set["personalPolicy"])
	}
}

// ── ② 三档 personalPolicy 各自的行为 ──

// inherit（默认）：个人资产与企业资产一视同仁，走全局模式——observe 下照常放行。
func TestPersonalInheritBehavesLikeBefore(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-PI-1"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}
	setDeviceAsset(t, h, "li.fang", "FP-PI-1", store.AssetClassPersonal, nil)
	// 观察模式 + inherit：pending 的个人资产照常放行（与本功能上线前逐字节一致）。
	if code, out := knockWithDevice(t, h, sess, "FP-PI-1"); code != http.StatusOK || out["token"] == "" {
		t.Fatalf("inherit 下个人资产应与企业资产一视同仁, http %d: %v", code, out)
	}
}

// strict：个人资产恒按严格准入判——即使全局仍是 observe。批准后放行。
func TestPersonalStrictAppliesUnderGlobalObserve(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-PS-1"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}
	setDeviceAsset(t, h, "li.fang", "FP-PS-1", store.AssetClassPersonal, nil)
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyStrict)

	code, out := knockWithDevice(t, h, sess, "FP-PS-1")
	if code != http.StatusForbidden {
		t.Fatalf("strict 策略下未批准的个人资产应被拒（全局仍是 observe）, http %d: %v", code, out)
	}
	// ★拒绝原因必须点名"个人资产"与"全局仍是观察模式"，否则管理员对着一张
	// 写着「准入模式：观察」的页面，永远排不出这次拒绝是从哪来的。
	msg := errMsg(out)
	if !strings.Contains(msg, "个人资产") {
		t.Fatalf("拒绝原因必须点名资产分类, got %q", msg)
	}

	approveDevice(t, h, "li.fang", "FP-PS-1")
	if code, out := knockWithDevice(t, h, sess, "FP-PS-1"); code != http.StatusOK {
		t.Fatalf("批准后的个人资产在 strict 策略下应放行, http %d: %v", code, out)
	}
}

// deny：个人资产一律拒，**即使已批准为 trusted**。
func TestPersonalDenyRejectsEvenTrusted(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	enrollTrusted(t, h, sess, "li.fang", "FP-PD-1")
	if code, _ := knockWithDevice(t, h, sess, "FP-PD-1"); code != http.StatusOK {
		t.Fatal("标成个人资产之前应能接入")
	}

	setDeviceAsset(t, h, "li.fang", "FP-PD-1", store.AssetClassPersonal, nil)
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyDeny)

	code, out := knockWithDevice(t, h, sess, "FP-PD-1")
	if code != http.StatusForbidden {
		t.Fatalf("deny 策略下个人资产应被拒（含已授信）, http %d: %v", code, out)
	}
	msg := errMsg(out)
	if !strings.Contains(msg, "个人资产") {
		t.Fatalf("拒绝原因必须点名资产分类而不是泛泛的「终端未授信」, got %q", msg)
	}
	// 设备状态仍然是 trusted：deny 是策略层面的否决，不是把设备吊销了。
	// 两者混为一谈的话，管理员把策略调回 inherit 后会发现设备"莫名其妙被吊销过"。
	if s := findDevice(t, h, "li.fang", "FP-PD-1")["status"]; s != store.DeviceStatusTrusted {
		t.Fatalf("deny 不得改动设备状态, got %v", s)
	}
	// 策略调回 inherit 立刻恢复（现算，不缓存判定结果）。
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyInherit)
	if code, out := knockWithDevice(t, h, sess, "FP-PD-1"); code != http.StatusOK {
		t.Fatalf("策略调回 inherit 后应立刻恢复接入, http %d: %v", code, out)
	}
}

// managed（企业纳管个人）按**企业资产**处理：deny 策略碰不到它。
// 否则"纳管"这个动作就没有结果——管理员没有任何办法让一台已纳管的自带设备正常接入。
func TestManagedAssetTreatedAsEnterprise(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	enrollTrusted(t, h, sess, "li.fang", "FP-MG-1")
	setDeviceAsset(t, h, "li.fang", "FP-MG-1", store.AssetClassManaged, []string{"已装管控"})
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyDeny)

	if code, out := knockWithDevice(t, h, sess, "FP-MG-1"); code != http.StatusOK {
		t.Fatalf("企业纳管个人应按企业资产放行（deny 只管 personal）, http %d: %v", code, out)
	}
	// strict 策略同理碰不到它：未批准的 managed 在全局 observe 下照常放行。
	if code, _ := reportPosture(t, h, sess, "FP-MG-2"); code != http.StatusOK {
		t.Fatal("上报第二台应成功")
	}
	setDeviceAsset(t, h, "li.fang", "FP-MG-2", store.AssetClassManaged, nil)
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyStrict)
	if code, out := knockWithDevice(t, h, sess, "FP-MG-2"); code != http.StatusOK {
		t.Fatalf("strict 策略也只约束 personal, http %d: %v", code, out)
	}
}

// ★★ 本设计的核心：**同账号一台企业机、一台个人机，deny 策略下企业机照常放行**。
//
// 这条钉住的是"执行方必须落在 (账号,指纹) 粒度的准入闸"这个决定本身。
// 若哪天有人把资产分类并进风险降权（那条通道是 store.PostureUsersByDisposal →
// 网关 DenyUsers，**按账号**表达），这条用例会红——而线上的表现是：
// 某人因为家里那台笔记本被标成个人资产，公司发的电脑也一起访问不了高敏资源，
// 页面上两台设备都写着"已授信"，谁也看不出来是哪一步做的。
func TestPersonalDenyDoesNotAffectEnterpriseDevice(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	enrollTrusted(t, h, sess, "li.fang", "FP-MIX-WORK") // 公司发的
	enrollTrusted(t, h, sess, "li.fang", "FP-MIX-HOME") // 自己带的

	setDeviceAsset(t, h, "li.fang", "FP-MIX-HOME", store.AssetClassPersonal, []string{"家用"})
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyDeny)

	if code, out := knockWithDevice(t, h, sess, "FP-MIX-HOME"); code != http.StatusForbidden {
		t.Fatalf("个人机应被拒, http %d: %v", code, out)
	}
	// 同一个账号、同一个会话令牌，只换指纹——企业机必须照常拿到敲门令牌。
	code, out := knockWithDevice(t, h, sess, "FP-MIX-WORK")
	if code != http.StatusOK || out["token"] == "" {
		t.Fatalf("★同账号的企业机不得被误伤（资产分类是设备维度，不能溢出成账号维度）, http %d: %v", code, out)
	}
	// 账号本身也不能被并入强制下线名单（那是吊销才做的事，会切断该账号所有终端的隧道）。
	if revokedUsers(t, h)["li.fang"] {
		t.Fatal("个人资产被拒不得把账号并入撤销名单——那会连企业机的隧道一起切断")
	}
	// strict 档同理：企业机不受影响。
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyStrict)
	if code, _ := knockWithDevice(t, h, sess, "FP-MIX-WORK"); code != http.StatusOK {
		t.Fatalf("strict 档下企业机同样不受影响, http %d", code)
	}
}

// 吊销的判定必须**排在**资产分类之前：两者都拒，但被拒的人看到的原因不同。
// 吊销是管理员对这台机器的显式处置，理由也更具体（含吊销理由原文）；
// 回一句资产分类会把人支去改分类，而改回企业资产这台机器照样进不来。
//
// 用重启把内存态的账号封禁清掉（同 TestKnockObserveStillRejectsRevokedDevice 的办法）：
// 吊销会顺带把账号并入强制下线，那道闸排在设备闸之前，不清掉就测不到设备闸自己的措辞。
func TestRevokedReasonWinsOverAssetClass(t *testing.T) {
	e := newDeviceEnv(t)
	sess := userSession(t, e.h, "li.fang")
	enrollTrusted(t, e.h, sess, "li.fang", "FP-RV-ASSET")
	setDeviceAsset(t, e.h, "li.fang", "FP-RV-ASSET", store.AssetClassPersonal, nil)
	savePersonalPolicy(t, e.h, store.DeviceTrustObserve, store.PersonalPolicyDeny)
	revokeDevice(t, e.h, "li.fang", "FP-RV-ASSET", "设备遗失")

	e.restart(t)
	if revokedUsers(t, e.h)["li.fang"] {
		t.Fatal("重启后账号封禁应已消失（内存态），本用例据此隔离出设备闸自身的措辞")
	}
	_, out := knockWithDevice(t, e.h, sess, "FP-RV-ASSET")
	msg := errMsg(out)
	if !strings.Contains(msg, "设备遗失") {
		t.Fatalf("已吊销设备的拒绝原因应是吊销理由（更具体的那条）, got %q", msg)
	}
}

// 未登记设备没有分类可言，仍走原有的"未登记"分支（observe 放行 / strict 拒），
// 不得因为 deny 策略把它们当成个人资产一并拒掉——那会让 deny 变成一个
// "顺便把所有没纳管的设备也挡了"的开关，与它的名字不符。
func TestUnknownDeviceUnaffectedByPersonalPolicy(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyDeny)
	if code, out := knockWithDevice(t, h, sess, "FP-UNKNOWN-1"); code != http.StatusOK {
		t.Fatalf("未登记设备在 observe 下仍应放行（deny 只约束已标为个人资产的设备）, http %d: %v", code, out)
	}
}

// ── ③ 编辑端点：权限、校验、审计 ──

func TestSetDeviceAssetEndpoint(t *testing.T) {
	h := newTestServer(t)
	sess := userSession(t, h, "li.fang")
	if code, _ := reportPosture(t, h, sess, "FP-EDIT-1"); code != http.StatusOK {
		t.Fatal("posture 上报应成功")
	}
	id := findDevice(t, h, "li.fang", "FP-EDIT-1")["id"].(string)

	// 非法分类 400，且库里一个字都不改。
	code, _ := doJSON(t, h, "PUT", "/api/v1/devices/"+id+"/asset", adminToken(),
		map[string]any{"assetClass": "byod"})
	if code != http.StatusBadRequest {
		t.Fatalf("非法分类应 400, got %d", code)
	}
	if c := findDevice(t, h, "li.fang", "FP-EDIT-1")["assetClass"]; c != store.AssetClassEnterprise {
		t.Fatalf("失败的写入不得改动分类, got %v", c)
	}
	// 不存在的设备 404。
	if code, _ := doJSON(t, h, "PUT", "/api/v1/devices/dev-nope/asset", adminToken(),
		map[string]any{"assetClass": store.AssetClassPersonal}); code != http.StatusNotFound {
		t.Fatalf("不存在的设备应 404, got %d", code)
	}
	// 审计管理员（只读权）改不动它——分类是准入判据，与批准/吊销同权。
	audTok := makeAdmin(t, h, "aud.asset", "audit")
	if code, _ := doJSON(t, h, "PUT", "/api/v1/devices/"+id+"/asset", audTok,
		map[string]any{"assetClass": store.AssetClassPersonal}); code != http.StatusForbidden {
		t.Fatalf("审计管理员改资产分类应 403, got %d", code)
	}

	// 正常路径：分类改动 + 标签归一（去重、去空）。
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyDeny)
	out := setDeviceAsset(t, h, "li.fang", "FP-EDIT-1", store.AssetClassPersonal,
		[]string{" 研发 ", "研发", "", "外包"})
	dev, _ := out["device"].(map[string]any)
	tags, _ := dev["tags"].([]any)
	if len(tags) != 2 || tags[0] != "研发" || tags[1] != "外包" {
		t.Fatalf("标签应去空去重并保序, got %#v", dev["tags"])
	}
	// 审计要写得出"从 X 改成 Y"，并带上当前生效的策略——分类本身不说明后果，
	// 同一次「改成个人资产」在 inherit 下什么都没发生、在 deny 下等于当场断它的路。
	if !auditHasEvent(t, h, "企业资产 → 个人资产") {
		t.Fatal("资产分类变更审计必须写明改动前后")
	}
	if !auditHasEvent(t, h, "将被拒发敲门令牌") {
		t.Fatal("deny 策略下改成个人资产的审计必须写明它的实际后果")
	}
	// ★标签必须被如实标注为"不参与判定"：界面与审计都不许暗示它能控制访问。
	if !auditHasEvent(t, h, "不参与任何准入或授权判定") {
		t.Fatal("标签变更审计必须写明标签没有执行方")
	}
}

// 准入设置：拼错的 personalPolicy 一律 400，不静默兜成 inherit。
// 管理员选了 deny 却保存成 inherit 且接口回 200，是本项目最不能接受的失败形态。
func TestSaveDeviceTrustSettingValidatesPersonalPolicy(t *testing.T) {
	h := newTestServer(t)
	code, _ := doJSON(t, h, "PUT", "/api/v1/devices/settings", adminToken(),
		map[string]any{"mode": store.DeviceTrustObserve, "bindMethod": store.DeviceBindApproval,
			"staleDays": 30, "personalPolicy": "deny-all"})
	if code != http.StatusBadRequest {
		t.Fatalf("非法 personalPolicy 应 400, got %d", code)
	}
	// 未配置过时，缺字段的旧版请求照常成功，落默认 inherit。
	code, out := doJSON(t, h, "PUT", "/api/v1/devices/settings", adminToken(),
		map[string]any{"mode": store.DeviceTrustObserve, "bindMethod": store.DeviceBindApproval, "staleDays": 30})
	if code != http.StatusOK {
		t.Fatalf("缺 personalPolicy 的旧版请求应照常成功, http %d: %v", code, out)
	}
	if out["personalPolicy"] != store.PersonalPolicyInherit {
		t.Fatalf("未配置过时缺省应落 inherit, got %v", out["personalPolicy"])
	}

	// ★核心：已配置 deny 之后，**不带该字段的保存不得把它改回 inherit**。
	// "没带这一项" ≠ "把这一项设成 inherit"。本 handler 是全量 PUT，若缺字段收成
	// inherit，任何按本功能上线前的接口写的客户端（旧 console 构建、浏览器里缓存的旧 JS、
	// 照老文档写的脚本）只要保存一次准入设置——哪怕只是把陈旧阈值从 30 改成 60——
	// 就会把整个 BYOD 封锁无声关掉，而页面上写着「跟随全局」，没人会把两件事联系起来。
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyDeny)
	code, out = doJSON(t, h, "PUT", "/api/v1/devices/settings", adminToken(),
		map[string]any{"mode": store.DeviceTrustObserve, "bindMethod": store.DeviceBindApproval, "staleDays": 60})
	if code != http.StatusOK {
		t.Fatalf("旧版请求应照常成功, http %d: %v", code, out)
	}
	if out["personalPolicy"] != store.PersonalPolicyDeny {
		t.Fatalf("★不带 personalPolicy 的保存把已配置的 deny 静默降级成了 %v", out["personalPolicy"])
	}
	if out["staleDays"].(float64) != 60 {
		t.Fatalf("其余字段应照常更新, got %v", out["staleDays"])
	}
	// 显式传 inherit 才算「改成跟随全局」
	code, out = doJSON(t, h, "PUT", "/api/v1/devices/settings", adminToken(),
		map[string]any{"mode": store.DeviceTrustObserve, "bindMethod": store.DeviceBindApproval,
			"staleDays": 60, "personalPolicy": store.PersonalPolicyInherit})
	if code != http.StatusOK || out["personalPolicy"] != store.PersonalPolicyInherit {
		t.Fatalf("显式 inherit 应生效, http %d: %v", code, out)
	}
	// 保存 deny 要落审计（写明它的实际含义，而不是一个枚举值）。
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyDeny)
	if !auditHasEvent(t, h, "个人资产一律拒绝接入") {
		t.Fatal("个人资产策略变更必须落审计且写人话")
	}
}

// ── ④ 判据读失败的方向性（个人资产策略同 Mode 一档待遇）──

// 准入设置读失败**不得**把 deny 静默降级成 inherit。
//
// ★这是 deviceTrustPolicy 缓存整份设置（而不只是 Mode）的理由：只缓存 Mode 的话，
// 一次数据库抖动就会让所有个人资产在那段时间里照常接入，而页面上仍写着"一律拒绝"，
// 现场唯一的痕迹是一条 slog——与 strict 被降级成 observe 是同一个失败形态。
func TestPersonalDenySurvivesTrustSettingReadFailure(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "flaky-asset.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	flaky := &flakyTrustSettingStore{Store: st}
	s := New(flaky, st, testKeys, "test", t.TempDir(), nil, nil, true)
	h := auth.Middleware(testKeys, s.IsOpen)(s.Routes())

	sess := userSession(t, h, "li.fang")
	enrollTrusted(t, h, sess, "li.fang", "FP-FLAKY-ASSET")
	setDeviceAsset(t, h, "li.fang", "FP-FLAKY-ASSET", store.AssetClassPersonal, nil)
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyDeny)
	// 读得到设置：被拒（同时把 deny 记成"上次已知"）。
	if code, _ := knockWithDevice(t, h, sess, "FP-FLAKY-ASSET"); code != http.StatusForbidden {
		t.Fatal("deny 下个人资产应被拒")
	}

	flaky.fail.Store(true)
	if code, out := knockWithDevice(t, h, sess, "FP-FLAKY-ASSET"); code != http.StatusForbidden {
		t.Fatalf("设置读失败不得把 deny 降级成 inherit, http %d: %v", code, out)
	}

	// 恢复后照常按库里的值判（缓存不会把闸永久卡死）。
	flaky.fail.Store(false)
	savePersonalPolicy(t, h, store.DeviceTrustObserve, store.PersonalPolicyInherit)
	if code, out := knockWithDevice(t, h, sess, "FP-FLAKY-ASSET"); code != http.StatusOK {
		t.Fatalf("策略调回 inherit 后应放行, http %d: %v", code, out)
	}
}
