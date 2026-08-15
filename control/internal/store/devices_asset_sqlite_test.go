package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// ── 终端资产分类与标签（wave7 行动 15）的存储层用例 ──
//
// 重点全在**回填**上：补列迁移只加列不填值，`apps.resource_id` 就这么静默断过一次。
// asset_class 是准入判据，留 NULL 的表现是"页面正常、SQL 侧筛不出来"，两边都不报错。

// oldSchemaDeviceDB 造一个"补列之前"的库：trusted_devices 没有 asset_class / tags 两列。
// 必须真的走一遍 OpenSQLite 的迁移路径，而不是断言 SQL 字符串。
func oldSchemaDeviceDB(t *testing.T, rows ...[3]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "old-devices.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE trusted_devices (
  id TEXT PRIMARY KEY, account TEXT, fingerprint TEXT, name TEXT, platform TEXT,
  status TEXT, first_seen INTEGER, last_seen INTEGER,
  approved_by TEXT, approved_at INTEGER, approval_id TEXT, revoke_reason TEXT,
  UNIQUE(account, fingerprint)
)`); err != nil {
		t.Fatalf("create old table: %v", err)
	}
	for _, r := range rows { // [id, account, fingerprint]
		if _, err := db.Exec(`INSERT INTO trusted_devices(id,account,fingerprint,name,platform,status,
first_seen,last_seen,approved_by,approved_at,approval_id,revoke_reason)
VALUES(?,?,?,'旧设备','macOS','trusted',1700000000,1700000000,'admin',1700000000,'','')`,
			r[0], r[1], r[2]); err != nil {
			t.Fatalf("insert old row: %v", err)
		}
	}
	return path
}

// 存量设备回填成 enterprise（企业资产）——**行为不变**是回填的唯一正确取值。
//
// 回填成 personal 的话，管理员一旦把个人资产策略切到 deny，全体存量终端会在
// 那一刻集体被拒发敲门令牌，而设备页上每一台都还写着"已授信"。
func TestBackfillDeviceAssetOnLegacyDB(t *testing.T) {
	path := oldSchemaDeviceDB(t,
		[3]string{"dev-old-1", "li.fang", "FP-OLD-1"},
		[3]string{"dev-old-2", "li.fang", "FP-OLD-2"},
	)
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	b, err := st.Devices(ctx)
	if err != nil {
		t.Fatalf("read devices: %v", err)
	}
	if len(b.Devices) != 2 {
		t.Fatalf("存量两台设备应都还在, got %d", len(b.Devices))
	}
	for _, d := range b.Devices {
		if d.AssetClass != AssetClassEnterprise {
			t.Fatalf("存量设备 %s 应回填成企业资产（迁移不得改变既有主体的接入权）, got %q", d.ID, d.AssetClass)
		}
		if d.Tags == nil || len(d.Tags) != 0 {
			t.Fatalf("存量设备 %s 的标签应是空集合而不是 null, got %#v", d.ID, d.Tags)
		}
	}

	// ★回填必须真的写进列里，不能只靠读侧兜底：按分类做的 SQL 查询是另一条路径，
	// 留 NULL 会让「页面显示 2 台企业资产、按分类统计 0 台」这种分歧成立，且两边都不报错。
	var n int
	if err := st.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM trusted_devices WHERE asset_class=?`, AssetClassEnterprise).Scan(&n); err != nil {
		t.Fatalf("按分类统计失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("asset_class 列本身必须被回填（SQL 侧筛得出来）, got %d", n)
	}
}

// 回填是一次性的：管理员标过的分类不得在下次启动时被"回填"回企业资产
// （"改了重启就变回去"，而 personalPolicy 随之静默失效）。
func TestBackfillDeviceAssetIsOneShot(t *testing.T) {
	path := oldSchemaDeviceDB(t, [3]string{"dev-old-1", "li.fang", "FP-OLD-1"})
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	ctx := context.Background()
	if _, _, err := st.SetDeviceAsset(ctx, "dev-old-1", AssetClassPersonal, []string{"BYOD"}); err != nil {
		t.Fatalf("标注资产失败: %v", err)
	}
	st.Close()

	st2, err := OpenSQLite(path) // 重启
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	d, found, err := st2.DeviceByFingerprint(ctx, "li.fang", "FP-OLD-1")
	if err != nil || !found {
		t.Fatalf("设备应还在: %v %v", found, err)
	}
	if d.AssetClass != AssetClassPersonal {
		t.Fatalf("重启不得把人工标注的分类冲回默认值, got %q", d.AssetClass)
	}
	if len(d.Tags) != 1 || d.Tags[0] != "BYOD" {
		t.Fatalf("标签应持久化, got %#v", d.Tags)
	}
}

// 新设备默认企业资产：终端自报的内容里没有"这台机器是谁买的"，猜一个只会让
// personalPolicy 作用在一批猜错的设备上。
func TestEnrollDeviceDefaultsToEnterpriseAsset(t *testing.T) {
	s := openTestStore(t)
	d, created, err := s.EnrollDevice(context.Background(), "li.fang", "FP-NEW", "MBP", "macOS", DeviceBindAuto)
	if err != nil || !created {
		t.Fatalf("登记失败: %v %v", created, err)
	}
	if d.AssetClass != AssetClassEnterprise {
		t.Fatalf("新设备应默认企业资产, got %q", d.AssetClass)
	}
	if len(d.Tags) != 0 {
		t.Fatalf("新设备不应带标签, got %#v", d.Tags)
	}
}

// 设备再次上报不得把管理员标注的分类冲掉——与「状态一律不动」同一条纪律：
// 否则 personalPolicy 会被一次 posture 上报静默解除。
func TestEnrollDeviceKeepsAssetClass(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	d, _, _ := s.EnrollDevice(ctx, "li.fang", "FP-KEEP", "MBP", "macOS", DeviceBindAuto)
	if _, _, err := s.SetDeviceAsset(ctx, d.ID, AssetClassPersonal, []string{"自带"}); err != nil {
		t.Fatalf("标注失败: %v", err)
	}
	again, created, err := s.EnrollDevice(ctx, "li.fang", "FP-KEEP", "MBP", "macOS", DeviceBindAuto)
	if err != nil || created {
		t.Fatalf("二次登记不应 created: %v %v", created, err)
	}
	if again.AssetClass != AssetClassPersonal {
		t.Fatalf("上报不得把分类冲回企业资产, got %q", again.AssetClass)
	}
	if len(again.Tags) != 1 || again.Tags[0] != "自带" {
		t.Fatalf("上报不得清掉标签, got %#v", again.Tags)
	}
}

// SetDeviceAsset 拒收非法分类（不静默归一）：页面选了个人资产、库里躺着企业资产
// 而接口回 200，是本项目最不能接受的那种"设置了但没生效"。
func TestSetDeviceAssetRejectsUnknownClass(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	d, _, _ := s.EnrollDevice(ctx, "li.fang", "FP-BAD", "", "macOS", DeviceBindAuto)
	if _, _, err := s.SetDeviceAsset(ctx, d.ID, "byod", nil); err == nil {
		t.Fatal("非法分类必须报错，不得静默兜成 enterprise")
	}
	after, _, _ := s.DeviceByFingerprint(ctx, "li.fang", "FP-BAD")
	if after.AssetClass != AssetClassEnterprise {
		t.Fatalf("失败的写入不得改动库里的值, got %q", after.AssetClass)
	}
}

// 标签归一：去空白、丢空串、去重、逐个截长、截到数量上限，且恒非 nil。
func TestNormalizeDeviceTags(t *testing.T) {
	got := NormalizeDeviceTags([]string{" 研发 ", "研发", "", "  ", "财务"})
	if len(got) != 2 || got[0] != "研发" || got[1] != "财务" {
		t.Fatalf("去空去重保序失败: %#v", got)
	}
	long := strings.Repeat("标", DeviceTagMaxRunes+10)
	if g := NormalizeDeviceTags([]string{long}); len([]rune(g[0])) != DeviceTagMaxRunes {
		t.Fatalf("超长标签应截到 %d 字, got %d", DeviceTagMaxRunes, len([]rune(g[0])))
	}
	many := make([]string, DeviceTagMaxCount+5)
	for i := range many {
		many[i] = string(rune('a' + i))
	}
	if g := NormalizeDeviceTags(many); len(g) != DeviceTagMaxCount {
		t.Fatalf("标签数应截到 %d, got %d", DeviceTagMaxCount, len(g))
	}
	if g := NormalizeDeviceTags(nil); g == nil {
		t.Fatal("空输入应回空切片而不是 nil（JSON 里是 [] 而不是 null）")
	}
}

// 坏 JSON 不得让读取失败：标签没有执行方，一条坏值不该把 DeviceByFingerprint
// 打成错误——那一步在 strict 准入下的失败方向是拒绝接入。
func TestParseDeviceTagsToleratesGarbage(t *testing.T) {
	for _, raw := range []string{"", "   ", "{", "null", `"not-an-array"`} {
		if got := ParseDeviceTags(raw); len(got) != 0 {
			t.Fatalf("坏值 %q 应回空集合, got %#v", raw, got)
		}
	}
	if got := ParseDeviceTags(`["a","a","b"]`); len(got) != 2 {
		t.Fatalf("读出来也要过一遍归一: %#v", got)
	}
}

// managed（企业纳管个人）按企业资产处理——它的语义就是"个人设备但已纳管"，
// 纳管完成后仍按 BYOD 收紧的话，「纳管」这个动作就没有了结果。
func TestIsPersonalAssetOnlyCoversPersonal(t *testing.T) {
	if !IsPersonalAsset(AssetClassPersonal) {
		t.Fatal("personal 必须受个人资产策略约束")
	}
	for _, c := range []string{AssetClassEnterprise, AssetClassManaged, "", "拼错的值"} {
		if IsPersonalAsset(c) {
			t.Fatalf("%q 不该被当成个人资产（脏值兜底方向必须是企业资产）", c)
		}
	}
}

// 准入设置的默认值与兜底：旧库里根本没有 personalPolicy 这个键，读出来是空串，
// 必须收敛成 inherit（= 行为不变），而不是任何一档收紧的取值。
func TestDeviceTrustSettingPersonalPolicyDefaults(t *testing.T) {
	if DefaultDeviceTrustSetting().PersonalPolicy != PersonalPolicyInherit {
		t.Fatal("默认个人资产策略必须是 inherit")
	}
	for _, in := range []string{"", "deny-all", "strict "} {
		st := DeviceTrustSetting{Mode: DeviceTrustStrict, PersonalPolicy: in}.Normalize()
		if st.PersonalPolicy != PersonalPolicyInherit {
			t.Fatalf("脏值 %q 应兜成 inherit, got %q", in, st.PersonalPolicy)
		}
	}
	st := DeviceTrustSetting{Mode: DeviceTrustObserve, PersonalPolicy: PersonalPolicyDeny}.Normalize()
	if st.PersonalPolicy != PersonalPolicyDeny {
		t.Fatalf("合法值必须原样保留, got %q", st.PersonalPolicy)
	}
}
