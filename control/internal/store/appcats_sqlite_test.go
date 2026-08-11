package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// 应用分类字典：回填、CRUD、唯一与格式、内置保护、删除守卫、Apps() 的分类栏来源。

func catByKey(t *testing.T, defs []AppCategoryDef, key string) AppCategoryDef {
	t.Helper()
	for _, d := range defs {
		if d.Key == key {
			return d
		}
	}
	t.Fatalf("分类 %s 不在字典里: %+v", key, defs)
	return AppCategoryDef{}
}

func appCatByKey(cats []AppCategory, key string) (AppCategory, bool) {
	for _, c := range cats {
		if c.Key == key {
			return c, true
		}
	}
	return AppCategory{}, false
}

// 回填：内置四类建成真实行（builtin=1），顺序与计数取自库。
func TestBackfillAppCategoriesSeedsBuiltins(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	defs, err := s.AppCategories(ctx)
	if err != nil {
		t.Fatalf("AppCategories: %v", err)
	}
	want := []string{"office", "finance", "dev", "global"}
	if len(defs) != len(want) {
		t.Fatalf("回填后应有 %d 个内置分类，得到 %d 个：%+v", len(want), len(defs), defs)
	}
	for i, k := range want {
		if defs[i].Key != k {
			t.Errorf("第 %d 个分类应为 %s，得到 %s（排序应按 sort 升序）", i, k, defs[i].Key)
		}
		if !defs[i].Builtin {
			t.Errorf("%s 应标记为内置", k)
		}
	}
	// 计数来自种子应用：office 2 / finance 1 / dev 2 / global 1
	for k, n := range map[string]int{"office": 2, "finance": 1, "dev": 2, "global": 1} {
		if got := catByKey(t, defs, k).Count; got != n {
			t.Errorf("%s 的应用数应为 %d，得到 %d", k, n, got)
		}
	}
	// 一次性标记必须落下，否则回填会变成每次启动的对账（见 appCatBackfillMarker）。
	if _, done, err := s.Setting(ctx, appCatBackfillMarker); err != nil || !done {
		t.Fatalf("回填标记未落库: done=%v err=%v", done, err)
	}
}

// 回填幂等：重启不复活管理员删掉的分类，也不覆盖他改过的名称与排序。
func TestAppCategoryBackfillSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "appcats.db")

	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("首次打开: %v", err)
	}
	if _, err := s1.CreateAppCategory(ctx, AppCategoryDef{Key: "hr", Label: "人力资源"}); err != nil {
		t.Fatalf("建分类: %v", err)
	}
	if err := s1.DeleteAppCategory(ctx, "hr"); err != nil {
		t.Fatalf("删分类: %v", err)
	}
	if _, _, err := s1.UpdateAppCategory(ctx, "office", "本单位办公", 5); err != nil {
		t.Fatalf("改内置分类: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("关库: %v", err)
	}

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("二次打开: %v", err)
	}
	defer s2.Close() //nolint:errcheck
	defs, err := s2.AppCategories(ctx)
	if err != nil {
		t.Fatalf("AppCategories: %v", err)
	}
	for _, d := range defs {
		if d.Key == "hr" {
			t.Fatal("重启后被删掉的分类不该复活")
		}
	}
	office := catByKey(t, defs, "office")
	if office.Label != "本单位办公" || office.Sort != 5 {
		t.Fatalf("重启后管理员改过的内置分类被回填覆盖了: %+v", office)
	}
	if len(defs) != 4 {
		t.Fatalf("重启后分类数应仍为 4，得到 %d：%+v", len(defs), defs)
	}
}

// 收养历史分类：旧版 POST /apps 不校验 category，库里可能有字典外的自由文本值。
// 不收养的话这批应用在筛选条的任何一栏都不出现。
func TestBackfillAppCategoriesAdoptsLegacyValues(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// 直接落一条带历史分类的应用（绕过 CreateApp 的字典校验，模拟旧版写入），
	// 再清掉一次性标记让回填重跑一遍。legacy_x 带下划线，不满足现在的 key 格式——
	// 收养要照收，校验管的是新写入。
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO apps(id,name,addr,mode,category,node,authed_users,status,created_at,resource_id)
VALUES('a-legacy','旧门户','10.1.1.1:80','web','legacy_x','华东出口',0,'running',?,'')`, nowStr()); err != nil {
		t.Fatalf("插历史应用: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE k=?`, appCatBackfillMarker); err != nil {
		t.Fatalf("清标记: %v", err)
	}
	if err := s.backfillAppCategories(ctx); err != nil {
		t.Fatalf("回填: %v", err)
	}

	defs, err := s.AppCategories(ctx)
	if err != nil {
		t.Fatalf("AppCategories: %v", err)
	}
	legacy := catByKey(t, defs, "legacy_x")
	if legacy.Builtin {
		t.Error("收养进来的历史分类不该是内置的（管理员应能改名与删除）")
	}
	if legacy.Label != "legacy_x" {
		t.Errorf("收养行的名字先用 key 顶着，得到 %q", legacy.Label)
	}
	if legacy.Count != 1 {
		t.Errorf("legacy_x 下应有 1 个应用，得到 %d", legacy.Count)
	}
	// 收养后这个分类在应用页的筛选条上要看得见。
	b, err := s.Apps(ctx)
	if err != nil {
		t.Fatalf("Apps: %v", err)
	}
	if _, ok := appCatByKey(b.Categories, "legacy_x"); !ok {
		t.Fatalf("收养后的分类未出现在筛选条上: %+v", b.Categories)
	}
}

// CRUD：建 → 改名与排序 → 删。
func TestAppCategoryCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	created, err := s.CreateAppCategory(ctx, AppCategoryDef{Key: "hr", Label: "人力资源"})
	if err != nil {
		t.Fatalf("建分类: %v", err)
	}
	if created.Builtin {
		t.Error("REST 建出来的分类不能是内置的——那等于自造一张免死金牌")
	}
	// 新分类排到末尾（内置最大 sort 是 40）
	if created.Sort <= 40 {
		t.Errorf("新分类应排到末尾，得到 sort=%d", created.Sort)
	}

	before, after, err := s.UpdateAppCategory(ctx, "hr", "人力与行政", 15)
	if err != nil {
		t.Fatalf("改分类: %v", err)
	}
	if before.Label != "人力资源" || after.Label != "人力与行政" || after.Sort != 15 {
		t.Fatalf("改前改后不对: before=%+v after=%+v", before, after)
	}
	defs, err := s.AppCategories(ctx)
	if err != nil {
		t.Fatalf("AppCategories: %v", err)
	}
	if got := catByKey(t, defs, "hr"); got.Label != "人力与行政" || got.Sort != 15 {
		t.Fatalf("改名未落库: %+v", got)
	}
	// sort=15 排在 office(10) 与 finance(20) 之间
	if defs[1].Key != "hr" {
		t.Errorf("排序未生效，字典顺序为 %+v", defs)
	}

	if err := s.DeleteAppCategory(ctx, "hr"); err != nil {
		t.Fatalf("删分类: %v", err)
	}
	if defs, err = s.AppCategories(ctx); err != nil {
		t.Fatalf("AppCategories: %v", err)
	}
	for _, d := range defs {
		if d.Key == "hr" {
			t.Fatal("删除后仍在字典里")
		}
	}
	// 不存在的分类：改与删都要能分辨出「不存在」而不是静默成功。
	if _, _, err := s.UpdateAppCategory(ctx, "hr", "人力", 1); !errors.Is(err, ErrAppCategoryNotFound) {
		t.Errorf("改不存在的分类应回 ErrAppCategoryNotFound，得到 %v", err)
	}
	if err := s.DeleteAppCategory(ctx, "hr"); !errors.Is(err, ErrAppCategoryNotFound) {
		t.Errorf("删不存在的分类应回 ErrAppCategoryNotFound，得到 %v", err)
	}
}

// key 唯一 + 格式校验；label 非空且限长。
func TestAppCategoryKeyAndLabelValidation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateAppCategory(ctx, AppCategoryDef{Key: "office", Label: "重名"}); !errors.Is(err, ErrAppCategoryExists) {
		t.Errorf("重复 key 应回 ErrAppCategoryExists，得到 %v", err)
	}
	// 重名尝试不能把既有分类改掉（upsert 式「保存」就会）。
	if got := catByKey(t, mustCats(t, s), "office"); got.Label != "办公协同" {
		t.Fatalf("重复 key 的建分类请求把既有分类改名了: %+v", got)
	}

	for _, bad := range []string{"", "All", "all", "有中文", "under_score", "-lead", "trail-", "a b",
		"aaaaaaaaaabbbbbbbbbbccccccccccddddd"} {
		if _, err := s.CreateAppCategory(ctx, AppCategoryDef{Key: bad, Label: "x"}); !errors.Is(err, ErrAppCategoryKey) {
			t.Errorf("key=%q 应被格式校验拒绝，得到 %v", bad, err)
		}
	}
	// 合法 key 放行（含中间连字符与数字）
	if _, err := s.CreateAppCategory(ctx, AppCategoryDef{Key: "iot-2", Label: "物联网"}); err != nil {
		t.Errorf("合法 key iot-2 应放行，得到 %v", err)
	}

	long := ""
	for i := 0; i <= AppCategoryLabelMaxRunes; i++ {
		long += "长"
	}
	for _, bad := range []string{"", "   ", long} {
		if _, err := s.CreateAppCategory(ctx, AppCategoryDef{Key: "tmp", Label: bad}); !errors.Is(err, ErrAppCategoryLabel) {
			t.Errorf("label=%q 应被拒绝，得到 %v", bad, err)
		}
	}
	if _, _, err := s.UpdateAppCategory(ctx, "office", long, 1); !errors.Is(err, ErrAppCategoryLabel) {
		t.Errorf("改名同样要限长，得到 %v", err)
	}
}

func mustCats(t *testing.T, s *SQLiteStore) []AppCategoryDef {
	t.Helper()
	defs, err := s.AppCategories(context.Background())
	if err != nil {
		t.Fatalf("AppCategories: %v", err)
	}
	return defs
}

// 内置分类：可改名、可排序，不可删。
func TestBuiltinAppCategoryProtection(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, _, err := s.UpdateAppCategory(ctx, "finance", "财务与结算", 1); err != nil {
		t.Fatalf("内置分类应允许改名与排序: %v", err)
	}
	if got := catByKey(t, mustCats(t, s), "finance"); got.Label != "财务与结算" || !got.Builtin {
		t.Fatalf("改名后内置标记应保持: %+v", got)
	}
	for _, k := range []string{"office", "finance", "dev", "global"} {
		if err := s.DeleteAppCategory(ctx, k); !errors.Is(err, ErrAppCategoryBuiltin) {
			t.Errorf("内置分类 %s 应拒删，得到 %v", k, err)
		}
	}
}

// 删除守卫：分类下还有应用一律拒删，且要说清还有几个（不做级联置空）。
func TestDeleteAppCategoryInUse(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if _, err := s.CreateAppCategory(ctx, AppCategoryDef{Key: "hr", Label: "人力资源"}); err != nil {
		t.Fatalf("建分类: %v", err)
	}
	for _, name := range []string{"招聘系统", "考勤系统"} {
		if _, err := s.CreateApp(ctx, App{Name: name, Addr: "10.5.0.1:80", Mode: "web", Category: "hr"}); err != nil {
			t.Fatalf("建应用: %v", err)
		}
	}
	err := s.DeleteAppCategory(ctx, "hr")
	var inUse ErrAppCategoryInUse
	if !errors.As(err, &inUse) {
		t.Fatalf("有应用在用时应拒删，得到 %v", err)
	}
	if inUse.Apps != 2 {
		t.Errorf("应报出仍有 2 个应用，得到 %d", inUse.Apps)
	}
	// 拒删之后分类与应用都还在（不能出现"删了一半"）。
	if got := catByKey(t, mustCats(t, s), "hr"); got.Count != 2 {
		t.Fatalf("拒删后分类应原样保留: %+v", got)
	}
}

// 发布应用时分类必须在字典里：字典外的 key 会让该应用在筛选条上任何一栏都不出现。
func TestCreateAppRejectsUnknownCategory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	for _, bad := range []string{"", "not-exist", "all"} {
		if _, err := s.CreateApp(ctx, App{Name: "x", Addr: "10.0.0.1:80", Mode: "web", Category: bad}); !errors.Is(err, ErrUnknownAppCategory) {
			t.Errorf("category=%q 应被拒绝，得到 %v", bad, err)
		}
	}
	if _, err := s.CreateApp(ctx, App{Name: "新 OA", Addr: "10.0.0.2:80", Mode: "web", Category: "office"}); err != nil {
		t.Fatalf("字典内的分类应放行: %v", err)
	}
}

// Apps() 的分类栏来自表：合成项 all 仍在、改名后应用页跟随、新分类立刻出现。
func TestAppsCategoriesComeFromTable(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	b, err := s.Apps(ctx)
	if err != nil {
		t.Fatalf("Apps: %v", err)
	}
	all, ok := appCatByKey(b.Categories, AppCategoryAllKey)
	if !ok {
		t.Fatal("合成项「全部应用」不该消失——它不入表，但筛选条上必须有")
	}
	if all.Label != AppCategoryAllLabel || all.Count != len(b.Apps) {
		t.Fatalf("全部应用项应显示应用总数: %+v（共 %d 个应用）", all, len(b.Apps))
	}
	if b.Categories[0].Key != AppCategoryAllKey {
		t.Errorf("全部应用应排在首位，得到 %+v", b.Categories)
	}

	// 改名 → 应用页跟随
	if _, _, err := s.UpdateAppCategory(ctx, "dev", "研发与运维", 30); err != nil {
		t.Fatalf("改名: %v", err)
	}
	// 新建分类 → 立刻出现在筛选条上，计数为 0
	if _, err := s.CreateAppCategory(ctx, AppCategoryDef{Key: "hr", Label: "人力资源"}); err != nil {
		t.Fatalf("建分类: %v", err)
	}
	if b, err = s.Apps(ctx); err != nil {
		t.Fatalf("Apps: %v", err)
	}
	dev, ok := appCatByKey(b.Categories, "dev")
	if !ok || dev.Label != "研发与运维" {
		t.Fatalf("分类改名后应用页未跟随: %+v", b.Categories)
	}
	hr, ok := appCatByKey(b.Categories, "hr")
	if !ok || hr.Count != 0 {
		t.Fatalf("新分类应出现在筛选条上且计数为 0: %+v", b.Categories)
	}
	// 筛选条条目数 = 1 个合成项 + 字典行数
	if len(b.Categories) != 1+len(mustCats(t, s)) {
		t.Fatalf("筛选条条目数与字典对不上: %+v", b.Categories)
	}
}

// 「发布应用」与「删除分类」并发：两者绝不能同时成功。
//
// CreateApp 的分类校验与 INSERT 若分成两次自动提交，DeleteAppCategory 的写锁挡不住
// 中间那道缝：A 校验通过（分类还在）→ B 删掉这个此刻确实空着的分类（守卫如实放行）
// → A 的 INSERT 落地，库里就留下一个分类字典外的孤儿应用——它在筛选条的任何一栏都
// 不出现，只有「全部应用」看得到，而接口回的是 201，且 apps 表没有改分类的入口，
// 此后没有任何办法把它救回来。两边都在同一个 immediate 事务里时，结果只能二选一。
func TestCreateAppAndDeleteCategoryAreMutuallyExclusive(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	const rounds = 24
	for i := 0; i < rounds; i++ {
		key := fmt.Sprintf("race-%d", i)
		if _, err := s.CreateAppCategory(ctx, AppCategoryDef{Key: key, Label: "并发用例"}); err != nil {
			t.Fatalf("建分类 %s: %v", key, err)
		}
		var wg sync.WaitGroup
		var createErr, deleteErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, createErr = s.CreateApp(ctx, App{Name: "并发应用", Addr: "10.9.0.1:80", Mode: "web", Category: key})
		}()
		go func() {
			defer wg.Done()
			deleteErr = s.DeleteAppCategory(ctx, key)
		}()
		wg.Wait()

		if createErr == nil && deleteErr == nil {
			t.Fatalf("第 %d 轮：发布与删分类同时成功了——库里已多出一个分类字典外的孤儿应用（category=%s）", i, key)
		}
		// 两者也不该同时失败（没有第三方在抢这把锁）：那说明锁等待被 busy_timeout 打断了，
		// 用例本身就不再有说服力，得先修环境而不是当成通过。
		if createErr != nil && deleteErr != nil {
			t.Fatalf("第 %d 轮：两者都失败了 create=%v delete=%v", i, createErr, deleteErr)
		}
		if createErr != nil && !errors.Is(createErr, ErrUnknownAppCategory) {
			t.Fatalf("第 %d 轮：分类先被删掉时，发布应回 ErrUnknownAppCategory，得到 %v", i, createErr)
		}
		var inUse ErrAppCategoryInUse
		if deleteErr != nil && !errors.As(deleteErr, &inUse) {
			t.Fatalf("第 %d 轮：应用先落库时，删分类应回 ErrAppCategoryInUse，得到 %v", i, deleteErr)
		}
	}

	// 收口断言：无论每一轮是哪一边赢，库里都不该存在字典外的 category。
	var orphans int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM apps WHERE COALESCE(category,'')<>'' AND category NOT IN (SELECT "key" FROM app_categories)`).
		Scan(&orphans); err != nil {
		t.Fatalf("统计孤儿应用: %v", err)
	}
	if orphans != 0 {
		t.Fatalf("库里出现 %d 个分类字典外的应用", orphans)
	}
}
