package api

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"baidi.dev/control/internal/store"
)

// 审计类别字典的**覆盖性**回归。
//
// ★这条测试是为一个已经发生过的缺陷立的：`policy` 这个类别有四个真实写入点
// （保存接入策略 / 设置网关对外接入地址 / 保存安全基线 / 删除安全基线），
// 记录逐条落进了 audit_log，但它
//
//	· 不在审计中心的任何一张类别卡里（卡片求和比库里的总行数少），
//	· 按它检索直接 400「未知的审计类别：policy」，
//	· 在态势总览里被并进了「策略变更」而与审计中心的分格对不上。
//
// 三处各抄了一份清单，谁也没错到会报错的程度——写进去了，就是查不出来。
//
// 现在字典只有 store.AuditCategories 一份，这条测试直接扫源码里的**写入点**，
// 保证「能写进去的类别」一定「查得出来」。加一个新类别却忘了进字典，这里当场红。
func TestAuditCategoriesCoverWrites(t *testing.T) {
	// 匹配 s.audit / s.auditAs / s.auditBG 的类别实参（紧跟在 request/actor 之后的那个字面量）。
	re := regexp.MustCompile(`\.audit(?:As|BG)?\([^,)]+,\s*(?:[^,)]+,\s*)?"([a-z]+)"`)
	found := map[string]string{} // 类别 → 第一次出现的位置

	roots := []string{".", filepath.Join("..", "store")}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("读 %s: %v", root, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(root, name))
			if err != nil {
				t.Fatalf("读 %s: %v", name, err)
			}
			for _, m := range re.FindAllStringSubmatch(string(b), -1) {
				if _, seen := found[m[1]]; !seen {
					found[m[1]] = filepath.Join(root, name)
				}
			}
		}
	}
	if len(found) < 4 {
		// 正则失配时这条测试会静默变成"什么都没检查"——那比没有测试更坏。
		t.Fatalf("只扫到 %d 个审计写入类别（%v），正则大概率已经和代码写法脱节，请修正正则而不是放宽这个下限", len(found), found)
	}

	var missing []string
	for cat, where := range found {
		if !store.ValidAuditCategory(cat) {
			missing = append(missing, cat+"（写于 "+where+"）")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("这些审计类别写得进库、却不在 store.AuditCategories 字典里，"+
			"于是在审计中心既数不到也筛不到：%s", strings.Join(missing, "、"))
	}
}

// 字典本身的自洽：键唯一、中文名唯一、都非空。
// 中文名重复会让两张类别卡长得一模一样，而它们统计的是不同的记录。
func TestAuditCategoryDictionaryWellFormed(t *testing.T) {
	keys, labels := map[string]bool{}, map[string]bool{}
	for _, c := range store.AuditCategories {
		if c.Key == "" || c.Label == "" {
			t.Fatalf("字典项不能有空值：%+v", c)
		}
		if keys[c.Key] {
			t.Fatalf("类别键重复：%s", c.Key)
		}
		if labels[c.Label] {
			t.Fatalf("类别中文名重复：%s（两张卡会长得一样，统计的却是不同记录）", c.Label)
		}
		keys[c.Key], labels[c.Label] = true, true
		if !store.ValidAuditCategory(c.Key) || store.AuditCategoryZh(c.Key) != c.Label {
			t.Fatalf("字典与查询函数不一致：%s", c.Key)
		}
	}
	// 不在字典里的键原样返回（页面稳定降级，而不是显示空白）。
	if store.AuditCategoryZh("no-such-cat") != "no-such-cat" {
		t.Fatal("未知类别应原样返回键")
	}
}
