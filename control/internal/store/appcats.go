package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ── 应用分类字典（app_categories 表）──
//
// 改造前分类是 sqlite.go 里的两个包级变量（catLabels / catOrder）：没有表、没有 CRUD、
// 没有任何入口，管理员既加不了也改不了——「应用分类」这一栏在页面上看起来是数据，
// 实际上是编译进二进制的常量。现在它是一张真实的表，Apps() 的分类栏由表构建，
// 那两个常量已删除：留着就会变成第二个真相来源（管理员改了库、筛选条仍按常量排序与显示）。

// AppCategoryDef 应用分类字典的一行。
//
// 与 AppCategory（应用页筛选条目）刻意分成两个类型：后者含一个不入表的合成项
// 「全部应用」，若共用一个结构体，那一项就会带着 sort/builtin 两个对它毫无意义的字段
// 出现在同一个数组里，读的人分不清哪几行是库里真有的。
type AppCategoryDef struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Sort  int    `json:"sort"`
	// Builtin 内置分类：可改名、可排序，**不可删**（key 被种子应用的 apps.category 引用，
	// 也是 backfillAppCategories 的回填清单）。内置行只由回填产生，REST 建不出来。
	Builtin bool `json:"builtin"`
	// Count 当前归属该分类的应用数。删除守卫判的就是这个数，页面上显示的也是它——
	// 同一个事实两处不同源的话，管理员会看到「显示 0 个应用却删不掉」。
	Count int `json:"count"`
}

// AppCategoryAllKey / AppCategoryAllLabel 应用页「全部应用」筛选项。
//
// ★它是 Apps() 现拼的**合成项，不入表**：真入表的话它会有自己的 count（只统计
// category='all' 的应用，恒为 0），而筛选条上同一个位置本该显示应用总数——
// 两个语义撞在同一个 key 上。所以 all 是建分类时的保留字，直接拒收。
const (
	AppCategoryAllKey   = "all"
	AppCategoryAllLabel = "全部应用"
)

// AppCategoryLabelMaxRunes 分类名长度上界（字符）。
//
// ★与 DeviceNameMaxRunes 同一个数不是巧合：两者都是「管理员手输、落库、随列表
// 原样回显」的短文本，两个入口两套标准的话，同一份界面上会出现一处能存 64 字、
// 另一处能存 200 字的分裂。超长一律**拒绝**而不是截断（管理员看得到错误提示，
// 截断只会让他以为存进去了）。
const AppCategoryLabelMaxRunes = 64

// appCategoryKeyMaxLen 分类 key 长度上界（字节，key 限定 ASCII 故与字符数等价）。
const appCategoryKeyMaxLen = 32

// appCategoryKeyRe 分类 key 格式：小写字母数字，连字符只能出现在中间。
// key 会进 URL 路径（DELETE /app-categories/{key}）也会进 apps.category，
// 收紧到这个字符集是为了让它在两处都不需要转义。
var appCategoryKeyRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

var (
	// ErrAppCategoryExists key 已被占用。★upsert 式「保存」在这里是错的：
	// 建分类时打错一个已存在的 key，会静默把那个分类改名，而管理员以为自己新建了一个。
	ErrAppCategoryExists   = errors.New("分类 key 已存在")
	ErrAppCategoryNotFound = errors.New("分类不存在")
	ErrAppCategoryBuiltin  = errors.New("内置分类不可删除（可以改名与调整排序）")
	ErrAppCategoryKey      = fmt.Errorf("分类 key 只能由小写字母、数字与中间的连字符组成，长度 ≤%d，且不能是保留字 %q", appCategoryKeyMaxLen, AppCategoryAllKey)
	ErrAppCategoryLabel    = fmt.Errorf("分类名称必填且 ≤%d 字", AppCategoryLabelMaxRunes)
	// ErrUnknownAppCategory 发布应用时给了一个字典里不存在的分类。
	// ★不校验的后果是静默的：该应用在筛选条的**任何一栏都不出现**（只有「全部应用」
	// 能看到），而 POST /apps 照回 201。
	ErrUnknownAppCategory = errors.New("category 必须是应用分类字典里已存在的 key")
)

// ErrAppCategoryInUse 分类下仍有应用，拒删（带数量，让管理员知道还要挪几个）。
// 刻意不做级联置空：静默失去分类归属 = 这些应用从筛选条上消失，而没有任何提示。
type ErrAppCategoryInUse struct {
	Key  string
	Apps int
}

func (e ErrAppCategoryInUse) Error() string {
	return fmt.Sprintf("分类「%s」下仍有 %d 个应用，请先把这些应用改到别的分类", e.Key, e.Apps)
}

// builtinAppCategories 内置分类清单。
//
// ★这是内置分类**唯一**一份定义：Memory 降级种子与 backfillAppCategories 都从这里取。
// 两处各写一份的话，回填出来的库与未连后端时的演示数据会在 label 上分家，
// 而那种分家只有把后端停掉再对比才看得出来。
//
// sort 留 10 的间隔纯粹是给人看的（界面上的排序用 ↑↓ 两两交换，不依赖间隔）。
func builtinAppCategories() []AppCategoryDef {
	return []AppCategoryDef{
		{Key: "office", Label: "办公协同", Sort: 10, Builtin: true},
		{Key: "finance", Label: "财务高敏", Sort: 20, Builtin: true},
		{Key: "dev", Label: "研发运维", Sort: 30, Builtin: true},
		{Key: "global", Label: "全网资源", Sort: 40, Builtin: true},
	}
}

// normalizeAppCategory 规范化 + 校验 key 与 label。
//
// 放在 store 而不是 handler：REST 不是唯一写入口（回填也写这张表），而 key 的格式
// 约束是这一列的**数据契约**，不该由某一个调用方代管。
func normalizeAppCategory(c AppCategoryDef) (AppCategoryDef, error) {
	c.Key = strings.ToLower(strings.TrimSpace(c.Key))
	c.Label = strings.TrimSpace(c.Label)
	if c.Key == "" || len(c.Key) > appCategoryKeyMaxLen ||
		c.Key == AppCategoryAllKey || !appCategoryKeyRe.MatchString(c.Key) {
		return AppCategoryDef{}, ErrAppCategoryKey
	}
	if err := checkAppCategoryLabel(c.Label); err != nil {
		return AppCategoryDef{}, err
	}
	return c, nil
}

func checkAppCategoryLabel(label string) error {
	if label == "" || len([]rune(label)) > AppCategoryLabelMaxRunes {
		return ErrAppCategoryLabel
	}
	return nil
}

// AppCategories 降级演示种子：内置四类 + 种子应用的现算计数。
func (m *Memory) AppCategories(ctx context.Context) ([]AppCategoryDef, error) {
	counts, _, err := m.appCounts(ctx)
	if err != nil {
		return nil, err
	}
	defs := builtinAppCategories()
	for i := range defs {
		defs[i].Count = counts[defs[i].Key]
	}
	return defs, nil
}

// appCounts 种子应用按分类的计数 + 总数。
func (m *Memory) appCounts(ctx context.Context) (map[string]int, int, error) {
	b, err := m.Apps(ctx)
	if err != nil {
		return nil, 0, err
	}
	counts := map[string]int{}
	for _, a := range b.Apps {
		counts[a.Category]++
	}
	return counts, len(b.Apps), nil
}
