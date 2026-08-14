package store

import (
	"context"
	"testing"
	"time"
)

// ClassifyIdle：可解析走 last_login、占位符走 created_at 兜底、都不可解析不判闲置。
func TestClassifyIdle(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.Local)
	cases := []struct {
		name, ll, ca string
		wantDays     int
		wantNever    bool
		wantHit      bool
	}{
		{"标准布局命中", "2026-06-01 10:00:00", "2026-01-01 00:00:00", 74, false, true},
		{"种子无秒布局", "2026-06-22 19:42", "2026-01-01", 52, false, true},
		{"新近登录不命中", "2026-08-10 09:00:00", "2026-01-01", 4, false, false},
		{"占位符走建号兜底", "—", "2026-03-01 00:00:00", 166, true, true},
		{"建号新近不命中", "—", "2026-08-13 00:00:00", 1, true, false},
		{"都解析不出→不可判定不算闲置", "—", "", -1, true, false},
	}
	for _, c := range cases {
		days, never, hit := ClassifyIdle(c.ll, c.ca, now, 30)
		if days != c.wantDays || never != c.wantNever || hit != c.wantHit {
			t.Errorf("%s: got (%d,%v,%v) want (%d,%v,%v)", c.name, days, never, hit, c.wantDays, c.wantNever, c.wantHit)
		}
	}
}

// IdleAccounts：种子库 30 天阈值应命中 4 个 active 老账号；非 active 状态不列；
// 新建号（created_at=今天）不列；排序最闲在前。
func TestIdleAccountsSeeded(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	list, err := s.IdleAccounts(ctx, 30)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]IdleAccount{}
	for _, a := range list {
		got[a.Account] = a
	}
	for _, want := range []string{"zhang.wei", "li.fang", "wang.qiang", "liu.yang"} {
		if _, ok := got[want]; !ok {
			t.Errorf("应命中 %s，实得 %v", want, list)
		}
	}
	for _, not := range []string{"zhao.min", "ext.zhou", "chen.jing", "admin"} {
		if _, ok := got[not]; ok {
			t.Errorf("%s 不应在清单（非 active 或建号新近）", not)
		}
	}
	if !got["zhang.wei"].IsAdmin {
		t.Error("zhang.wei 应标记为管理员")
	}
	if got["li.fang"].NeverRecorded {
		t.Error("li.fang 有可解析的登录记录，不应标 NeverRecorded")
	}
	// 排序：IdleDays 单调不增
	for i := 1; i < len(list); i++ {
		if list[i].IdleDays > list[i-1].IdleDays {
			t.Fatalf("应按闲置天数降序，实得 %v", list)
		}
	}
	// 高阈值一个都不该命中
	if none, _ := s.IdleAccounts(ctx, 3650); len(none) != 0 {
		t.Errorf("3650 天阈值不应命中任何账号，实得 %v", none)
	}
}
