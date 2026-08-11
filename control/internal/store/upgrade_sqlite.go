package store

import (
	"context"
	"encoding/json"

	"baidi.dev/control/internal/upgrade"
)

// 升级管理的持久化（PRD 第 4 章）。
//
// 灰度计划与升级规则都是**单例配置**（每个平台一条计划 / 全局一份规则），
// 量小且总是整体读写，故直接复用 settings 表存 JSON，不另建表——
// 为一份配置建一张只会有一行的表，反而多一处 schema 要维护。
// 与之相对，NAT 策略、告警规则那种「条目会增长、要按条件查询」的才建表。

const (
	grayPlansKey    = "upgrade.gray.plans.v1"
	upgradeRulesKey = "upgrade.rules.v1"
)

// GrayPlans 读全部平台的灰度计划。没配过时返回空切片而非 nil ——
// 前端 v-for 对 nil 与 [] 表现一致，但 JSON 里 null 与 [] 不同，
// 让前端多写一处 ?? [] 是无谓的。
func (s *SQLiteStore) GrayPlans(ctx context.Context) ([]upgrade.GrayPlan, error) {
	raw, ok, err := s.Setting(ctx, grayPlansKey)
	if err != nil || !ok || raw == "" {
		return []upgrade.GrayPlan{}, err
	}
	var out []upgrade.GrayPlan
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		// 坏数据不该让整页打不开，但也绝不能静默当成「没有灰度」——
		// 那会让一批本该拿新版本的终端悄悄退回稳定版。
		return nil, err
	}
	if out == nil {
		out = []upgrade.GrayPlan{}
	}
	return out, nil
}

// SaveGrayPlan 保存/覆盖某平台的灰度计划；Version 为空即删除该平台的计划。
func (s *SQLiteStore) SaveGrayPlan(ctx context.Context, p upgrade.GrayPlan) ([]upgrade.GrayPlan, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	plans, err := s.GrayPlans(ctx)
	if err != nil {
		return nil, err
	}
	next := make([]upgrade.GrayPlan, 0, len(plans)+1)
	for _, old := range plans {
		if old.Platform != p.Platform {
			next = append(next, old)
		}
	}
	if p.Version != "" {
		next = append(next, p)
	}
	b, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	if err := s.SetSetting(ctx, grayPlansKey, string(b)); err != nil {
		return nil, err
	}
	return next, nil
}

// UpgradeRules 读升级校验规则；没配过时回出厂规则。
func (s *SQLiteStore) UpgradeRules(ctx context.Context) (upgrade.Rules, error) {
	raw, ok, err := s.Setting(ctx, upgradeRulesKey)
	if err != nil || !ok || raw == "" {
		return upgrade.DefaultRules(), err
	}
	r := upgrade.DefaultRules()
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		// 规则读不出来时**回出厂规则**（禁降级 + 要求组件一致），而不是回零值。
		// 零值的 Rules{} 是 AllowDowngrade=false 但 RequireComponentMatch=false，
		// 看起来无害，实际是把一道校验静默关掉了。
		return upgrade.DefaultRules(), err
	}
	return r, nil
}

func (s *SQLiteStore) SaveUpgradeRules(ctx context.Context, r upgrade.Rules) error {
	// 规则里的版本号先校验：坏规则在判定时会被跳过（见 CheckUpgrade 的注释），
	// 结果是管理员以为配了一条强制链路、实际它从不生效。
	for _, h := range r.Hops {
		if _, err := upgrade.ParseVersion(h.Below); err != nil {
			return err
		}
		if _, err := upgrade.ParseVersion(h.Next); err != nil {
			return err
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, upgradeRulesKey, string(b))
}

// UpgradeStore 升级配置的读写口（独立接口，不进 Store）。
type UpgradeStore interface {
	GrayPlans(ctx context.Context) ([]upgrade.GrayPlan, error)
	SaveGrayPlan(ctx context.Context, p upgrade.GrayPlan) ([]upgrade.GrayPlan, error)
	UpgradeRules(ctx context.Context) (upgrade.Rules, error)
	SaveUpgradeRules(ctx context.Context, r upgrade.Rules) error
}
