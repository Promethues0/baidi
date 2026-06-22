/**
 * 主动防御流水线共享处置动作映射（一致性收敛）：消除 DefensePolicy / DefenseCorrelate
 * 各自一套 actLabel+actClass 的三套不一致定义（尤其修掉 lock 在两页 danger/warn 打架）。
 * 与 lib/status.ts 同范式：返回 { label, badge }，badge 为全局 zl-badge--* 类（非 scoped）。
 * 流水线：主动防御(单会话检测) → 关联规则(跨事件聚合) → IP 信誉名单(自动加黑)。
 */
export interface ActionMeta {
  label: string;
  badge: string;
}

// 处置动作全集（各页取适用子集）。严重度递增：alert < stepup < logout < lock < blacklist；
// quarantine（关联规则专用）与 lock 同危险级。
const ACTION: Record<string, ActionMeta> = {
  alert: { label: '告警', badge: 'zl-badge--idle' },
  stepup: { label: '二次鉴权', badge: 'zl-badge--accent' },
  logout: { label: '强制下线', badge: 'zl-badge--warn' },
  lock: { label: '锁定账号', badge: 'zl-badge--danger' },
  blacklist: { label: '加入黑名单', badge: 'zl-badge--danger' },
  quarantine: { label: '隔离', badge: 'zl-badge--danger' }
};

// 审计链通用判定别名（DefensePolicy 威胁事件 decision 列复用 allow/deny/step-up）。
const DECISION_ALIAS: Record<string, ActionMeta> = {
  allow: { label: '允许', badge: 'zl-badge--ok' },
  deny: { label: '拒绝', badge: 'zl-badge--danger' },
  'step-up': { label: '二次鉴权', badge: 'zl-badge--accent' }
};

const idle = (k?: string): ActionMeta => ({ label: k || '—', badge: 'zl-badge--idle' });

export const defenseAction = (k?: string): ActionMeta => ACTION[k ?? ''] ?? DECISION_ALIAS[k ?? ''] ?? idle(k);

// a-select 选项（纯中文 label，与 DefensePolicy 一致）。
export interface ActionOption {
  value: string;
  label: string;
}
export const defenseActionOptions = (keys: string[]): ActionOption[] =>
  keys.map((v) => ({ value: v, label: ACTION[v]?.label ?? v }));
