/**
 * 共享状态/判定映射（一致性收敛）：消除各视图重复的 badge/text helper。
 * 统一返回 { label, badge }，badge 为全局 zl-badge--* 类（非 scoped，可跨组件复用）。
 * 各页保留薄包装（const badge = s => gwStatus(s).badge）即可，模板无需改动。
 */
export interface StatusMeta {
  label: string;
  badge: string;
}

const idle = (k?: string): StatusMeta => ({ label: k || '—', badge: 'zl-badge--idle' });

/** 访问/审计判定：allow/step-up/deny/success/fail */
const DECISION: Record<string, StatusMeta> = {
  allow: { label: '允许', badge: 'zl-badge--ok' },
  'step-up': { label: '二次鉴权', badge: 'zl-badge--warn' },
  deny: { label: '拒绝', badge: 'zl-badge--danger' },
  success: { label: '成功', badge: 'zl-badge--ok' },
  fail: { label: '失败', badge: 'zl-badge--danger' }
};
export const decision = (k?: string): StatusMeta => DECISION[k ?? ''] ?? idle(k);

/** 网关运行状态：online/degraded/offline */
const GATEWAY: Record<string, StatusMeta> = {
  online: { label: '在线', badge: 'zl-badge--ok' },
  degraded: { label: '降级', badge: 'zl-badge--warn' },
  offline: { label: '离线', badge: 'zl-badge--danger' }
};
export const gwStatus = (k?: string): StatusMeta => GATEWAY[k ?? ''] ?? idle(k);

/** IPSec SA / 隧道状态：established/connecting/down */
const SA: Record<string, StatusMeta> = {
  established: { label: '已建立', badge: 'zl-badge--ok' },
  connecting: { label: '协商中', badge: 'zl-badge--warn' },
  down: { label: '断开', badge: 'zl-badge--danger' }
};
export const saStatus = (k?: string): StatusMeta => SA[k ?? ''] ?? idle(k);
