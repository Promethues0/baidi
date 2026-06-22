/**
 * 审计服务 · GET /api/audit/events（zhulong-control）。
 * 控制面 emitAudit 实时落库的真事件（登录认证/策略变更/配置变更/访问决策），
 * 统一 schema（ZL-FR-109）；访问决策含自适应信任/风险分与 allow/step-up/deny。
 */
import { getJSON } from './http';

export interface AuditRow {
  seq?: string;
  ts: string;
  category: string;
  actor: string;
  device?: string;
  resource?: string;
  mode?: string;
  decision: string; // allow | step-up | deny | success | fail
  policy?: string;
  action?: string;
  detail?: string;
  source?: string;
  trust?: number;
  risk?: number;
  // 前端派生（兼容旧视图逻辑）
  kind: string; // access | admin | config | auth
  note: string;
}

function kindOf(cat: string): string {
  return cat === '访问决策' ? 'access' : cat === '策略变更' ? 'admin' : cat === '配置变更' ? 'config' : 'auth';
}

export async function listAuditEvents(limit = 200): Promise<AuditRow[]> {
  const rows = await getJSON<any[]>(`/api/audit/events?limit=${limit}`);
  return rows.map((e) => ({ ...e, kind: kindOf(e.category), note: e.detail || '' }));
}
