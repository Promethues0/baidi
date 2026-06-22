/**
 * 策略服务 · GET /api/policies（zhulong-control）。
 * 控制面策略的 cond 已是结构化对象（mfa/posture/workhours），与 policy-store 的
 * Cond 直通，无需转换；netmap 求值引擎可直接消费。
 */
import { getJSON } from './http';
import type { Pol, Cond } from '@/policy-store';

interface PolicyDTO {
  id: string;
  subjects: string[];
  resources: string[];
  action: 'allow' | 'deny';
  cond: Cond;
  modes: string;
  hits: number;
  enabled: boolean;
}

export async function listPolicies(): Promise<Pol[]> {
  const rows = await getJSON<PolicyDTO[]>('/api/policies');
  return rows.map((p) => ({
    id: p.id,
    subjects: p.subjects,
    resources: p.resources,
    action: p.action,
    cond: p.cond ?? {},
    modes: p.modes,
    hits: p.hits ?? 0,
    enabled: p.enabled
  }));
}
