/** 白帝控制台 · HTTP 客户端。管理 API 经 vite /api 反代到自有后端 baidi-control(:8090)。 */
const BASE = '/api/v1';

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { Accept: 'application/json', ...(init?.headers ?? {}) },
    ...init
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

/* ── 与 baidi-control internal/store.Overview 同构 ── */
export interface KV { name: string; value: number }
export interface DefenseLine { key: string; name: string; risk: number; trend: 'up' | 'down' | 'flat'; top: string[] }
export interface Overview {
  generatedAt: string;
  devices: { online: number; total: number; rate: number };
  users: { total: number; disabled: number; locked: number };
  threats: { rejected: number; failed: number; secondary: number };
  sessions: number;
  auditByKind: KV[];
  verdicts: KV[];
  defense: DefenseLine[];
}
