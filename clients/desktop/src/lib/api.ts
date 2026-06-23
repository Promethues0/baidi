/** 白帝桌面客户端 · HTTP 客户端。经 vite /api 反代到 baidi-control(:8090)；自动携带 Bearer。 */
import { session } from './store';

const BASE = '/api/v1';

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: {
      Accept: 'application/json',
      ...(session.token ? { Authorization: `Bearer ${session.token}` } : {}),
      ...(init?.headers ?? {})
    },
    ...init
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

/** 控制中心连通性探测（真实命中 baidi-control /healthz，开放免认证）。 */
export async function ping(): Promise<boolean> {
  try {
    const res = await fetch('/healthz', { headers: { Accept: 'application/json' } });
    return res.ok;
  } catch {
    return false;
  }
}

/* 与门户端点同构（客户端以 user 身份登录、拉取可访问应用） */
export interface PortalLoginResp { ok: boolean; needMfa?: boolean; reason?: string; token?: string; displayName?: string }
export interface PortalTile { id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string; sensitivity: 'normal' | 'high'; accessible: boolean }
export interface PortalAppsResp { apps: PortalTile[] }
