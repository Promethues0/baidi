/** 白帝移动客户端 · HTTP 客户端。dev 经 vite /api 反代到 baidi-control(:8090)；
 *  原生壳打包后由 __BAIDI_NATIVE__.apiBase 提供控制中心地址（生产按下发配置）。 */
import { session, config } from './store';

// 控制中心地址优先级：原生壳注入 apiBase → 「我的」页配置 control → 空（dev 走 vite /api 代理）。
function origin(): string {
  const nb = (window as unknown as { __BAIDI_NATIVE__?: { apiBase?: string } }).__BAIDI_NATIVE__;
  return (nb?.apiBase || config.control || '').replace(/\/+$/, '');
}
function apiBase(): string {
  return origin() + '/api/v1';
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(apiBase() + path, {
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

/** 控制中心连通性探测（命中 /healthz，免认证）。 */
export async function ping(): Promise<boolean> {
  try {
    const res = await fetch(origin() + '/healthz', { headers: { Accept: 'application/json' } });
    return res.ok;
  } catch {
    return false;
  }
}

/* 与门户端点同构（移动端以 user 身份登录、拉取可访问应用） */
export interface PortalLoginResp { ok: boolean; needMfa?: boolean; reason?: string; token?: string; displayName?: string }
export interface PortalTile { id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string; sensitivity: 'normal' | 'high'; accessible: boolean }
export interface PortalAppsResp { apps: PortalTile[] }
