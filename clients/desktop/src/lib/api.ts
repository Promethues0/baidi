/** 白帝桌面客户端 · HTTP 客户端。dev 经 vite /api 反代；Tauri 打包后无代理，直连配置的控制中心。 */
import { session, config } from './store';

function inTauri(): boolean {
  return typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}
// 打包后 webview origin 是 tauri://localhost，没有 vite /api 代理 → 直连「设置」里配置的控制中心
// （默认 http://127.0.0.1:8090）。控制中心 CORS=* 且放行 OPTIONS。dev 浏览器走 vite 代理（ORIGIN=''）。
function origin(): string { return inTauri() ? config.control.replace(/\/+$/, '') : ''; }

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(origin() + '/api/v1' + path, {
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
    const res = await fetch(origin() + '/healthz', { headers: { Accept: 'application/json' } });
    return res.ok;
  } catch {
    return false;
  }
}

/* 与门户端点同构（客户端以 user 身份登录、拉取可访问应用） */
export interface PortalLoginResp { ok: boolean; needMfa?: boolean; reason?: string; token?: string; displayName?: string }
export interface PortalTile { id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string; sensitivity: 'normal' | 'high'; accessible: boolean }
export interface PortalAppsResp { apps: PortalTile[] }
