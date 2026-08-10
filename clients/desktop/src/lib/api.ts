/** 白帝桌面客户端 · HTTP 客户端。dev 经 vite /api 反代；Tauri 打包后无代理，直连配置的控制中心。 */
import { session, config } from './store';

function inTauri(): boolean {
  return typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}
// 打包后 webview origin 是 tauri://localhost，没有 vite /api 代理 → 直连「设置」里配置的控制中心
// （默认 http://127.0.0.1:8090）。控制中心 CORS=* 且放行 OPTIONS。dev 浏览器走 vite 代理（ORIGIN=''）。
function origin(): string { return inTauri() ? config.control.replace(/\/+$/, '') : ''; }

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  // headers 必须在 ...rest 之后合并：否则调用方传入 headers 会把 Authorization 整体顶掉（静默 401）
  const { headers: extra, ...rest } = init ?? {};
  const res = await fetch(origin() + '/api/v1' + path, {
    ...rest,
    headers: {
      Accept: 'application/json',
      ...(session.token ? { Authorization: `Bearer ${session.token}` } : {}),
      ...(extra ?? {})
    }
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
export interface PortalTile {
  id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string;
  sensitivity: 'low' | 'normal' | 'high';
  accessible: boolean;
  /** 因终端风险降权而不可访问（而非缺授权）。此时提交访问申请无效——降权否决压过 JIT 授予，
   *  用户该做的是修复终端环境。两种"不可访问"的下一步动作完全不同，提示语必须区分。 */
  degraded?: boolean;
}
export interface PortalAppsResp { apps: PortalTile[] }

/* ── 接入剖面（GET /api/v1/client/profile）──
 * 控制面一次性下发「网关落点 + 该接管哪些网段 + 哪个地址对应哪个资源」。
 * 客户端不再自己猜网段：此前默认接管 10.99.0.0/24，而业务真实地址是 10.20.1.10，
 * 于是隧道建起来了、点开应用却完全不走隧道——这正是「连上了但没用」的根因。
 */
export interface ProfileGateway {
  host: string; spaPort: string; proxyPort: string;
  /** 网关隧道证书 SHA-256 指纹：客户端据此钉扎，把「加密」补成「加密 + 认证」。 */
  tunnelPin: string;
  /** 网关是否在心跳新鲜期内。false = 以下地址是回退默认值，接入很可能失败。 */
  online: boolean;
}
export interface ProfileApp {
  id: string; name: string; mode: 'tunnel' | 'web' | 'global';
  sensitivity: 'low' | 'normal' | 'high';
  resourceId: string;
  backend: string;   // 业务真实 host:port
  vip: string;       // 控制面分配的虚拟 IP（稳定，可安全收藏）
  port: number;
  url: string;       // 「点开即用」地址：web 给 http(s)://，其余给 host:port
  accessible: boolean;
  /** 该资源此刻因终端风险降权被暂停访问（高敏资源 + 本机判定 degrade）。
   *  降权只摘高敏资源，隧道与普通资源照常——具体原因见剖面 warnings 第一条。 */
  degraded?: boolean;
}
/**
 * 客户端分离式 DNS（split-DNS）配置。
 *
 * 在此之前客户端**只按 IP 路由**：管理员配一个 oa.corp.internal:8080 的应用，
 * 客户端完全不接管它，流量直连内网且没有任何提示——企业业务几乎都靠域名访问，
 * 这正是「配了却不生效」里最难归因的一种。
 */
export interface ProfileDNS {
  /** 隧道内解析器的 VIP（如 10.99.0.53）。它本身也必须在 routes 里，否则查询包不进隧道。 */
  server: string;
  /**
   * 需要交给隧道内解析器的搜索域（如 ["corp.internal"]）。
   * ★只按域分流、不全局接管：全局接管会让所有 DNS 走隧道，隧道一断全网解析全挂。
   */
  domains: string[];
  /** FQDN（小写、不带尾点）→ VIP。客户端解析器据此直接作答，不做递归转发。 */
  records: Record<string, string>;
}
export interface ClientProfile {
  generatedAt: string;
  user: string;
  gateway: ProfileGateway;
  vipCidr: string;
  tunIp: string;
  routes: string[];              // 需接管进隧道的网段
  apps: ProfileApp[];
  resmap: Record<string, string>; // "host:port" → 资源 id
  /** 分离式 DNS 配置。可选：老版本控制面不下发，此时域名类业务退回不接管（行为同以前）。 */
  dns?: ProfileDNS;
  warnings?: string[];            // 配置缺口（应用未关联资源、网关离线…），应显著提示
}

export function fetchProfile(): Promise<ClientProfile> {
  return api<ClientProfile>('/client/profile');
}
