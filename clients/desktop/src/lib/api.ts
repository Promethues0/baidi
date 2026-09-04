/** 白帝桌面客户端 · HTTP 客户端。dev 经 vite /api 反代；Tauri 打包后无代理，直连配置的控制中心。 */
import { session, config } from './store';

function inTauri(): boolean {
  return typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}
// 打包后 webview origin 是 tauri://localhost，没有 vite /api 代理 → 直连「设置」里配置的控制中心
// （默认 http://127.0.0.1:8090）。控制中心 CORS=* 且放行 OPTIONS。dev 浏览器走 vite 代理（ORIGIN=''）。
function origin(): string { return inTauri() ? config.control.replace(/\/+$/, '') : ''; }

/**
 * 后端**明确拒绝**（HTTP 4xx/5xx，带 httpx.Error 的中文原因）。
 *
 * ★与 NetworkError 分开是有意的，两者该说的话完全相反：前者要原样转述后端那句话，
 *   后者才该去做传输层归因（探 TCP、查地址、导证书）。桌面端此前**没有这个区分**——
 *   api() 一律 `throw new Error(\`${res.status} ${res.statusText}\`)`，连后端 message
 *   都不解，于是 Connect.vue 的 catch 把一次 403 当成"连不上"，交给 explainControl()
 *   去做证书归因。控制台那边（console/src/lib/api.ts）早就有这两个类型了，
 *   桌面端漏掉——同一条纪律只做了一半，而漏掉的这半后果最坏（见 Connect.vue doLogin）。
 */
export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'ApiError';
  }
}

/** 请求压根没到后端（fetch 抛 TypeError：控制面没起 / 网络断 / TLS 被拒 / CORS 拦）。
 *  ★只有这条路径才轮得到 explainControlFailure 那套传输层归因。 */
export class NetworkError extends Error {
  constructor(readonly cause: unknown) {
    super('连不上控制面');
    this.name = 'NetworkError';
  }
}

/** 取后端的错误文案（httpx.Error 的 {"error":{"message":…}}），拿不到才退回状态行。 */
async function errText(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: { message?: string } };
    const msg = body?.error?.message;
    if (msg) return msg;
  } catch { /* 非 JSON 应答（反代 502 之类）：退回状态行 */ }
  return `${res.status} ${res.statusText}`;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  // headers 必须在 ...rest 之后合并：否则调用方传入 headers 会把 Authorization 整体顶掉（静默 401）
  const { headers: extra, ...rest } = init ?? {};
  let res: Response;
  try {
    res = await fetch(origin() + '/api/v1' + path, {
      ...rest,
      headers: {
        Accept: 'application/json',
        ...(session.token ? { Authorization: `Bearer ${session.token}` } : {}),
        ...(extra ?? {})
      }
    });
  } catch (e) {
    throw new NetworkError(e);
  }
  if (!res.ok) throw new ApiError(await errText(res), res.status);
  return (await res.json()) as T;
}

/**
 * failStatus 取失败的 HTTP 状态码（不是 ApiError 就回 0）。
 * ★判状态码只能用它：api() 抛出的 message 是**后端中文原文**，永远不以状态码开头，
 * `msg.startsWith('401')` 那种写法在正常路径上一次都不会命中。
 */
export function failStatus(e: unknown): number {
  return e instanceof ApiError ? e.status : 0;
}

/**
 * failReason 把一次失败翻译成该给用户看的那句话：后端明确拒绝 → **原样转述**，一个字不改；
 * 请求没到后端 → 这时才该说"连不上"（调用方通常还会再做一次传输层归因）。
 */
export function failReason(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof NetworkError) return '连不上控制中心';
  if (e instanceof Error && e.message) return e.message;
  return '未知错误';
}

/** 连通性探测打的端点：一条真实的免认证 API（控制面 api.go 的免认证白名单里有它）。 */
export const PING_PATH = '/api/v1/auth/domains';
/** 探测超时。理由见 ping() 第三条：`location /api/` 的 proxy_read_timeout 是 3600s。 */
export const PING_TIMEOUT_MS = 5000;

/**
 * 控制中心连通性探测。
 *
 * ★改造前打的是 `origin() + '/healthz'` 且**只看 res.ok**，在参考部署上恒为真：
 *   deploy/nginx/baidi.conf 此前只有六个 location（`/`、三条登录端点、`/api/`、`/downloads/`），
 *   `/healthz` 一条都不匹配 → 落进 `location /` 的 `try_files … /index.html` → 拿到 200 + SPA 的
 *   HTML → `res.ok` 为真。**后果：把 baidi-control 停掉，「一键诊断」第一格「控制中心可达」
 *   照样是绿的**，而那正是排障时第一眼看的地方。移动端 wave10 已修，桌面端当时漏了——
 *   本仓最高频的那种「纪律只做了一半」。
 *
 * ★两道判据缺一不可：`res.ok` 挡不住那张 200 的 HTML，故还要**核对 content-type 是 JSON**。
 *   这道判据**不因 nginx 被修好而多余**：客户端装在别人的网里，前面可能是任何一台没跟着
 *   更新的反代（含此刻的在线演示站——它跑的还是没有 /healthz location 的那份配置），
 *   而"探测恒绿"这种错法在现场看不出来。把结论押在运维配置上，等于把判据交给一个
 *   我们既看不见也改不动的地方。
 *
 * ★自带 5s 超时：`location /api/` 的 proxy_read_timeout 是 3600s（管理 API 要长连接），
 *   控制面「进程活着但卡死」时请求会一直挂着，诊断页停在「检测中…」——那和假阳性一样坏。
 */
export async function ping(): Promise<boolean> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), PING_TIMEOUT_MS);
  try {
    const res = await fetch(origin() + PING_PATH, {
      headers: { Accept: 'application/json' }, signal: ac.signal
    });
    if (!res.ok) return false;
    return (res.headers.get('content-type') || '').toLowerCase().includes('application/json');
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

/* 与门户端点同构（客户端以 user 身份登录、拉取可访问应用） */
export interface PortalLoginResp {
  ok: boolean;
  needMfa?: boolean;      // legacy 演示验证码（未配置 WebAuthn 且未注册 TOTP 时回落）
  needTotp?: boolean;     // TOTP 动态验证码：配合 ticket 走 POST /auth/totp
  needWebauthn?: boolean; // passkey 断言（客户端做不了 WebAuthn 仪式，引导去浏览器门户）
  ticket?: string;        // 「口令已验」一次性票据（3min）
  reason?: string; token?: string; displayName?: string;
}
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
  /** 网关注册 id（= mTLS 证书 CN）。故障转移时要说清「现在用的是哪一台」，
   *  只报 IP 的话，网关换了地址或同机多实例就对不上账。回退落点为空串。 */
  id: string;
  host: string; spaPort: string; proxyPort: string;
  /** 该网关隧道证书的 SHA-256 指纹：客户端据此钉扎，把「加密」补成「加密 + 认证」。
   *  ★指纹**逐网关**，不是全局一份——共用会让故障转移在钉扎那一步必然失败，
   *  而症状是「切过去就连不上」，极易被误判成第二台网关也坏了。 */
  tunnelPin: string;
  /** 网关是否在心跳新鲜期内（控制面视角）。清单里离线的排在末尾但仍下发：
   *  「控制面看不到心跳」与「终端连不上它」是两个独立事实。 */
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
  /** 首选落点，恒等于 gateways[0]。老控制面只发这一个字段，故它仍是兜底来源。 */
  gateway: ProfileGateway;
  /** 全部网关落点，**顺序即优先级**（在线优先 → 网关 id 字典序，控制面已排好）。
   *  客户端按序尝试、失败切下一个。可选：老控制面不下发，此时退回只用 gateway 单落点。 */
  gateways?: ProfileGateway[];
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

/* ── 客户端灰度更新检查（GET /api/v1/client/update，登录用户）──
 *
 * ★判定完全在服务端：控制面按 (平台, 账号) 稳定分桶、叠加定向名单/用户组，
 * 算出「这台机器此刻该被告知哪个版本」，并且只有目标版本**高于**上报版本时才回 update=true。
 * 客户端刻意不自己算比例、也不自己比版本号——本地算的话改一个配置就能提前领灰度包，
 * 灰度就失去了"先小范围验证"的意义；两边各写一份版本比较，则迟早出现
 * 「服务端说不用升、客户端横幅还挂着」这种谁也说不清对错的分歧。
 */
export interface ClientUpdateResp {
  platform: string;
  /** 客户端上报的当前版本，服务端原样回显。 */
  current: string;
  /** 该账号此刻应拿到的版本。平台无发布计划时该字段缺席。 */
  latest?: string;
  /** 是否落在灰度批次里（false = 拿的是稳定版）。 */
  inGray?: boolean;
  /** 判定理由（定向灰度名单 / 按 N% 命中 / 未落入批次 / 该平台当前没有发布计划）。 */
  reason: string;
  /** ★横幅的唯一判据：服务端已排除「版本相同」与「目标更旧（那是降级）」两种情况。 */
  update: boolean;
}

/**
 * 检查客户端更新。
 *
 * ★version 必须是本机真实版本，不能留空：服务端对空版本的语义是
 * 「客户端没报版本 → 把最新版告诉它，由它自行比对」，会无条件回 update=true，
 * 于是横幅在早已是最新版的机器上常亮。取不到版本就别调（见 Connect.vue 的 checkUpdate）。
 */
export function checkClientUpdate(platform: string, version: string): Promise<ClientUpdateResp> {
  const q = new URLSearchParams({ platform, version });
  return api<ClientUpdateResp>('/client/update?' + q.toString());
}
