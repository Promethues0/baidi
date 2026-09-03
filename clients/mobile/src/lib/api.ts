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

/** 连通性探测打的端点。**必须是一条真实的免认证 API**（GET /api/v1/auth/domains：
 *  控制面 api.go 的免认证白名单里有它，登录页在登录之前就要拿它，回 200 + JSON）。 */
export const PING_PATH = '/api/v1/auth/domains';

/** 探测超时。见 ping() 里第三条：`location /api/` 的 proxy_read_timeout 是 3600s。 */
export const PING_TIMEOUT_MS = 5000;

/**
 * 控制中心连通性探测。
 *
 * ★改造前打的是 `origin() + '/healthz'`，在**当时的参考部署上恒为真**：deploy/nginx/baidi.conf
 *   只有六个 location（`/`、三条登录端点、`/api/`、`/downloads/`），`/healthz` 一条都不匹配，
 *   于是落进 `location /` 的 `try_files $uri $uri/ /index.html` —— nginx 把 SPA 的 index.html
 *   回给它，200 OK，`res.ok` 恒 true。**后果：控制面整个停掉，「我的」页照样显示
 *   「控制中心 连通」**，而那一行正是用户排障时第一眼看的地方。
 *
 * ★所以两道判据缺一不可：`res.ok` 挡不住那张 200 的 HTML，故还要**核对 content-type 是 JSON**
 *   （控制面的 httpx.JSON 一律发 `application/json; charset=utf-8`，SPA 回退发 text/html）。
 *   这道判据**不因反向代理被修好而多余**：客户端装在别人的网里，前面可能是任何一台
 *   没跟着改的 nginx / 网关 / 门户回退，而「探测恒绿」这种错法在现场看不出来。
 *   把结论押在运维配置上，等于把判据交给一个我们既看不见也改不动的地方。
 *
 * ★打 auth/domains 而不是 `/healthz`：它免认证（未登录也能探）、无副作用，且走
 *   `location /api/`——探的是**业务请求真正走的那条路**。代价是那条 location 的
 *   proxy_read_timeout 是 3600s（管理 API 要长连接），控制面「进程活着但卡死」时
 *   请求会一直挂着，界面停在「检测中…」——那和假阳性一样坏（用户看不出区别）。
 *   故这里自带 5s 超时：判不出来就报不可达，绝不无限期地挂着不给结论。
 */
export async function ping(): Promise<boolean> {
  // 用 AbortController 而不是 AbortSignal.timeout：后者在旧安卓 WebView / 老 iOS 上没有，
  // 而探测失败在那些机器上会变成"永远检测中"，正是这段要消灭的形态。
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

/* 与门户端点同构（移动端以 user 身份登录、拉取可访问应用） */
export interface PortalLoginResp {
  ok: boolean;
  needMfa?: boolean;      // legacy 演示验证码（未配置 WebAuthn 且未注册 TOTP 时回落）
  needTotp?: boolean;     // TOTP 动态验证码：配合 ticket 走 POST /auth/totp
  needWebauthn?: boolean; // passkey 断言（移动客户端做不了，引导去浏览器门户）
  ticket?: string;        // 「口令已验」一次性票据（3min）
  reason?: string; token?: string; displayName?: string;
  /** needDirectory 配了 ≥2 个外部认证域又没指定：服务端**拒绝登录**并带回候选。
   *  ★不是"可选项"——挨个去问等于把明文口令投递给排在前面的每一台目录服务器
   *  （wave8 行动 12 的核心不变式：一次登录只把口令交给一台服务器）。
   *  此前移动端没有这两个字段，服务端那句「请先选择你所属的认证域」只能原样显示成
   *  一条错误——而移动端**没有任何控件可做这件事**，外部目录账号 100% 登不进去。 */
  needDirectory?: boolean;
  domains?: AuthDomainOption[];
}
/** 登录页的认证域下拉项（GET /api/v1/auth/domains，免认证；只在 ≥2 个源时非空）。 */
export interface AuthDomainOption { id: string; name: string; kind: string }
export interface PortalTile {
  id: string; name: string; mode: 'tunnel' | 'web' | 'global'; addr: string;
  sensitivity: 'low' | 'normal' | 'high';
  /** 服务端算出的授权结论：静态 ACL ∪ 组织/用户组展开 ∪ 有效 JIT 授予，减去终端降权否决。
   *  ★唯一判据就是它。**不要**按 sensitivity 自己推「要不要申请」——高敏不等于没授权，
   *  普通也不等于人人可进，这两处推导正是控制面侧被消灭掉的那个第四判定点。 */
  accessible: boolean;
  /** 因终端风险降权而不可访问（而非缺授权）。此时提交访问申请无效——降权否决压过 JIT 授予，
   *  用户该做的是修复终端环境。两种"不可访问"的下一步动作完全不同，提示语必须区分。 */
  degraded?: boolean;
  /** 结构上不可用（未关联受控资源 / 后端不是 host:port）：配置缺口而非授权结论，
   *  自助申请同样会被后端拒掉，只能找管理员。 */
  unavailable?: boolean;
  /** 不可用的具体原因，直接说给用户听。 */
  unavailableReason?: string;
}
export interface PortalAppsResp { apps: PortalTile[] }

/* ── 客户端灰度更新检查（GET /api/v1/client/update，登录用户）──
 *
 * ★判定完全在服务端：控制面按 (平台, 账号) 稳定分桶、叠加定向名单/用户组，
 * 算出「这台机器此刻该被告知哪个版本」，并且只有目标版本**高于**上报版本时才回 update=true。
 * 移动端刻意不自己算比例、也不自己比版本号——两边各写一份版本比较，迟早出现
 * 「服务端说不用升、客户端横幅还挂着」这种谁也说不清对错的分歧（与桌面端同一条纪律）。
 *
 * 后端按 platform 分桶**早已支持** android/ios/harmony；改造前只是移动端从没调过这一跳
 * （grep client/update 在 clients/mobile 里零命中）。
 */
export interface ClientUpdateResp {
  platform: string;
  current: string;
  latest?: string;
  inGray?: boolean;
  reason: string;
  /** ★横幅的唯一判据：服务端已排除「版本相同」与「目标更旧（那是降级）」两种情况。 */
  update: boolean;
}

/** 本端版本（构建期由 vite define 从 package.json 注入）。 */
export const appVersion: string = typeof __APP_VERSION__ === 'string' ? __APP_VERSION__ : '';

/**
 * 检查客户端更新。
 *
 * ★version 必须是本机真实版本，不能留空：服务端对空版本的语义是
 * 「客户端没报版本 → 把最新版告诉它」，会无条件回 update=true，
 * 于是横幅在早已是最新版的机器上常亮。取不到版本就别调。
 */
export function checkClientUpdate(platform: string, version: string): Promise<ClientUpdateResp> {
  const q = new URLSearchParams({ platform, version });
  return api<ClientUpdateResp>('/client/update?' + q.toString());
}
