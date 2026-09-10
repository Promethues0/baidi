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

/**
 * 后端**明确拒绝**（HTTP 4xx/5xx，带 httpx.Error 的中文原因）。
 *
 * ★与 NetworkError 分开是有意的，两者该说的话完全相反：前者要原样转述后端那句话，
 *   后者才该说"连不上控制中心"。移动端此前**没有这个区分**——`api()` 一律
 *   `throw new Error(\`${res.status} ${res.statusText}\`)`，连后端 message 都不解，
 *   于是登录页那句 bare catch 把每一种拒绝都说成「无法连接控制中心（baidi-control）」：
 *   防爆破锁（403「登录失败次数过多，请约 N 分钟后重试」）、账号被禁用、
 *   首登改密时的 400「新口令强度不足：<哪一条不达标>」全被换成一个方向相反的归因，
 *   用户于是去查网络、去重试，而每重试一次都在给自己续锁。
 *   桌面端与控制台早有这两个类型，移动端是同一条纪律没做的那一半。
 */
export class ApiError extends Error {
  // ★字段显式声明 + 构造函数里赋值，**不能**写成 TS 的「参数属性」（`readonly status: number`
  //   写在参数表里）：移动端用例跑在 `node --experimental-strip-types` 的 strip-only 模式下，
  //   那种语法要真正的类型转译，node 会当场抛 ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX，
  //   于是整个测试文件挂掉——而它离被测代码有两层 import，报错看起来与本文件毫无关系。
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** 请求压根没到后端（fetch 抛 TypeError：控制面没起 / 网络断 / TLS 被拒 / CORS 拦）。 */
export class NetworkError extends Error {
  cause: unknown;
  constructor(cause: unknown) {
    super('连不上控制中心');
    this.name = 'NetworkError';
    this.cause = cause;
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

/**
 * failReason 把一次失败翻译成该给用户看的那句话：后端明确拒绝 → **原样转述**，一个字不改；
 * 请求没到后端 → 这时才该说"连不上"。**唯一收口**，别在页面里另写归因。
 */
export function failReason(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof NetworkError) return '无法连接控制中心（baidi-control），请检查网络与「我的」页里的控制中心地址';
  if (e instanceof Error && e.message) return e.message;
  return '未知错误';
}

/** failStatus 取失败的 HTTP 状态码（不是 ApiError 就回 0）。
 *  ★判状态码只能用它：api() 抛出的 message 是**后端中文原文**，永远不以状态码开头。 */
export function failStatus(e: unknown): number {
  return e instanceof ApiError ? e.status : 0;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  // ★headers 必须先从 init 里摘出来再单独合并。原写法是 `{ headers: {…合并…}, ...init }`，
  //   而 `...init` 里**也有** headers，展开在后就把合并结果整个顶掉——于是任何一个
  //   传了 headers 的调用（改密要带 Authorization + Content-Type）会静默丢掉
  //   `Accept` 与自动注入的 Bearer，症状是一次谁也解释不了的 401。
  //   桌面端 api.ts 早已是这个写法，移动端是同一条纪律没做的那一半。
  const { headers: extra, ...rest } = init ?? {};
  let res: Response;
  try {
    res = await fetch(apiBase() + path, {
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
  /**
   * 首登强制改密（FR-DEPLOY-09）：认证**已经通过**，但初始口令没换，于是 token 不是 8h
   * 会话令牌而是 15min 受限令牌（`Use=pwreset`），中间件只放行 `POST /auth/password`
   * 与 `GET /auth/me`，其余端点（含 /knock-token）一律 403。
   *
   * ★它与 `ok:true, token:…` 同时出现，所以**必须先判它**：先判 `ok && token` 就会
   * 拿受限令牌 login() 并 replace('/connect')，然后应用列表与接入逐个 403——而
   * `BAIDI_SEED_MUST_CHANGE` 默认 1、管理员每次重置口令也置这一位，也就是说
   * 每台按脚本装出来的机器上、每一个新用户的首次登录都会走这条路。
   */
  mustChangePassword?: boolean;
  /** 本回合第一因子来自外部认证源：后端不再校验旧口令（他不可能知道管理员设的**本地**旧口令）。 */
  skipOldPassword?: boolean;
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
  /** 上面那行 addr 是**哪来的**（服务端 portalAddr 现算，wave11 行动 15②）：
   *   - `resource`  取自关联受控资源的 backend —— 网关真正拨号的那个地址；
   *   - `bookmark`  直连书签自己的链接（那一档 addr 是执行值）；
   *   - `declared`  管理员手填、**没有任何执行方**的展示值。
   *  ★缺省（旧后端不下发）= 判不出来，此时一律不贴标注：说它「来自资源」是编，
   *  说它「只是手填」也是编，而两句话会把用户支去两个相反的方向。 */
  addrSource?: 'resource' | 'bookmark' | 'declared';
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
