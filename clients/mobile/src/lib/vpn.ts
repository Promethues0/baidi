/**
 * 白帝移动端 VPN 数据面抽象。
 *
 * 移动端无法像桌面那样 fork 子进程敲门：系统流量接管必须走平台 VPN 扩展——
 *   · iOS：NEPacketTunnelProvider（Network Extension），扩展内运行 Go 数据面(gomobile 编出 .xcframework)
 *           做 SPA 敲门 + 国密 TLCP 隧道 + utun 引流；
 *   · 安卓：VpnService 建立 TUN，JNI 调同一份 Go 数据面(gomobile aar)；
 *   · 鸿蒙：VpnExtensionAbility，NAPI 调 Go 数据面。
 * 原生壳通过 window.__BAIDI_NATIVE__ 把 startTunnel/stopTunnel 暴露给本 webview UI；
 * 接入配置（网关/网段/虚拟IP/国密/端口）经 startTunnel(token, cfg) 下传给原生扩展，
 * 由扩展据此建 TUN + 敲门 + 隧道（不再在原生侧写死）。
 *
 * dev 浏览器无原生桥时，退化为经本地 baidi-knock-agent(/knock) 发起**真实** SPA 敲门 +
 * 隧道可达性探测——同桌面 dev 路径，便于在移动视口里验证 UI 与后端链路。
 */
import { config, session } from './store';
import { api } from './api';
import {
  createTunnelWatch, judgeReady, notReadyReason,
  type TunnelStatus, type TunnelWatch
} from './tunnelwatch';

export interface TunnelResult { ok: boolean; detail?: string }

/** 下传给原生 VPN 扩展的接入配置。 */
export interface TunnelConfig {
  control: string;   // 控制中心（取短时效敲门令牌 + 保活）
  gateway: string;   // 安全代理网关主机
  spaPort: string;   // SPA 敲门端口
  proxyPort: string; // 隧道代理端口
  route: string;     // 受保护网段（引流进 TUN）
  ip: string;        // utun 虚拟 IP
  gm: boolean;       // 国密 TLCP 隧道
  // ★以下三项来自控制面接入剖面，此前**整条链路上都不存在**：
  //   pin 缺席 → 隧道对网关身份零校验（桌面端专门做的钉扎在移动端结构性没有）；
  //   resmap 缺席 → 每条连接都不发 CONNECT 前导，落进网关那条跳过资源鉴权的回退路径
  //   （wave9 已把它改成 fail-closed，所以现在缺 resmap = 什么都访问不到，而非"越权访问"）。
  pin: string;              // 网关隧道证书 SHA-256 指纹（hex）
  resmap: string;           // {"host:port":"资源id"} 的 JSON 串（gomobile 不能传 map）
  defaultResource: string;  // 默认资源 id（resmap 未命中时的兜底，通常为空）
}

/** 接入剖面里本端要用的那几项（GET /client/profile 的子集）。 */
interface ProfileLite {
  gateway?: { host?: string; spaPort?: string; proxyPort?: string; tunnelPin?: string };
  routes?: string[];
  tunIP?: string;
  resmap?: Record<string, string>;
}

/** 最近一次成功拉取的接入剖面。null = 还没拉到（此时回退到「我的」页的手填配置）。 */
let profile: ProfileLite | null = null;

/**
 * 拉取接入剖面。**接入前必须调一次**——网关落点、该接管哪些网段、资源映射、
 * 证书指纹全都只有控制面知道，终端不该自己猜（同桌面端 loadProfile 的纪律）。
 *
 * 拉不到不阻断接入：退回手填配置并把原因交给调用方显示——但那种接入多半是
 * 「隧道起来了却什么都访问不了」的半成功状态（无 resmap → 无前导 → 网关 fail-closed）。
 */
export async function loadProfile(): Promise<string> {
  try {
    profile = await api<ProfileLite>('/client/profile');
    return '';
  } catch (e) {
    profile = null;
    return String((e as Error)?.message ?? e);
  }
}

interface NativeBridge {
  apiBase?: string;
  startTunnel?: (token: string, cfg?: TunnelConfig) => Promise<{ ok: boolean; detail?: string }>;
  stopTunnel?: () => Promise<void>;
  /**
   * 原生真实运行态（目前只有安卓壳实现；iOS / 鸿蒙壳没有 → 接入后的中断在那两端不可判定）。
   *
   * ★返回 **null = 这一刻读不到**（桥抛错 / 状态不是合法 JSON），不是「已断开」。安卓桥的
   *   catch 分支必须回 null 而不是合成 { stage:'failed' }：合成的话，下面 startTunnelWatch
   *   会据此判中断、写 dropReason、并主动 stopTunnel 把一条好隧道真的断掉。
   *
   * ★**同名不同契约**：鸿蒙壳（`clients/harmony/entry/…/Index.ets`）注入的
   *   `window.__BAIDI_NATIVE__.tunnelStatus` 是**异步**的 `{ running, pid, log, endpoint }`
   *   ——那座桥服务的是 `clients/desktop` 那套 UI（经 `clients/harmony/webui/shim/core.ts`
   *   翻成 Tauri 的 `invoke('tunnel_status')`），与这里的同步 `{ stage, reason }` 毫无关系。
   *   两条契约各自只被对应的 UI 包消费，**壳与 UI 必须成对，不得互换**（把移动端 dist 装进
   *   鸿蒙壳、或反过来，接入态判定会整段错而两边都不报错）。见 docs/ARCHITECTURE.md 第七节。
   */
  tunnelStatus?: () => TunnelStatus | null;
}

function native(): NativeBridge | undefined {
  return (window as unknown as { __BAIDI_NATIVE__?: NativeBridge }).__BAIDI_NATIVE__;
}

export function isNative(): boolean {
  return !!native()?.startTunnel;
}

export function platformLabel(): string {
  if (isNative()) return '原生 VPN 扩展';
  return 'dev 浏览器（knock-agent）';
}

/** 由当前配置组装下传给原生扩展的隧道配置。
 *  control 的优先级与 api.ts 一致：原生壳注入 apiBase →「我的」页配置 control。
 *  真机上用户常把 control 留空（由壳注入），只读 config.control 会传空串——
 *  而网关 strict 模式下没有 control 就换不到敲门令牌，隧道直接连不上。 */
export function tunnelConfig(): TunnelConfig {
  const nb = (window as unknown as { __BAIDI_NATIVE__?: { apiBase?: string } }).__BAIDI_NATIVE__;
  const g = profile?.gateway;
  // 剖面优先、手填兜底：控制面同时知道网关在哪、业务在哪、当前用户有权访问什么，
  // 三者只有它凑得齐；手填配置只是剖面拉不到时的降级。
  const routes = profile?.routes?.length ? profile.routes.join(',') : config.route;
  const resmap = profile?.resmap && Object.keys(profile.resmap).length
    ? JSON.stringify(profile.resmap) : '';
  return {
    control: (nb?.apiBase || config.control || '').replace(/\/+$/, ''),
    gateway: g?.host || config.gateway,
    spaPort: g?.spaPort || config.spaPort,
    proxyPort: g?.proxyPort || config.proxyPort,
    route: routes,
    ip: profile?.tunIP || config.ip,
    gm: config.gm,
    pin: g?.tunnelPin || '',
    resmap,
    defaultResource: ''
  };
}

/** 接入信息卡展示用（真实来自当前配置，而非硬编码）。 */
export function tunnelInfo() {
  const c = tunnelConfig();
  return {
    gateway: c.gateway ? `${c.gateway}:${c.proxyPort}` : '（原生下发）',
    vip: c.ip,
    route: c.route,
    // ★算法名后面要跟上**是否认证了网关身份**：只写"国密 TLCP · SM2/SM4-GCM/SM3"
    //   读起来比钉扎那档还强，而它此前恰恰是零认证的那一档。
    cipher: (c.gm ? '国密 TLCP · SM2 / SM4-GCM / SM3' : '通用 TLS 1.3')
      + (c.pin ? ' · 已钉扎网关证书' : ' · 未钉扎（加密但不认证网关身份）'),
    pinned: !!c.pin,
    resources: c.resmap ? Object.keys(JSON.parse(c.resmap)).length : 0
  };
}

/** 启动隧道：原生走平台 VPN 扩展（下传配置）；dev 走本地敲门代理（真实敲门 + 隧道探测）。 */
export async function startTunnel(token: string): Promise<TunnelResult> {
  if (!token) return { ok: false, detail: '未登录，缺少身份令牌' };
  const nb = native();
  if (nb?.startTunnel) {
    try {
      const r = await nb.startTunnel(token, tunnelConfig());
      if (r.ok) { startTunnelWatch(); return { ok: true, detail: r.detail }; }
      // ★失败**不等于**没在跑：桥现在会因「引擎起来了、门没敲开」而 resolve ok:false
      //   （真机形态：stage=up + knock=false + x509 证书校验失败）。这种时候：
      //     · 绝不 stopTunnel —— 敲门每 15s 自动重试，随时可能自愈（gateway/internal/dataplane
      //       的 knockOne 对非 403 失败只 warn 后 return false，Run 继续阻塞，reknock ticker 重试）；
      //     · 必须 startTunnelWatch —— 否则留下一条**无人监视**、仍以当前账号保活续窗的孤儿 VPN：
      //       它此后被抢占 / 被回收 / 自愈成功，webview 一概不知道。
      //   引擎没在跑（idle/failed/读不到）才是真失败，走原路返回，UI 照旧回 idle。
      const s = tunnelStatus();
      if (s && (s.stage === 'starting' || s.stage === 'up')) {
        startTunnelWatch(); // 注意顺序：它会清 notReady/dropReason，代表"新一段接入从此刻起算"
        session.notReady = (r.detail && r.detail.trim()) ? r.detail.trim() : notReadyReason(s);
      }
      return { ok: false, detail: r.detail };
    } catch (e) {
      return { ok: false, detail: String(e) };
    }
  }
  try {
    const res = await fetch('/knock', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    return (await res.json()) as TunnelResult;
  } catch {
    return { ok: false, detail: 'dev 敲门代理不可达（启动 baidi-knock-agent）' };
  }
}

/** 断开隧道（用户主动）。先停监视：主动断开不是中断，不该被判成一次「隧道已停止」。
 *  同时清掉未就绪原因——隧道都不在了，「门没敲开」这句话已经没有对象了；
 *  dropReason 刻意不清（onDrop 正是先写它再调这里，清了等于把中断原因当场擦掉）。 */
export async function stopTunnel(): Promise<void> {
  stopTunnelWatch();
  session.notReady = '';
  session.tunnelNote = '';
  const nb = native();
  if (nb?.stopTunnel) {
    try { await nb.stopTunnel(); } catch { /* ignore */ }
  }
}

/** 读原生真实运行态；无桥 / 桥没有 tunnelStatus / 调用抛错 → null（不可判定，不是「已断开」）。 */
export function tunnelStatus(): TunnelStatus | null {
  const nb = native();
  if (!nb?.tunnelStatus) return null;
  try { return nb.tunnelStatus() ?? null; } catch { return null; }
}

let watch: TunnelWatch | null = null;

/**
 * 接入成功后开始监视原生运行态。**这是 TunnelState 里那些失败原因的唯一读端**：
 * 另一 VPN 抢占（onRevoke）/ 系统回收服务 / 引擎因强制下线、账号禁用、终端合规阻断而停机，
 * 原生侧都会把 stage 翻成 failed 并留下原因——没有这道轮询，用户看到的是纹丝不动的
 * 「已接入企业内网」，直到他自己点断开把原因一并清掉。
 *
 * 放在模块级而不是 Connect.vue 里：切到「应用」页 Connect 就卸载了，隧道却还在跑；
 * 监视的寿命要跟隧道走，不跟页面走。中断的处置只有三件事——把会话翻成未接入、
 * 把原因写进 session.dropReason（UI 各页自己读）、把原生侧的残留清掉（stopTunnel）。
 *
 * ★wave10 起它同时是**就绪态的读端**：接入态不再由「startTunnel 返回了成功」一锤定音
 * （真机上那一锤正好敲反：引擎起来了、门没敲开），而是每轮跟着数据面健康行双向翻转。
 */
export function startTunnelWatch(): void {
  stopTunnelWatch();
  if (!native()?.tunnelStatus) return; // 不可判定就不监视，也不假装监视
  session.dropReason = '';
  session.notReady = '';
  watch = createTunnelWatch(tunnelStatus, {
    onDrop: (reason) => {
      watch = null;
      session.connected = false;
      session.dropReason = reason;
      // 断了就不是"未就绪"了：两条横幅同时挂着会让用户以为出了两件事。
      session.notReady = '';
      session.tunnelNote = '';
      // 原生侧可能还挂着一个引擎已死的服务，清掉它；这里的 stopTunnel 会再调一次 stopTunnelWatch，幂等。
      void stopTunnel();
    },
    // ★null（本端壳不报健康态：iOS / 鸿蒙 / 旧安卓包）时**一个字段都不动**：
    //   翻成 false 会让那几端在毫无依据的情况下集体显示「未就绪」，翻成 true 则是替
    //   一份根本没读到的健康行背书。不可判定就保持调用方原来的判断。
    onReady: (v, s) => {
      // 隧道类当前失败与就绪判定**互不相干**，故在 v===null 之前就写：那几端读不到 ready，
      // 但只要健康行里有 terr 就该把它显示出来。空串同样要写回去——它是"这一刻没有隧道类失败"，
      // 不写就会让一条早已恢复的告警永远挂在界面上。
      session.tunnelNote = (s?.healthTunnelErr || '').trim();
      if (v === null) return;
      session.connected = v;
      session.notReady = v ? '' : notReadyReason(s);
    }
  });
}

export function stopTunnelWatch(): void {
  watch?.stop();
  watch = null;
}

/**
 * webview 挂载时把**原生仍在跑的隧道**认领回 UI 状态。App.vue 的 onMounted 是唯一调用点。
 *
 * ★为什么必需：`session.connected` 不持久化、每次从 false 起算，而原生 VPN 是进程外的前台
 *   服务——webview 重载、Activity 被系统重建、用户从最近任务切回来，隧道都照常在跑。改造前
 *   `startTunnelWatch()` 唯一的调用点在 `startTunnel` 的成功分支上，于是重建之后：页面显示
 *   「未接入」而流量正走着隧道（用户会再点一次接入），**且此后再没有任何人读 tunnelStatus**——
 *   被其它 VPN 抢占、引擎因下线/合规阻断停机，原生侧留下的原因一个读者都没有。
 *
 * 四种处置严格对应四种事实：
 *   · up 且 ready 判真   —— 确实在跑、门也开着：翻成已接入并重新开始监视
 *                          （认领了却不监视 = 把上面那个洞留一半）；
 *   · up 且 ready 判假   —— 引擎在跑、门没敲开：**照样认领并监视**（它每 15s 自动重试、
 *                          随时可能自愈，不监视就没人看见它自愈，也没人看见它被抢占），
 *                          但接入态是「未就绪」而不是「已接入」，原因写进 notReady；
 *   · failed             —— 上一段接入不是用户断的、原因还留着：写进 dropReason 让 UI 当面显示；
 *   · 其它               —— **什么都不做**。null=读不到（不可判定，见上）、idle=本就没在接入、
 *                          starting=几秒钟的过渡窗口。
 *
 * ★ready 不可判定（本端壳不报健康态）时回落成「已接入」：这是**认领**语义下唯一合理的方向——
 *   改造前 iOS / 鸿蒙 / 旧安卓包在这里就是这么认的，一律翻成未就绪等于给那几端凭空造出
 *   一个它们永远出不去的中间态。判据的收紧只发生在真报了 ready 的壳上。
 */
export function adoptRunningTunnel(): void {
  const s = tunnelStatus();
  if (!s) return; // 读不到 ≠ 断了，也 ≠ 在跑：不下任何结论
  if (s.stage === 'up') {
    const ready = judgeReady(s);
    session.connected = ready !== false;
    startTunnelWatch(); // 注意顺序：它会清 dropReason/notReady，代表"新的一段接入从此刻起算"
    if (ready === false) session.notReady = notReadyReason(s);
    return;
  }
  if (s.stage === 'failed' && s.reason?.trim()) session.dropReason = s.reason.trim();
}
