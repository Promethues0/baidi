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
import { config } from './store';
import { api } from './api';

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
      return { ok: !!r.ok, detail: r.detail };
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

/** 断开隧道。 */
export async function stopTunnel(): Promise<void> {
  const nb = native();
  if (nb?.stopTunnel) {
    try { await nb.stopTunnel(); } catch { /* ignore */ }
  }
}
