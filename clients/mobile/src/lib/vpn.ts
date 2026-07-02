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

/** 由当前配置组装下传给原生扩展的隧道配置。 */
export function tunnelConfig(): TunnelConfig {
  return {
    control: config.control.replace(/\/+$/, ''),
    gateway: config.gateway,
    spaPort: config.spaPort,
    proxyPort: config.proxyPort,
    route: config.route,
    ip: config.ip,
    gm: config.gm
  };
}

/** 接入信息卡展示用（真实来自当前配置，而非硬编码）。 */
export function tunnelInfo() {
  return {
    gateway: config.gateway ? `${config.gateway}:${config.proxyPort}` : '（原生下发）',
    vip: config.ip,
    route: config.route,
    cipher: config.gm ? '国密 TLCP · SM2 / SM4-GCM / SM3' : '通用 TLS 1.3'
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
