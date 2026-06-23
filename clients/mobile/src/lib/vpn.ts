/**
 * 白帝移动端 VPN 数据面抽象。
 *
 * 移动端无法像桌面那样 fork 子进程敲门：系统流量接管必须走平台 VPN 扩展——
 *   · iOS：NEPacketTunnelProvider（Network Extension），扩展内运行 Go 数据面(gomobile 编出 .xcframework)
 *           做 SPA 敲门 + 国密 TLCP 隧道 + utun 引流；
 *   · 安卓：VpnService 建立 TUN，JNI 调同一份 Go 数据面(gomobile aar)；
 *   · 鸿蒙：VpnExtensionAbility，NAPI 调 Go 数据面。
 * 原生壳通过 window.__BAIDI_NATIVE__ 把 startTunnel/stopTunnel 暴露给本 webview UI。
 *
 * dev 浏览器无原生桥时，退化为经本地 baidi-knock-agent(/knock) 发起**真实** SPA 敲门 +
 * 隧道可达性探测——同桌面 dev 路径，便于在移动视口里验证 UI 与后端链路。
 */

export interface TunnelResult { ok: boolean; detail?: string }

interface NativeBridge {
  apiBase?: string;
  startTunnel?: (token: string) => Promise<{ ok: boolean; detail?: string }>;
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

/** 启动隧道：原生走平台 VPN 扩展；dev 走本地敲门代理（真实敲门 + 隧道探测）。 */
export async function startTunnel(token: string): Promise<TunnelResult> {
  if (!token) return { ok: false, detail: '未登录，缺少身份令牌' };
  const nb = native();
  if (nb?.startTunnel) {
    try {
      const r = await nb.startTunnel(token);
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
