/**
 * `@tauri-apps/api/core` 的鸿蒙 shim。
 *
 * 鸿蒙壳复用的是 clients/desktop 那套 Vue（桌面布局），而它经 Tauri 的 invoke 调
 * Rust 侧命令。鸿蒙没有 Rust 壳，于是在这里把这些命令按**本端真实具备的能力**分发：
 *
 *   · tunnel_start / stop / status  → window.__BAIDI_NATIVE__（原生桥，契约同安卓/iOS 壳）
 *   · open_app_url / force_quit     → 鸿蒙原生（经同一座桥）
 *   · 其余                          → **如实抛「本端未实现」**
 *
 * ★最后一条是纪律不是偷懒：collect_posture / probe_tcp / probe_dns / collect_diag
 * 在鸿蒙上都还没有实现，返回一个编造的成功值会让诊断页画出一份**假报告**——
 * 那比功能缺失更坏（见 docs/ARCHITECTURE.md 里「采不到就报不可判定，绝不补 0」）。
 */

interface NativeBridge {
  platform?: string;
  startTunnel?: (token: string, cfg?: unknown) => Promise<{ ok: boolean; detail?: string }>;
  stopTunnel?: () => Promise<void>;
  tunnelStatus?: () => Promise<{ running: boolean; pid?: string; log?: string; endpoint?: string }>;
  openUrl?: (url: string) => Promise<void>;
  quit?: () => Promise<void>;
}

function native(): NativeBridge | undefined {
  return (window as unknown as { __BAIDI_NATIVE__?: NativeBridge }).__BAIDI_NATIVE__;
}

/** 本端尚未实现的命令：抛错，让调用方按失败处理并把原因显示出来。 */
function unimplemented(cmd: string): never {
  throw new Error(`鸿蒙端尚未实现该能力（${cmd}）`);
}

export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const nb = native();
  switch (cmd) {
    case 'tunnel_start': {
      if (!nb?.startTunnel) unimplemented(cmd);
      // desktop 侧传的是 { opts }，鸿蒙桥的契约是 (token, cfg)。
      // token 由 UI 自己放在 opts 里（接入剖面拉取时带的会话令牌）。
      const opts = (args?.opts ?? {}) as Record<string, unknown>;
      const token = String(opts.token ?? '');
      const r = await nb.startTunnel(token, opts);
      if (!r?.ok) throw new Error(r?.detail || '接入失败');
      return undefined as T;
    }
    case 'tunnel_stop':
      if (!nb?.stopTunnel) unimplemented(cmd);
      await nb.stopTunnel();
      return undefined as T;
    case 'tunnel_status': {
      if (!nb?.tunnelStatus) {
        // 桥没有这个方法 = 数据面还没接：如实报「没在跑」，不编造 running。
        return { running: false, pid: '', log: '' } as T;
      }
      const s = await nb.tunnelStatus();
      return { running: !!s.running, pid: s.pid ?? '', log: s.log ?? '', endpoint: s.endpoint } as T;
    }
    case 'open_app_url':
      if (!nb?.openUrl) unimplemented(cmd);
      await nb.openUrl(String(args?.url ?? ''));
      return undefined as T;
    case 'force_quit':
      if (!nb?.quit) unimplemented(cmd);
      await nb.quit();
      return undefined as T;
    default:
      // collect_posture / probe_tcp / probe_dns / collect_diag 等
      unimplemented(cmd);
  }
}

/**
 * Tauri 的 IPC 流式通道。@tauri-apps/plugin-shell 会 import 它（用于子进程输出流）。
 *
 * ★鸿蒙壳里**没有子进程**（desktop 用 sidecar 拉起 baidi-tun，鸿蒙走的是
 * VpnExtensionAbility），所以这里只需要一个能被 import 的形状，让打包过得去。
 * 真去调它的路径在鸿蒙上不存在——若将来有了，onmessage 永远不触发这件事
 * 会立刻暴露，好过在这里伪造一个"看起来能收数据"的实现。
 */
export class Channel<T = unknown> {
  id = 0;
  onmessage: (msg: T) => void = () => { /* 鸿蒙壳无子进程，永不触发 */ };
  toJSON(): string { return `__CHANNEL__:${this.id}`; }
}
