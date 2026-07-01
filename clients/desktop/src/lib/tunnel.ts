/**
 * 客户端数据面隧道控制（真 utun 接管流量）：
 *  - Tauri 运行时：经自定义命令 tunnel_start/status/stop 以管理员权限拉起 baidi-tun，
 *    真正用 utun 接管受保护网段 → 逐流 SPA 敲门 → 加密隧道 → 网关。
 *  - 浏览器 dev：无 utun（需 root + Tauri），退化为经 baidi-knock-agent 的真实敲门探测，
 *    供 UI 联调；不接管系统流量。
 */
import { config, session } from './store';

export function tauriRuntime(): boolean {
  return typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const mod = '@tauri-apps/api/core';
  const core = (await import(/* @vite-ignore */ mod)) as { invoke: (c: string, a?: Record<string, unknown>) => Promise<T> };
  return core.invoke(cmd, args);
}

interface TunStatusRaw { running: boolean; pid: string; log: string }

/** 从 baidi-tun 真实日志解析出的接入态。 */
export interface TunView {
  running: boolean;
  ready: boolean;       // 数据面就绪（TUN→netstack→隧道）
  dev: string;          // utunN
  vip: string;          // 虚拟 IP
  route: string;        // 受保护网段
  gateway: string;      // 网关隧道地址
  cipher: string;       // 隧道密码学
  keepalive: boolean;   // 敲门保活已起
  error: string;        // 最近的失败原因（若有）
  lines: string[];      // 最近日志尾巴
}

export async function tunnelStart(): Promise<void> {
  await invoke('tunnel_start', {
    opts: {
      control: config.control.replace(/\/+$/, ''),
      gateway: config.gateway,
      spaPort: config.spaPort,
      proxyPort: config.proxyPort,
      route: config.route,
      ip: config.ip,
      gm: config.gm,
      token: session.token
    }
  });
}

export async function tunnelStop(): Promise<void> {
  await invoke('tunnel_stop');
}

export async function tunnelStatus(): Promise<TunView> {
  const s = await invoke<TunStatusRaw>('tunnel_status');
  return parse(s);
}

function parse(s: TunStatusRaw): TunView {
  const log = s.log || '';
  const lines = log.split('\n').map((l) => l.trim()).filter(Boolean);
  const dev = (log.match(/dev=(utun\d+)/) || [])[1] || '';
  // ready/keepalive 仅在进程存活时才认（进程已退出=旧日志残留，不据此误判）
  const ready = s.running && /数据面就绪/.test(log);
  const keepalive = s.running && /敲门保活/.test(log);
  // 取最近一条失败（创建/敲门/隧道/退出）作为错误提示
  const fails = lines.filter((l) => /失败|未敲门成功|panic|fatal|退出/i.test(l));
  const error = !s.running && fails.length ? stripTs(fails[fails.length - 1]) : '';
  return {
    running: s.running,
    ready,
    dev,
    vip: config.ip,
    route: config.route,
    gateway: `${config.gateway}:${config.proxyPort}`,
    cipher: config.gm ? '国密 TLCP（SM2 / SM4-GCM / SM3）' : '通用 TLS 1.3',
    keepalive,
    error,
    lines: lines.slice(-8)
  };
}

function stripTs(l: string): string {
  // 去掉 slog 的 time=... level=... 前缀，留人话
  return l.replace(/^time=\S+\s+level=\S+\s+msg=/, '').replace(/^"|"$/g, '');
}
