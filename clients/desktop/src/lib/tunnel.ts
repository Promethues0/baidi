/**
 * 客户端数据面隧道控制（真 utun 接管流量）：
 *  - Tauri 运行时：经自定义命令 tunnel_start/status/stop 以管理员权限拉起 baidi-tun，
 *    真正用 utun 接管受保护网段 → 逐流 SPA 敲门 → 加密隧道 → 网关。
 *  - 浏览器 dev：无 utun（需 root + Tauri），退化为经 baidi-knock-agent 的真实敲门探测，
 *    供 UI 联调；不接管系统流量。
 */
import { config, session, profile } from './store';

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
  denied: boolean;      // 被控制面定性拒绝（强制下线 / 账号禁用锁定）——不可自愈，别重试
  deniedReason: string; // 拒绝原因（人话，供 UI 显著呈现）
  lines: string[];      // 最近日志尾巴
}

/**
 * 接入参数解析：剖面优先，config 兜底。
 *
 * 正常路径下网关地址、接管网段、虚拟 IP 全部取自控制面剖面——只有控制面同时知道
 * 网关在哪、业务在哪、当前用户有权访问什么。config 里的同名字段退化为「剖面拿不到时
 * 的应急覆盖」（如控制面暂时不可达但想用上次已知的落点试一把），不再是主来源。
 */
export function resolveTunOpts() {
  const p = profile.data;
  const gw = p?.gateway;
  // routes 必须非空：一个网段都不接管的话，隧道会成功建立但没有任何流量进去，
  // 表现为「显示已接入、什么都访问不了」——正是此前最迷惑人的失败形态。
  const routes = p?.routes?.length ? p.routes : [config.route];
  // 分离式 DNS：整段来自控制面剖面，客户端不推导也不兜底。
  // 剖面没有 dns 段（老控制面）时三个字段都是空串 → baidi-tun 不启用解析器，
  // 域名类业务退回「不接管」的老行为；这里刻意**不给 config 兜底**：
  // 解析器 VIP 必须与控制面下发的 routes 一致，手填一个对不上的地址只会让查询包
  // 压根不进隧道，症状是解析超时——比不启用更难查。
  const dns = p?.dns;
  return {
    control: config.control.replace(/\/+$/, ''),
    gateway: gw?.host || config.gateway,
    spaPort: gw?.spaPort || config.spaPort,
    proxyPort: gw?.proxyPort || config.proxyPort,
    route: routes.join(','),
    ip: p?.tunIp || config.ip,
    gm: config.gm,
    token: session.token,
    // 资源映射表整体交给 Tauri 侧落盘（-resmap）。空对象时传空串，让 Rust 侧
    // 清掉上一轮的遗留文件，避免换用户后仍按旧表路由。
    resmap: p?.resmap && Object.keys(p.resmap).length ? JSON.stringify(p.resmap) : '',
    pin: gw?.tunnelPin || '',
    // 与 resmap 同一套写法：记录表整体交给 Tauri 侧落盘（-dns-records）。
    // 空串让 Rust 侧清掉上一轮的遗留文件，避免换用户/换策略后仍按旧记录作答。
    dnsListen: dns?.server?.trim() || '',
    dnsDomains: dns?.domains?.length ? dns.domains.join(',') : '',
    dnsRecords: dns?.records && Object.keys(dns.records).length ? JSON.stringify(dns.records) : ''
  };
}

/**
 * 启动隧道时用的那份接入参数快照。
 *
 * ★接入信息必须展示这一份，而不是「当前剖面」算出来的那份。全局剖面会被随时刷新
 * （切到「应用」页就会重新拉一次），而 baidi-tun 的参数在 tunnel_start 那一刻就定死了，
 * 之后不再变。用当前剖面展示的后果是把**未钉扎的运行中隧道显示成已钉扎**：
 * 网关重启后尚未上报证书指纹时接入 → 剖面无 pin → 隧道以不校验网关身份的方式建立；
 * 用户切一次页面触发刷新，此时网关已上报指纹 → 界面显示「证书钉扎」，
 * 而运行中的隧道根本没有钉扎。同理，新批的 JIT 授权会让「引流网段」显示一个
 * 运行中的 baidi-tun 从未接管过的网段。
 */
let startedOpts: ReturnType<typeof resolveTunOpts> | null = null;

export async function tunnelStart(): Promise<void> {
  const opts = resolveTunOpts();
  await invoke('tunnel_start', { opts });
  startedOpts = opts; // 拉起成功才记，失败时保持上一份（或 null）
}

/** 用系统浏览器打开应用地址（经 Rust 侧白名单校验，仅 http/https）。 */
export async function openAppUrl(url: string): Promise<void> {
  await invoke('open_app_url', { url });
}

export async function tunnelStop(): Promise<void> {
  await invoke('tunnel_stop');
  startedOpts = null;
}

/** 前端确认后真正退出应用（隧道运行中退出前的二次确认走此）。 */
export async function forceQuit(): Promise<void> {
  await invoke('force_quit');
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
  // 控制面定性拒绝：dataplane 的 knock.ErrDenied 原文含「接入被拒」，Run 停机前会 warn「接入被控制面拒绝」。
  // 与瞬时失败区别对待——被强制下线/账号禁用不可自愈，UI 应显著提示且不诱导重试。
  const denyLine = lines.filter((l) => /接入被拒|接入被控制面拒绝/.test(l)).pop() || '';
  const denied = !s.running && !!denyLine;
  const deniedReason = denied ? (stripTs(denyLine).match(/接入被拒[：:]\s*(.+)$/)?.[1] || '已被管理员禁止接入').trim() : '';
  // 展示值取「数据面真正在用的那份」：隧道运行中一律用启动时的快照，
  // 只有未运行时才用当前剖面预览（那时展示的是"下次接入会用什么"）。
  // 直接现算当前剖面会把未钉扎的隧道显示成已钉扎，见 startedOpts 的注释。
  const eff = s.running && startedOpts ? startedOpts : resolveTunOpts();
  return {
    running: s.running,
    ready,
    dev,
    vip: eff.ip,
    route: eff.route,
    gateway: `${eff.gateway}:${eff.proxyPort}`,
    cipher: config.gm
      ? '国密 TLCP（SM2 / SM4-GCM / SM3）'
      : eff.pin
        ? '通用 TLS 1.3 · 证书钉扎'
        : '通用 TLS 1.3（未钉扎：加密但不认证网关）',
    keepalive,
    error,
    denied,
    deniedReason,
    lines: lines.slice(-8)
  };
}

function stripTs(l: string): string {
  // 去掉 slog 的 time=... level=... 前缀，留人话
  return l.replace(/^time=\S+\s+level=\S+\s+msg=/, '').replace(/^"|"$/g, '');
}
