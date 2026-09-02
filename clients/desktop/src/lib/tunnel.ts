/**
 * 客户端数据面隧道控制（真 utun 接管流量）：
 *  - Tauri 运行时：经自定义命令 tunnel_start/status/stop 以管理员权限拉起 baidi-tun，
 *    真正用 utun 接管受保护网段 → 逐流 SPA 敲门 → 加密隧道 → 网关。
 *  - 浏览器 dev：无 utun（需 root + Tauri），退化为经 baidi-knock-agent 的真实敲门探测，
 *    供 UI 联调；不接管系统流量。
 */
import { invoke as tauriInvoke } from '@tauri-apps/api/core';
import { config, session, profile, device } from './store';
import type { ProfileGateway } from './api';

export function tauriRuntime(): boolean {
  return typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined';
}

/**
 * 调一条 Tauri 命令。
 *
 * ★这里**必须是静态 import**，别再改回 `await import(/* @vite-ignore *\/ mod)`。
 * 那种写法（变量做说明符 + @vite-ignore）等于明确告诉 Vite「别管这个 import」，
 * 于是**裸模块名原样留在了打包产物里**：`import("@tauri-apps/api/core")`。
 * 浏览器/WebView2 解析不了裸说明符（没有 import map），运行期直接抛
 * `Failed to resolve module specifier '@tauri-apps/api/core'`。
 *
 * 后果是整条隧道控制链在**打包后的客户端里全是死的**——tunnel_start / status / stop /
 * open_app_url / force_quit 一个都调不动。点「接入」什么都不会发生：不弹 UAC、
 * 不建网卡、也没有任何服务端痕迹，看起来就像"客户端没反应"。
 *
 * 为什么一直没暴露：dev 走浏览器时 `tauriRuntime()` 为 false，这条路径根本不进；
 * 而打包后的客户端在 2026-08-18 之前从没在真机上被点过「接入」。
 * 同仓库的 Diagnostics.vue 一直是静态 import，能正常工作——两种引法并存，
 * 坏的那种恰好在主链路上。
 */
async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return tauriInvoke<T>(cmd, args as Record<string, unknown>);
}

/** Rust 侧 tunnel_status 回传的原始状态（serde 字段名一一对应 main.rs 的 TunStatus）。导出只为单测。 */
export interface TunStatusRaw {
  running: boolean;
  pid: string;
  log: string;
  /**
   * 最近一条「网关落点」状态行，由 Rust 侧从**整份日志**里捞出来单独带过来。
   *
   * ★不能只靠 log 尾巴解析：落点切换只在切换那一瞬打一行，而之后每条流都会打一行
   * 引流日志（每行上百字节），几十条流之后那一行就被挤出窗口了。丢了它的后果全是
   * 静默的——「已故障转移」横幅消失、接入信息显示回那台已经挂掉的网关、
   * 还可能把未钉扎的隧道显示成「证书钉扎」。老版本 Rust 壳没有这个字段，
   * 此时退回从尾巴里找（能找到多少算多少）。
   */
  endpoint?: string;
  /**
   * 最近一条「数据面健康」行（契约见 gateway/internal/dataplane/dataplane.go 的 logHealth）：
   *   `... msg=数据面健康 knock=true tunnel=false err="网关证书指纹不匹配（疑似中间人）…"`
   * 同样由 Rust 侧（main.rs `last_health_line`，serde 字段名就是 `health`）从**整份日志**里捞出来。
   *
   * ★它才是接入态的真判据。knock / tunnel 记的是**真实事件**（敲门包真的发出去了 /
   * 隧道真的拨通过），err 是最近一次失败的原因（任何一次成功即清空）。此前 ready/keepalive
   * 判的是「数据面就绪」「敲门保活」两行**启动日志**——它们打印于任何一次 knock 与拨号之前，
   * 于是全部落点拨不通 / gm 开关与网关不一致 / 指纹钉扎失败（疑似中间人）三类故障，
   * 界面一律绿色「已接入」。老壳（无此字段）或数据面尚未产生任何事件时为空 / 缺席，
   * 那时才退回旧判据（见 parseTunStatus）。
   */
  health?: string | null;
}

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
  /** 隧道是否**曾**拨通过（健康行 tunnel 位）。null = 不可判定（老壳 / 老数据面没有健康行）。
   *
   *  ★只用于展示，**不是** ready 的判据：Go 侧 `markTunnel()` 只在第一条业务流拨通时才置位，
   *  `Run()` 启动期只敲门、不预拨。一次完全正常的接入，在用户打开第一个应用之前健康行恒为
   *  `knock=true tunnel=false err=-`——拿它当必要条件，界面会停在「接入中」直到 25s 超时报一句
   *  猜的归因，而应用页「访问」闸因 session.connected 为 false 拒绝放行，用户永远产生不出那第一条流。 */
  tunnelUsed: boolean | null;
  denied: boolean;      // 被控制面定性拒绝（强制下线 / 账号禁用锁定）——不可自愈，别重试
  deniedReason: string; // 拒绝原因（人话，供 UI 显著呈现）
  /** stale：运行中隧道用的路由/资源映射与**当前剖面**已经不一致，需重连才生效。
   *
   * ★这是「隧道参数拉起即定死」的必然后果，必须显式呈现出来。最典型的一次是
   * 终端合规降级：降级期间接入 → 隧道里没有高敏资源的 VIP /32 与 DNS 记录 →
   * 修好终端、重新上报、网关侧下一轮就恢复放行，但客户端这半不会重配已建接口，
   * 用户看到的是「已接入、提示已恢复、财务系统还是打不开」，且没有任何线索。
   * 同理还有：管理员新授了一个资源、JIT 审批刚通过、网关重启换了证书指纹。 */
  stale: boolean;
  staleReason: string;  // 差异说明（哪一项变了），人话
  /** 当前用的是第几个网关落点（1 起）/ 共几个 / 它是谁 / 为什么是它。
   *
   * ★这四项**从 baidi-tun 的真实日志里解析**，不是按剖面现算的。落点会在运行期
   * 因故障转移而改变，而剖面里的顺序只是"下次接入会先试谁"。现算的话，一次成功的
   * 容灾在界面上完全看不出来——用户说「我明明连着但很慢」，现场没有任何线索指向
   * 「你现在走的是备用那台异地网关」。 */
  endpointIndex: number;
  endpointTotal: number;
  endpointId: string;
  endpointReason: string;
  lines: string[];      // 最近日志尾巴
}

/** 一个网关落点在客户端侧的形态（就是 baidi-tun 的 -gateways 清单里的一行）。 */
export interface TunEndpoint { id: string; spa: string; proxy: string; pin: string }

/**
 * 由剖面（缺剖面时由本机配置）排出**有序**的网关落点清单。
 *
 * ★顺序原样沿用控制面给的那份，客户端不重排也不过滤：只有控制面知道哪台在线、
 * 该优先给谁；终端手里没有任何能推翻它的材料。离线的落点也照单收下——控制面
 * 看不到心跳与终端连不上它是两回事，砍掉它等于在控制面抖动时自断一条可用退路。
 */
export function resolveEndpoints(): TunEndpoint[] {
  const p = profile.data;
  const list: ProfileGateway[] = p?.gateways?.length ? p.gateways : p?.gateway ? [p.gateway] : [];
  if (!list.length) {
    // 剖面拿不到：退回设置页里那份本机配置试一把（单落点、无钉扎）。
    // 这条路径本身就是降级，接入页会同时显示 profile.error。
    return [{ id: '', spa: `${config.gateway}:${config.spaPort}`, proxy: `${config.gateway}:${config.proxyPort}`, pin: '' }];
  }
  return list.map((g) => ({
    id: g.id || '',
    spa: `${g.host}:${g.spaPort}`,
    proxy: `${g.host}:${g.proxyPort}`,
    pin: g.tunnelPin || ''
  }));
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
  // 网关落点清单（多活 + 故障转移）：首项即首选，其余是按序尝试的备用。
  const eps = resolveEndpoints();
  const gw = eps[0];
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
    // 单落点三件套仍然下传：Rust 侧与 baidi-tun 的 -spa/-proxy/-pin 是旧入口，
    // 保留它们让「装了新客户端、配的却是老 sidecar」不至于一步都走不动。
    // 有 gateways 清单时 baidi-tun 以清单为准（见 loadGateways），不会两头打架。
    gateway: hostOf(gw.spa),
    spaPort: portOf(gw.spa),
    proxyPort: portOf(gw.proxy),
    // gateways 整份交给 Tauri 侧落盘（-gateways），与 resmap/dns-records 同一套写法。
    gateways: JSON.stringify(eps),
    route: routes.join(','),
    ip: p?.tunIp || config.ip,
    gm: config.gm,
    token: session.token,
    // 资源映射表整体交给 Tauri 侧落盘（-resmap）。空对象时传空串，让 Rust 侧
    // 清掉上一轮的遗留文件，避免换用户后仍按旧表路由。
    resmap: p?.resmap && Object.keys(p.resmap).length ? JSON.stringify(p.resmap) : '',
    pin: gw.pin,
    // 与 resmap 同一套写法：记录表整体交给 Tauri 侧落盘（-dns-records）。
    // 空串让 Rust 侧清掉上一轮的遗留文件，避免换用户/换策略后仍按旧记录作答。
    dnsListen: dns?.server?.trim() || '',
    dnsDomains: dns?.domains?.length ? dns.domains.join(',') : '',
    dnsRecords: dns?.records && Object.keys(dns.records).length ? JSON.stringify(dns.records) : '',
    // 终端指纹：随敲门令牌上报给控制面，供「授信终端」准入闸判定。
    // 取的是 posture 采集写进 store 的那一份——与设备台账里那台机器同一个值。
    // 空（还没采过一轮）时不传：控制面在观察模式下照常放行并留痕，严格模式会明确拒绝
    // 并带回原因，好过在这里兜底猜一个与台账对不上的值。
    device: device.id
  };
}

/** 拆 "host:port"（落点地址由控制面下发，形态可控，不做 IPv6 方括号解析）。 */
function hostOf(addr: string): string {
  const i = addr.lastIndexOf(':');
  return i < 0 ? addr : addr.slice(0, i);
}
function portOf(addr: string): string {
  const i = addr.lastIndexOf(':');
  return i < 0 ? '' : addr.slice(i + 1);
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

/**
 * 自助诊断用：数据面**此刻真正在用**的隧道内解析器配置。
 *
 * ★必须取 startedOpts 而不是现算剖面，理由与接入信息那处同源（见上方注释）：
 * 记录表在 baidi-tun 拉起那一刻就定死了。拿刚获批的新域名去探运行中的隧道，
 * 解析器必然回 REFUSED——那是「需重连才生效」，不是解析器故障，
 * 判成红色会把用户引向完全错误的排查方向。
 * 未运行时回当前剖面（那时诊断页对该项本就判 skip，只用于展示"下次会用什么"）。
 */
export function effectiveDNS(running: boolean): { server: string; firstName: string } {
  const eff = running && startedOpts ? startedOpts : resolveTunOpts();
  let firstName = '';
  try {
    const rec = eff.dnsRecords ? (JSON.parse(eff.dnsRecords) as Record<string, string>) : {};
    firstName = Object.keys(rec)[0] || '';
  } catch { /* 记录表解析不了就当没有——诊断页会显示"未启用" */ }
  return { server: eff.dnsListen || '', firstName };
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
  return parseTunStatus(s);
}

/**
 * 把 Rust 侧回传的原始状态解析成接入态。导出只为单测（src/lib/tunnel.test.ts），
 * 生产路径只经 tunnelStatus 调它。
 *
 * ready / keepalive / error 三项的判据**优先取数据面健康行**（TunStatusRaw.health）：
 *   - keepalive：敲门包真的发出去过（knock=true）；
 *   - ready：敲门真成功过，且最近一次事件不是失败（err 为空）。**tunnel 位不参与**——
 *     它只在第一条业务流拨通时才置位（见 TunView.tunnelUsed 的说明），健康的空闲态就是
 *     `knock=true tunnel=false err=-`，把它判成未就绪会让接入停在「接入中」并把应用页锁死；
 *     隧道拨通过一次之后每次都因指纹不匹配拨不通，err 会一直挂着（直到下一次保活敲门），那不是「已接入」；
 *   - error：运行中如实显示 err（改造前 `!s.running && …` 让运行中的失败恒为空串，
 *     指纹钉扎失败 / 敲门被拒 / 隧道拨不通三类故障因此到不了界面）。
 * 健康行缺席（老壳、老数据面、尚无任何事件）时才退回旧判据，且旧判据**逐字不变**。
 */
export function parseTunStatus(s: TunStatusRaw): TunView {
  const log = s.log || '';
  const lines = log.split('\n').map((l) => l.trim()).filter(Boolean);
  const dev = (log.match(/dev=(utun\d+)/) || [])[1] || '';
  // 取最近一条失败（创建/敲门/隧道/退出）作为错误提示（旧判据 / 进程已退出时的兜底）
  const fails = lines.filter((l) => /失败|未敲门成功|panic|fatal|退出/i.test(l));
  const lastFail = fails.length ? stripTs(fails[fails.length - 1]) : '';
  const h = parseHealth(s.health ?? '');
  let ready: boolean;
  let keepalive: boolean;
  let error: string;
  let tunnelUsed: boolean | null;
  if (h) {
    // ready/keepalive 仅在进程存活时才认（进程已退出=旧日志残留，不据此误判）
    keepalive = s.running && h.knock;
    // ★不要求 h.tunnel：那是「曾拨通」的粘性位，空闲的健康接入它恒为 false（Go 侧只在业务流拨通时置位）。
    ready = s.running && h.knock && !h.err;
    // 运行中：健康行里的 err 就是数据面此刻的结论；已退出：优先它，没有再退回日志尾巴。
    error = s.running ? h.err : (h.err || lastFail);
    tunnelUsed = h.tunnel;
  } else {
    // ★旧判据（健康行拿不到时的回落），逐字保留：两行启动日志 + 只在退出后报错。
    ready = s.running && /数据面就绪/.test(log);
    keepalive = s.running && /敲门保活/.test(log);
    error = !s.running && fails.length ? lastFail : '';
    tunnelUsed = null; // 没有健康行就是不可判定，不猜
  }
  // 控制面定性拒绝：dataplane 的 knock.ErrDenied 原文含「接入被拒」，Run 停机前会 warn「接入被控制面拒绝」。
  // 与瞬时失败区别对待——被强制下线/账号禁用不可自愈，UI 应显著提示且不诱导重试。
  const denyLine = lines.filter((l) => /接入被拒|接入被控制面拒绝/.test(l)).pop() || '';
  const denied = !s.running && !!denyLine;
  const deniedReason = denied ? (stripTs(denyLine).match(/接入被拒[：:]\s*(.+)$/)?.[1] || '已被管理员禁止接入').trim() : '';
  // 展示值取「数据面真正在用的那份」：隧道运行中一律用启动时的快照，
  // 只有未运行时才用当前剖面预览（那时展示的是"下次接入会用什么"）。
  // 直接现算当前剖面会把未钉扎的隧道显示成已钉扎，见 startedOpts 的注释。
  const eff = s.running && startedOpts ? startedOpts : resolveTunOpts();
  const { stale, staleReason } = staleAgainstProfile(s.running);
  const ep = parseEndpoint(s.endpoint || '', lines, s.running, eff);
  return {
    running: s.running,
    ready,
    dev,
    vip: eff.ip,
    route: eff.route,
    // 网关地址取**数据面此刻真正在用的那个落点**（故障转移后会变），日志里没有
    // 落点行时才退回启动快照的首选落点。写死首选的话，切换过去之后接入信息会
    // 一直显示那台已经挂掉的网关——排查时所有人都会去查错的那台机器。
    gateway: ep.addr || `${eff.gateway}:${eff.proxyPort}`,
    cipher: config.gm
      ? '国密 TLCP（SM2 / SM4-GCM / SM3）'
      : ep.pin
        ? '通用 TLS 1.3 · 证书钉扎'
        : '通用 TLS 1.3（未钉扎：加密但不认证网关）',
    keepalive,
    error,
    tunnelUsed,
    denied,
    deniedReason,
    stale,
    staleReason,
    endpointIndex: ep.index,
    endpointTotal: ep.total,
    endpointId: ep.id,
    endpointReason: ep.reason,
    lines: lines.slice(-8)
  };
}

/**
 * 从 baidi-tun 日志里解析「当前在用第几个落点」。
 *
 * ★数据面每次选定/切换落点都会打一行结构固定的日志（见 gateway 的 picker.logCurrent）：
 *   `... msg="网关落点切换" endpoint=2/3 id=gw-b addr=10.0.0.2:18443 reason="..."`
 * 取**最后一条**即当前态。契约是双向的：那边改键名要同步改这里的正则，
 * 否则接入页会静默退回「第 1 个落点」——而那恰恰是切换之后最不该显示的信息。
 *
 * ★这一行由 Rust 侧的 tunnel_status 从**整份日志**里捞出来单独送过来（TunStatusRaw.endpoint）：
 * 日志尾巴只有 4000 字节，而切换只打一行、引流日志每条流一行，几十条流就把它冲掉了。
 * 冲掉之后这里会静默退回「第 1 个落点」——而那正是切换之后最不该显示的信息
 * （地址显示成已经挂掉的那台、pin 退回首选那台的指纹，把未钉扎的隧道显示成已钉扎）。
 *
 * 解析不到时（老 baidi-tun、日志还没打出来）退回启动快照：第 1 个 / 共 N 个。
 * 这一步只影响展示，不影响数据面真实行为。
 */
function parseEndpoint(
  endpointLine: string,
  lines: string[],
  running: boolean,
  eff: ReturnType<typeof resolveTunOpts>
) {
  const total = countEndpoints(eff.gateways);
  const fallback = { index: 1, total, id: '', addr: '', pin: eff.pin, reason: '' };
  if (!running) return fallback;
  // 优先用 Rust 侧从整份日志里捞出来的那一行；没有（老壳）才退回尾巴里找。
  const line = /endpoint=\d+\/\d+/.test(endpointLine)
    ? endpointLine
    : lines.filter((l) => /endpoint=\d+\/\d+/.test(l)).pop();
  if (!line) return fallback;
  const m = line.match(/endpoint=(\d+)\/(\d+)/);
  if (!m) return fallback;
  const index = Number(m[1]);
  const id = (line.match(/\bid=("[^"]*"|\S+)/) || [])[1] || '';
  const addr = (line.match(/\baddr=("[^"]*"|\S+)/) || [])[1] || '';
  const reason = (line.match(/\breason=("[^"]*"|\S+)/) || [])[1] || '';
  const eps = parseEndpointList(eff.gateways);
  return {
    index,
    total: Number(m[2]) || total,
    id: unquote(id),
    addr: unquote(addr),
    // 钉扎与否要看**这个落点**的指纹，不是首选落点的：切到一台没上报指纹的备用网关
    // 之后仍显示「证书钉扎」，就等于把一次真实的降级藏了起来。
    pin: eps[index - 1]?.pin ?? eff.pin,
    reason: unquote(reason)
  };
}

function parseEndpointList(raw: string): TunEndpoint[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? (v as TunEndpoint[]) : [];
  } catch {
    return [];
  }
}

function countEndpoints(raw: string): number {
  return parseEndpointList(raw).length || 1;
}

function unquote(s: string): string {
  return s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s;
}

/**
 * 比对「隧道真正在用的那份参数」与「当前剖面会用的那份」，报告是否已经不一致。
 *
 * 只比 baidi-tun **拉起后不会再变**的三项：接管网段、资源映射、DNS 记录。
 * 网关落点/钉扎指纹变了同样要重连，但那属于另一类提示（隧道会自己断），这里不掺进来。
 *
 * ★不做的事：不自动重连。重连要重新提权、会打断在途连接，必须由用户决定；
 * 客户端能做也该做的是**让这件事可见**——静默不一致正是"已接入却打不开"的成因。
 */
function staleAgainstProfile(running: boolean): { stale: boolean; staleReason: string } {
  if (!running || !startedOpts || !profile.data) return { stale: false, staleReason: '' };
  const now = resolveTunOpts();
  const diffs: string[] = [];
  if (now.route !== startedOpts.route) diffs.push('接管网段');
  if (now.resmap !== startedOpts.resmap) diffs.push('资源映射');
  if (now.dnsRecords !== startedOpts.dnsRecords) diffs.push('隧道内 DNS 记录');
  // 落点清单同样在拉起那一刻定死：管理员新加/下线一台网关后，运行中的隧道既不会
  // 把新网关纳入故障转移备选，也不会知道某个备选已经不该用了——容灾余量变了却看不见。
  if (now.gateways !== startedOpts.gateways) diffs.push('网关落点清单');
  if (!diffs.length) return { stale: false, staleReason: '' };
  return {
    stale: true,
    staleReason: `授权范围已变化（${diffs.join('、')}），当前隧道仍在用接入那一刻的参数——断开后重新接入才会生效`
  };
}

/** 健康行解析结果：knock / tunnel 是「真成功过」，err 是最近一次失败（空 = 最近一次事件是成功）。 */
export interface TunHealth { knock: boolean; tunnel: boolean; err: string }

/**
 * 解析「数据面健康」行。拿不到（旧壳 / 尚无事件 / 缺 knock 或 tunnel 字段）返回 null，
 * 调用方退回旧判据——**返回 null 而不是猜一个值**，猜错的两个方向都在界面上看不出来。
 *
 * 行是 slog TextHandler 打的：`time=… level=INFO msg=数据面健康 knock=true tunnel=false err=…`。
 * 容错：键之间多余空白、字段顺序、未知键一律不影响；`err=` 缺席按无错误处理；
 * err 值含空格时 slog 会用 Go 字面量引号包起来（内部 `"` 转成 `\"`），这里还原成人话。
 * `-` 是数据面对「无错误」的占位（见 dataplane.orNone）。
 */
export function parseHealth(line: string | null | undefined): TunHealth | null {
  if (!line) return null;
  const k = /(?:^|\s)knock=(true|false)(?=\s|$)/.exec(line);
  const t = /(?:^|\s)tunnel=(true|false)(?=\s|$)/.exec(line);
  if (!k || !t) return null;
  // err 是行尾自由文本（可能含空格与中文标点），取 `err=` 之后的全部。
  const raw = /(?:^|\s)err=(.*)$/.exec(line)?.[1]?.trim() ?? '';
  const e = unquoteGo(raw);
  return { knock: k[1] === 'true', tunnel: t[1] === 'true', err: e === '-' ? '' : e };
}

/** 还原 slog TextHandler 用 strconv.Quote 包起来的值；未加引号的原样返回。 */
function unquoteGo(v: string): string {
  if (v.length < 2 || !v.startsWith('"') || !v.endsWith('"')) return v;
  return v.slice(1, -1).replace(/\\(["\\nt])/g, (_, c: string) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
}

/**
 * 数据面失败的类别。判据是 Go 侧 `dataplane.knockOne` 给 markFail 的两个固定前缀
 * （`取敲门令牌失败：` / `SPA 拨号失败：`，见 gateway/internal/dataplane/dataplane.go）；
 * 其余一律算 tunnel 类（`dialTunnel` 的原文：拨号超时 / 握手失败 / 指纹不匹配…）。
 * 认不出的前缀**落向 tunnel 类**：那一侧是粘住不清，认错的代价是多显示一会儿，而不是把一条中间人告警擦掉。
 */
export type FailClass = 'knock' | 'tunnel';
export function classifyFail(err: string): FailClass {
  return /^(取敲门令牌失败|SPA 拨号失败)[：:]/.test(err) ? 'knock' : 'tunnel';
}

/** 接入页「数据面报告」提示条的状态（纯数据，由 nextDataplaneNotice 推进）。 */
export interface DataplaneNotice {
  text: string;                     // 失败原文（健康行 err）
  at: number;                       // 最近一次观察到该失败的时刻（ms）
  cls: FailClass;
  tunnelUsedAtFail: boolean | null; // 失败当时的 tunnel 位，用于识别「之后真的拨通了」
}

/**
 * 推进「数据面报告」提示条：决定一条运行中的失败要不要继续显示。
 *
 * ★为什么不能简单地「err 空了就清」：Go 侧 `markKnock()` 与 `markTunnel()` 都无差别地把 lastErr 清空，
 * 而保活敲门每 15s 成功一次。于是「网关证书指纹不匹配（疑似中间人）」这类**隧道拨号失败**在健康行里
 * 最多挂 15s 就被一次与它无关的敲门成功擦掉——按 err 直接渲染，一个持续性的中间人告警在界面上
 * 是一闪而过的红条，用户再点一次应用又闪一次。TS 侧从同一行 `knock=true tunnel=x err=-` 分不出
 * 「被敲门清掉」与「被拨通清掉」，所以按失败类别区分处置：
 *   - knock 类（取令牌 / SPA 拨号）：err 清空意味着一次成功敲门（或拨通），那就是真恢复 → 清；
 *   - tunnel 类：粘住。只有观察到 tunnel 位 false→true（失败时还没拨通过、之后拨通了）才算真恢复；
 *     失败时 tunnel 已是 true 的情形本机无法判定，由用户手动关掉。根治要 Go 侧把 lastErr 按类别拆开
 *     （健康行多带一个键），本轮未改 Go，边界见 docs/ARCHITECTURE.md 第七节。
 * 进程未运行返回 null：退出后的原因走「数据面退出：…」那条独立路径，不归这里。
 */
export function nextDataplaneNotice(prev: DataplaneNotice | null, v: TunView, now: number): DataplaneNotice | null {
  if (!v.running) return null;
  if (v.error) {
    // 新失败，或同一失败再次出现：刷新时间戳（提示条写的是「最近一次」）。
    return { text: v.error, at: now, cls: classifyFail(v.error), tunnelUsedAtFail: v.tunnelUsed };
  }
  if (!prev) return null;
  if (prev.cls === 'knock') return null;
  if (prev.tunnelUsedAtFail === false && v.tunnelUsed === true) return null;
  return prev;
}

function stripTs(l: string): string {
  // 去掉 slog 的 time=... level=... 前缀，留人话
  return l.replace(/^time=\S+\s+level=\S+\s+msg=/, '').replace(/^"|"$/g, '');
}
