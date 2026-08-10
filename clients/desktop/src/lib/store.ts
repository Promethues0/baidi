import { reactive } from 'vue';
import type { ClientProfile } from './api';

const ls = localStorage;

/**
 * 控制面下发的接入剖面（网关落点 / 路由表 / 资源映射）。登录后拉取，接入时照它执行。
 *
 * ★这是「客户端真正连得通」的权威依据。config 里那些 gateway/route/ip 字段现在只是
 * 剖面不可用时的回退与人工覆盖入口——正常路径下一律以剖面为准，因为只有控制面同时
 * 知道网关在哪、业务在哪、以及当前用户有权访问哪些资源。
 */
export const profile = reactive<{ data: ClientProfile | null; loadedAt: string; error: string }>({
  data: null,
  loadedAt: '',
  error: ''
});

export function setProfile(p: ClientProfile): void {
  profile.data = p;
  profile.loadedAt = new Date().toLocaleTimeString('zh-CN');
  profile.error = '';
}

/**
 * 记下剖面拉取失败的原因，供「接入」页显著呈现。
 *
 * ★保留 profile.data 不清：上一份剖面虽然可能过期，但它比「本机默认单网段」
 * 接近事实得多，清掉等于主动退化成最差配置。代价是页面上可能同时出现
 * 「拉取失败」与基于旧剖面的告警——这正是要让用户看到的状态，故 loadedAt
 * 一并呈现，让「这份数据是什么时候的」有据可查。
 */
export function setProfileError(msg: string): void {
  profile.error = msg;
}

/** 客户端会话与接入状态（终端 Agent 全局状态）。 */
/**
 * 本机终端指纹（collectPosture().device 的最近一次值）。
 *
 * ★放在 store 而不是从 posture.ts 直接取，是为了避免 tunnel.ts ↔ posture.ts 的循环依赖；
 * 更要紧的是让「指纹只有一个来源」在代码结构上成立——posture 上报、登录 deviceId、
 * 敲门令牌三处必须是**同一个值**。三处各采一次的话，管理员在设备台账里批准的那台机器
 * 与敲门时自报的那台可能对不上，严格准入模式下表现为「批了也连不上」，两边日志都正常。
 */
export const device = reactive({ id: '' });

export function setDeviceID(id: string): void {
  device.id = id.trim();
}

export const session = reactive({
  token: ls.getItem('baidi_client_token') || '',
  user: ls.getItem('baidi_client_user') || '',
  connected: false,             // 是否已接入（utun 数据面就绪）
  autostart: ls.getItem('baidi_client_autostart') === '1'
});

/** 接入配置（设置页可改，持久化）。默认对准本机演示（control + gateway 跑在 localhost）。 */
export const config = reactive({
  control: ls.getItem('baidi_cfg_control') || 'http://127.0.0.1:8090', // 控制中心：登录/应用/短时效敲门令牌
  gateway: ls.getItem('baidi_cfg_gateway') || '127.0.0.1',             // 安全代理网关主机
  spaPort: ls.getItem('baidi_cfg_spaport') || '18201',                 // SPA 敲门端口（UDP）
  proxyPort: ls.getItem('baidi_cfg_proxyport') || '18443',             // 隧道代理端口（TCP）
  route: ls.getItem('baidi_cfg_route') || '10.99.0.0/24',             // 引流进隧道的受保护网段
  ip: ls.getItem('baidi_cfg_ip') || '10.99.0.2',                       // utun 虚拟 IP
  gm: (ls.getItem('baidi_cfg_gm') ?? '1') === '1'                      // 国密 TLCP 隧道
});

/** 校验接入配置，返回第一条错误文案；全部合法则 null。接入前与保存时共用。 */
export function validateConfig(): string | null {
  const port = (p: string) => { const n = Number(p); return Number.isInteger(n) && n >= 1 && n <= 65535; };
  if (!/^https?:\/\/.+/.test(config.control.trim())) return '控制中心地址须以 http:// 或 https:// 开头';
  if (!config.gateway.trim()) return '网关地址不能为空';
  if (!port(config.spaPort) || !port(config.proxyPort)) return '端口须为 1-65535 的整数';
  if (!/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(config.route.trim())) return '受保护网段须为 CIDR，如 10.99.0.0/24';
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(config.ip.trim())) return '虚拟 IP 须为 IPv4 地址，如 10.99.0.2';
  return null;
}

export function saveConfig(): void {
  ls.setItem('baidi_cfg_control', config.control);
  ls.setItem('baidi_cfg_gateway', config.gateway);
  ls.setItem('baidi_cfg_spaport', config.spaPort);
  ls.setItem('baidi_cfg_proxyport', config.proxyPort);
  ls.setItem('baidi_cfg_route', config.route);
  ls.setItem('baidi_cfg_ip', config.ip);
  ls.setItem('baidi_cfg_gm', config.gm ? '1' : '0');
}

export function authed(): boolean { return !!session.token; }

export function login(token: string, user: string): void {
  session.token = token;
  session.user = user;
  ls.setItem('baidi_client_token', token);
  ls.setItem('baidi_client_user', user);
}

export function logout(): void {
  session.token = '';
  session.user = '';
  session.connected = false;
  // 剖面是按登录身份下发的（含该用户有权访问的资源），换人必须重拉——
  // 留着旧剖面会让下一个登录者看到上一个人的资源清单。
  profile.data = null;
  profile.loadedAt = '';
  profile.error = '';
  ls.removeItem('baidi_client_token');
  ls.removeItem('baidi_client_user');
}
