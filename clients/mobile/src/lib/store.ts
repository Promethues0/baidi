import { reactive } from 'vue';

const ls = localStorage;

/** 移动端会话与接入状态（终端 Agent 全局状态）。 */
export const session = reactive({
  token: ls.getItem('baidi_m_token') || '',
  user: ls.getItem('baidi_m_user') || '',
  connected: false
});

/**
 * 接入配置（「我的」页可改，持久化）。移动端与桌面端同构，但形态适配原生 VPN 扩展：
 *  - control / gateway 留空 = 用原生壳注入的 apiBase / 下发配置（dev 浏览器走 vite 代理）；
 *  - route / ip / gm / 端口 由本层配置并经 __BAIDI_NATIVE__.startTunnel(token, cfg) 传给原生 VPN 扩展。
 */
export const config = reactive({
  control: ls.getItem('baidi_m_cfg_control') || '',      // 控制中心地址（空=原生注入/dev 代理）
  gateway: ls.getItem('baidi_m_cfg_gateway') || '',      // 安全代理网关主机（空=原生下发）
  spaPort: ls.getItem('baidi_m_cfg_spaport') || '18201',
  proxyPort: ls.getItem('baidi_m_cfg_proxyport') || '18443',
  route: ls.getItem('baidi_m_cfg_route') || '10.99.0.0/24',
  ip: ls.getItem('baidi_m_cfg_ip') || '10.99.0.2',
  gm: (ls.getItem('baidi_m_cfg_gm') ?? '1') === '1'
});

/** 校验接入配置，返回第一条错误文案；全部合法则 null。control/gateway 可留空（原生提供）。 */
export function validateConfig(): string | null {
  const port = (p: string) => { const n = Number(p); return Number.isInteger(n) && n >= 1 && n <= 65535; };
  const c = config.control.trim();
  if (c && !/^https?:\/\/.+/.test(c)) return '控制中心地址须以 http:// 或 https:// 开头（或留空用默认）';
  if (!port(config.spaPort) || !port(config.proxyPort)) return '端口须为 1-65535 的整数';
  if (!/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(config.route.trim())) return '受保护网段须为 CIDR，如 10.99.0.0/24';
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(config.ip.trim())) return '虚拟 IP 须为 IPv4 地址，如 10.99.0.2';
  return null;
}

export function saveConfig(): void {
  ls.setItem('baidi_m_cfg_control', config.control);
  ls.setItem('baidi_m_cfg_gateway', config.gateway);
  ls.setItem('baidi_m_cfg_spaport', config.spaPort);
  ls.setItem('baidi_m_cfg_proxyport', config.proxyPort);
  ls.setItem('baidi_m_cfg_route', config.route);
  ls.setItem('baidi_m_cfg_ip', config.ip);
  ls.setItem('baidi_m_cfg_gm', config.gm ? '1' : '0');
}

export function authed(): boolean { return !!session.token; }

export function login(token: string, user: string): void {
  session.token = token;
  session.user = user;
  ls.setItem('baidi_m_token', token);
  ls.setItem('baidi_m_user', user);
}

export function logout(): void {
  session.token = '';
  session.user = '';
  session.connected = false;
  ls.removeItem('baidi_m_token');
  ls.removeItem('baidi_m_user');
}
