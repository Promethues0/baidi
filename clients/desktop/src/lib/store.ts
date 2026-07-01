import { reactive } from 'vue';

const ls = localStorage;

/** 客户端会话与接入状态（终端 Agent 全局状态）。 */
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
  ls.removeItem('baidi_client_token');
  ls.removeItem('baidi_client_user');
}
