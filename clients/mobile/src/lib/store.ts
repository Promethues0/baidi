import { reactive } from 'vue';

const ls = localStorage;

/** 移动端会话与接入状态（终端 Agent 全局状态）。 */
export const session = reactive({
  token: ls.getItem('baidi_m_token') || '',
  user: ls.getItem('baidi_m_user') || '',
  connected: false,
  /** 最近一次**非用户主动**的隧道中断原因（被抢占 / 被系统回收 / 引擎停机），由 vpn.ts 的监视写入；
   *  下一次接入或用户主动断开时清空。非空即意味着「上一段接入不是你断的」，UI 必须当面显示。 */
  dropReason: '',
  /**
   * 「引擎在跑、但数据面没就绪」的原因原文（典型：`取敲门令牌失败：… x509: certificate signed
   * by unknown authority`），由 vpn.ts 的监视按健康行每轮改写；就绪或断开时清空。
   *
   * ★与 dropReason **刻意分开两个字段**：前者说「现在门没敲开」（隧道还在，每 15s 自动重试，
   *   用户该做的是等一会儿或把 CA 装上），后者说「上一段接入不是你断的」（隧道已经没了，
   *   要重新接入）。用户的下一步动作不同，合并成一个字段就只能给出一句必然误导一半人的话。
   *   同理，未就绪**不写 dropReason**——App.vue 会照着它弹「接入已中断」，而这次接入
   *   从来就没有建立过。
   */
  notReady: '',

  /**
   * 隧道类当前失败的原文（健康行 `terr=`；空 = 没有或不可判定）。
   *
   * ★为什么必须单独有它：wave10 把就绪判据从合并的 `err` 收紧成敲门类的 `knockErr` 之后，
   *   一次**持续性**的隧道故障（指纹不匹配「疑似中间人」/ 网关装了隐身规则集却没带 -pf 导致
   *   放行集合永远为空 / gm 开关与网关不一致）不再翻接入态——门确实敲开了。若不另立一格
   *   常驻显示，界面就会安安静静地写着「已接入」，而这条隧道拉不起任何一条业务流：
   *   那正好又是一种「配置齐全、零报错、不生效」。
   *   它**不是**失败态，不参与大环状态，只作为一条常驻横幅（同桌面端 terr 那条）。
   */
  tunnelNote: ''
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
  session.dropReason = '';
  // 未就绪原因也必须清：它挂在 App.vue / Apps.vue / Connect.vue 上，
  // 留着会让下一个登录进来的人看到上一个账号那次接入的失败原文。
  session.notReady = '';
  session.tunnelNote = '';
  ls.removeItem('baidi_m_token');
  ls.removeItem('baidi_m_user');
}
