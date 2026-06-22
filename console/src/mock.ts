/** 白帝控制台演示数据（M1）。后续接入控制面 gRPC-gateway 时替换为真实 API。 */

export const overviewStats = [
  { label: '在线设备', value: 1284, unit: '台', trend: '+36' },
  { label: '活跃会话', value: 942, unit: '', trend: '+12' },
  { label: '今日策略命中', value: 18630, unit: '', trend: '' },
  { label: '威胁/阻断事件', value: 7, unit: '起', trend: '-2', tone: 'warn' as const }
];

export interface Gateway {
  name: string;
  role: string;
  modes: ('ssl' | 'mesh' | 'ipsec')[];
  status: 'online' | 'degraded' | 'offline';
  cpu: number;
  mem: number;
  sessions: number;
  version: string;
}
export const gateways: Gateway[] = [
  { name: 'zl-gw-hq-01', role: 'ALL-IN-ONE', modes: ['ssl', 'mesh', 'ipsec'], status: 'online', cpu: 41, mem: 63, sessions: 612, version: 'v0.1.0' },
  { name: 'zl-gw-dmz-02', role: '接入网关', modes: ['ssl', 'mesh'], status: 'online', cpu: 58, mem: 71, sessions: 330, version: 'v0.1.0' },
  { name: 'zl-gw-branch-sh', role: '站点网关', modes: ['ipsec', 'mesh'], status: 'degraded', cpu: 22, mem: 49, sessions: 0, version: 'v0.1.0' },
  { name: 'zl-gw-branch-gz', role: '站点网关', modes: ['ipsec'], status: 'offline', cpu: 0, mem: 0, sessions: 0, version: 'v0.1.0' }
];

export const trafficSeries = {
  hours: ['14:00', '14:10', '14:20', '14:30', '14:40', '14:50', '15:00'],
  ssl: [4.2, 6.8, 9.1, 7.4, 11.2, 13.6, 12.1],
  mesh: [8.1, 7.6, 6.9, 9.2, 8.8, 7.1, 9.6],
  ipsec: [2.1, 2.4, 2.2, 2.8, 3.1, 2.6, 2.9]
};

export interface PolicyRow {
  id: string;
  subjects: string[];
  resources: string[];
  action: 'allow' | 'deny';
  conditions: string[];
  modes: string;
  hits: number;
  enabled: boolean;
}
export const policies: PolicyRow[] = [
  { id: 'pol-rd-database', subjects: ['group:研发-动态', 'tag:ci-runner'], resources: ['service:db.corp:5432', 'app:gitlab'], action: 'allow', conditions: ['posture: disk_encrypted', 'auth: mfa'], modes: 'auto', hits: 4210, enabled: true },
  { id: 'pol-oa-all', subjects: ['group:全体员工'], resources: ['app:oa.corp'], action: 'allow', conditions: [], modes: 'ssl', hits: 12880, enabled: true },
  { id: 'pol-branch-erp', subjects: ['site:上海分支'], resources: ['subnet:10.20.0.0/16'], action: 'allow', conditions: [], modes: 'ipsec', hits: 1340, enabled: true },
  { id: 'pol-finance-deny-byod', subjects: ['group:BYOD'], resources: ['app:finance'], action: 'deny', conditions: [], modes: 'auto', hits: 96, enabled: true },
  { id: 'pol-ops-ssh', subjects: ['group:运维'], resources: ['service:*.corp:22'], action: 'allow', conditions: ['auth: mfa', 'time: workhours'], modes: 'mesh', hits: 220, enabled: false }
];

export const users = [
  { name: '张伟', account: 'zhang.wei', org: '研发中心 / 平台组', auth: ['密码', 'TOTP'], devices: 2, status: 'active' },
  { name: '李娜', account: 'li.na', org: '财务中心', auth: ['SSO', 'WebAuthn'], devices: 1, status: 'active' },
  { name: '王强', account: 'wang.qiang', org: '运维中心', auth: ['密码', 'TOTP'], devices: 3, status: 'active' },
  { name: '陈静', account: 'chen.jing', org: '研发中心 / 移动组', auth: ['扫码'], devices: 1, status: 'locked' },
  { name: 'ci-runner-01', account: 'svc.ci', org: '服务账号', auth: ['证书'], devices: 1, status: 'active' }
];

export interface ResourceObj {
  name: string;
  type: 'app' | 'service' | 'subnet' | 'node' | 'site';
  addr: string;
  modes: string;
  health: 'up' | 'down' | 'unknown';
  stepup: boolean;
  allowSelfRequest?: boolean;
}
export const resources: ResourceObj[] = [
  { name: 'OA 办公系统', type: 'app', addr: 'https://oa.corp', modes: 'ssl', health: 'up', stepup: false },
  { name: 'GitLab', type: 'app', addr: 'https://gitlab.corp', modes: 'auto', health: 'up', stepup: false },
  { name: '核心数据库', type: 'service', addr: 'db.corp:5432', modes: 'auto', health: 'up', stepup: true, allowSelfRequest: true },
  { name: '财务系统', type: 'app', addr: 'https://finance.corp', modes: 'ssl', health: 'up', stepup: true },
  { name: '上海分支网段', type: 'subnet', addr: '10.20.0.0/16', modes: 'ipsec', health: 'unknown', stepup: false },
  { name: '堡垒机 SSH', type: 'service', addr: 'bastion.corp:22', modes: 'mesh', health: 'down', stepup: true }
];

export interface AuditEvent {
  ts: string;
  actor: string;
  device: string;
  resource: string;
  mode: 'ssl' | 'mesh' | 'ipsec';
  decision: 'allow' | 'deny';
  policy: string;
}
export const auditEvents: AuditEvent[] = [
  { ts: '15:02:11', actor: 'zhang.wei', device: 'MBP-7F2A', resource: 'app:gitlab', mode: 'mesh', decision: 'allow', policy: 'pol-rd-database' },
  { ts: '15:02:03', actor: 'li.na', device: 'iPhone-92', resource: 'app:oa.corp', mode: 'ssl', decision: 'allow', policy: 'pol-oa-all' },
  { ts: '15:01:55', actor: 'BYOD-tablet', device: 'Pad-1180', resource: 'app:finance', mode: 'ssl', decision: 'deny', policy: 'pol-finance-deny-byod' },
  { ts: '15:01:40', actor: 'svc.ci', device: 'ci-runner-01', resource: 'service:db.corp:5432', mode: 'mesh', decision: 'allow', policy: 'pol-rd-database' },
  { ts: '15:01:22', actor: '上海分支', device: 'gw-branch-sh', resource: 'subnet:10.20.0.0/16', mode: 'ipsec', decision: 'allow', policy: 'pol-branch-erp' },
  { ts: '15:00:58', actor: 'wang.qiang', device: 'WS-330', resource: 'service:bastion.corp:22', mode: 'mesh', decision: 'deny', policy: 'pol-ops-ssh' }
];

/* ── IdP 联邦（PRD 第 5 章 / PDP-11）── */
export interface IdpConfig {
  name: string;
  protocol: 'OIDC' | 'SAML' | 'LDAP';
  kind: string;
  issuer: string;
  jit: boolean;
  users: number;
  status: 'active' | 'error' | 'disabled';
}
export const idps: IdpConfig[] = [
  { name: '钉钉（集团主）', protocol: 'OIDC', kind: '钉钉', issuer: 'https://oapi.dingtalk.com', jit: true, users: 1180, status: 'active' },
  { name: '企业微信（子公司）', protocol: 'OIDC', kind: '企微', issuer: 'https://open.work.weixin.qq.com', jit: true, users: 312, status: 'active' },
  { name: '集团 AD', protocol: 'LDAP', kind: 'AD/LDAP', issuer: 'ldaps://ad.corp:636', jit: false, users: 1496, status: 'active' },
  { name: '合作方 Okta', protocol: 'SAML', kind: '标准 SAML', issuer: 'https://partner.okta.com', jit: true, users: 28, status: 'error' },
  { name: '飞书（试点）', protocol: 'OIDC', kind: '飞书', issuer: 'https://open.feishu.cn', jit: true, users: 0, status: 'disabled' }
];
export const sdkFederation = {
  enabled: true,
  audiences: ['baidi-sdk'],
  grantTtlMin: 10,
  maxDevices: 5,
  evictPolicy: 'LRU 踢最旧',
  ephemeralGc: true,
  sessions24h: 437,
  jtiReplayBlocked: 3
};

/* ── IPSec 站点编排（V5 并入 / PRD 6.3）── */
export interface IpsecTunnel {
  id: string;
  local: string;
  remote: string;
  selectors: string[];
  ike: 'IKEv2' | 'IKEv1';
  suite: '国密 SM2/SM3/SM4' | 'AES-GCM/SHA2' | string;
  status: 'established' | 'connecting' | 'down';
  childSa: number;
  rekeyIn: string;
  rx: string;
  tx: string;
  // 高级组网参数（可选，真实策略回填用）
  natt?: boolean;
  pfs?: boolean;
  pfsGroup?: string;
  dpd?: string;
  lifetime?: string;
  topology?: string;
  errCode?: string;
}
export const ipsecTunnels: IpsecTunnel[] = [
  { id: 'tun-hq-sh', local: 'zl-gw-hq-01', remote: '上海分支 · zl-gw-branch-sh', selectors: ['10.8.0.0/16 ↔ 10.20.0.0/16'], ike: 'IKEv2', suite: '国密 SM2/SM3/SM4', status: 'established', childSa: 2, rekeyIn: '42 分钟', rx: '38.2 GB', tx: '21.7 GB' },
  { id: 'tun-hq-gz', local: 'zl-gw-hq-01', remote: '广州分支 · zl-gw-branch-gz', selectors: ['10.8.0.0/16 ↔ 10.30.0.0/16'], ike: 'IKEv2', suite: '国密 SM2/SM3/SM4', status: 'down', childSa: 0, rekeyIn: '—', rx: '0', tx: '0' },
  { id: 'tun-hq-cloud', local: 'zl-gw-dmz-02', remote: '阿里云 VPC · vpn-gw-ali', selectors: ['10.8.0.0/16 ↔ 172.16.0.0/12'], ike: 'IKEv2', suite: 'AES-GCM/SHA2', status: 'established', childSa: 1, rekeyIn: '18 分钟', rx: '102.4 GB', tx: '96.1 GB' },
  { id: 'tun-sh-partner', local: 'zl-gw-branch-sh', remote: '合作方机房 · partner-fw', selectors: ['10.20.5.0/24 ↔ 192.168.77.0/24'], ike: 'IKEv2', suite: 'AES-GCM/SHA2', status: 'connecting', childSa: 0, rekeyIn: '—', rx: '0', tx: '0' }
];
export const ikeLifecycle = [
  { phase: 'IKE_SA_INIT', desc: '密钥交换与算法协商', state: 'done' },
  { phase: 'IKE_AUTH', desc: '身份认证（证书/PSK）', state: 'done' },
  { phase: 'CHILD_SA', desc: '建立数据面 SA · selector 下发', state: 'done' },
  { phase: 'REKEY', desc: '周期性重协商（前向保密）', state: 'pending' }
];

/* ── 审计链 HMAC-SM3（ZL-FR-109 / V5 模式）── */
export interface ChainBlock {
  seq: number;
  range: string;
  events: number;
  hash: string;
  prevHash: string;
}
export const chainBlocks: ChainBlock[] = [
  { seq: 1024, range: '15:00 – 15:10', events: 482, hash: 'a3f8c91d', prevHash: '7b22e04f' },
  { seq: 1023, range: '14:50 – 15:00', events: 519, hash: '7b22e04f', prevHash: 'c4d10a88' },
  { seq: 1022, range: '14:40 – 14:50', events: 444, hash: 'c4d10a88', prevHash: '912bfe3a' },
  { seq: 1021, range: '14:30 – 14:40', events: 503, hash: '912bfe3a', prevHash: '5e77cd02' },
  { seq: 1020, range: '14:20 – 14:30', events: 467, hash: '5e77cd02', prevHash: '08a1b6e9' }
];

/* ── Mesh 模式（M2 点亮 · doc 02 / DP-01 路径B）── */
// 拓扑节点：网关(中继+连接器) / 设备 / 子网。坐标为视图固定布局（非物理引擎）。
export interface MeshNode {
  id: string; label: string; kind: 'gateway' | 'device' | 'subnet';
  x: number; y: number; os?: string; nat?: string; relay?: boolean; connector?: boolean;
}
export const meshNodes: MeshNode[] = [
  { id: 'gw-hq', label: 'zl-gw-hq-01', kind: 'gateway', x: 430, y: 230, relay: true, connector: true },
  { id: 'mbp', label: 'MBP-7F2A · 张伟', kind: 'device', x: 200, y: 110, os: 'macOS', nat: 'EIM(易穿透)' },
  { id: 'ws', label: 'WS-330 · 王强', kind: 'device', x: 660, y: 110, os: 'Windows', nat: 'EIM(易穿透)' },
  { id: 'ci', label: 'ci-runner-01', kind: 'device', x: 700, y: 360, os: 'Ubuntu', nat: '公网' },
  { id: 'pad', label: 'Pad-1180 · 陈静', kind: 'device', x: 285, y: 420, os: 'HarmonyOS', nat: 'Symmetric(难穿透)' },
  { id: 'srv', label: 'SRV-OPS · 王强', kind: 'device', x: 430, y: 70, os: 'Kylin', nat: 'EIM(易穿透)' },
  { id: 'subnet-sh', label: '10.20.0.0/16 上海', kind: 'subnet', x: 430, y: 420 }
];
// 边：direct = P2P 直连(WireGuard)，relay = 经 derp 中继回退，route = 子网路由
export interface MeshEdge { a: string; b: string; type: 'direct' | 'relay' | 'route'; rtt: string; }
export const meshEdges: MeshEdge[] = [
  { a: 'mbp', b: 'ws', type: 'direct', rtt: '12ms' },
  { a: 'mbp', b: 'srv', type: 'direct', rtt: '8ms' },
  { a: 'mbp', b: 'ci', type: 'direct', rtt: '23ms' },
  { a: 'ws', b: 'srv', type: 'direct', rtt: '9ms' },
  { a: 'ws', b: 'ci', type: 'direct', rtt: '18ms' },
  { a: 'srv', b: 'ci', type: 'direct', rtt: '15ms' },
  { a: 'pad', b: 'gw-hq', type: 'relay', rtt: '41ms' },   // 对称 NAT → 中继回退
  { a: 'pad', b: 'mbp', type: 'relay', rtt: '46ms' },
  { a: 'gw-hq', b: 'subnet-sh', type: 'route', rtt: '—' },
  { a: 'mbp', b: 'subnet-sh', type: 'route', rtt: '—' }
];
export const meshStats = { nodes: 6, directRatio: 82, relayFallback: 2, derpRegions: 3, subnetRoutes: 1 };

export interface DerpRelay { region: string; addr: string; sessions: number; bytesRelayed: string; status: 'up' | 'up' }
export const derpRelays: DerpRelay[] = [
  { region: '华东(总部)', addr: 'zl-gw-hq-01:3478', sessions: 2, bytesRelayed: '1.4 GB', status: 'up' },
  { region: '华南(DMZ)', addr: 'zl-gw-dmz-02:3478', sessions: 0, bytesRelayed: '0', status: 'up' },
  { region: '内置兜底', addr: 'derp.baidi.internal:3478', sessions: 0, bytesRelayed: '0', status: 'up' }
];
export interface Connector { name: string; gateway: string; routes: string[]; mode: string; status: 'online' | 'offline'; }
export const connectors: Connector[] = [
  { name: 'conn-sh-01', gateway: 'zl-gw-branch-sh', routes: ['10.20.0.0/16'], mode: '子网路由(advertise)', status: 'online' },
  { name: 'conn-hq-01', gateway: 'zl-gw-hq-01', routes: ['10.8.0.0/16', '192.168.1.0/24'], mode: '子网路由(advertise)', status: 'online' }
];
