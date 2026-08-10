/**
 * 白帝控制台导航 · 对齐《白帝零信任控制中心》设计稿的分组 IA。
 * 四组：监控中心 / 业务管理 / 安全防护 / 系统。
 */
export interface NavLeaf {
  title: string;
  path: string;
  icon: string;                   // Arco 图标组件名
  /**
   * 右侧角标的**数据来源键**（不是字面量）。
   *
   * ★这里此前是写死的 '10' / '2'：一个永远显示 10 的"在线用户"角标，
   * 与真实值一致纯属巧合，而它在页面上与真实计数长得一模一样——
   * 假数据里最便宜也最容易长期留存的一种。现在角标值由 AppLayout 按这个键
   * 从真实接口取（见 src/lib/badges.ts），取不到就**不显示**（不显示 0，
   * 也不回落到任何编造值）。
   */
  badgeKey?: BadgeKey;
  badgeKind?: 'count' | 'alert';  // count=灰色计数；alert=红色告警
  done?: boolean;                 // 是否已按设计稿落地（否则 ComingSoon 占位）
}

/** 角标数据源键：online=在线会话数；risk=需关注用户数；alerts=未处理业务告警数。 */
export type BadgeKey = 'online' | 'risk' | 'alerts';
export interface NavGroup {
  label: string;
  children: NavLeaf[];
}

export const NAV: NavGroup[] = [
  {
    label: '监控中心',
    children: [
      { title: '安全概览', path: '/monitor/overview', icon: 'IconDashboard', done: true },
      { title: '业务告警', path: '/monitor/alerts', icon: 'IconNotification', badgeKey: 'alerts', badgeKind: 'alert', done: true },
      { title: '在线用户', path: '/monitor/online', icon: 'IconUser', badgeKey: 'online', badgeKind: 'count', done: true },
      { title: '用户状态', path: '/monitor/userstate', icon: 'IconExclamationCircle', badgeKey: 'risk', badgeKind: 'alert', done: true },
      { title: '设备状态', path: '/monitor/devicestat', icon: 'IconDesktop', done: true }
    ]
  },
  {
    label: '业务管理',
    children: [
      { title: '应用管理', path: '/business/apps', icon: 'IconApps', done: true },
      { title: '策略管理', path: '/business/policy', icon: 'IconSafe', done: true },
      { title: '用户与角色', path: '/business/users', icon: 'IconUserGroup', done: true },
      { title: '认证源接入', path: '/business/auth', icon: 'IconLock', done: true },
      { title: '终端管理', path: '/business/devices', icon: 'IconMobile', done: true },
      { title: 'JIT 即时访问', path: '/business/jit', icon: 'IconThunderbolt', done: true },
      { title: '对象库', path: '/business/objects', icon: 'IconBookmark', done: true }
    ]
  },
  {
    label: '安全防护',
    children: [
      { title: '网关与隐身', path: '/security/gateway', icon: 'IconStorage', done: true },
      { title: 'IPSec 组网', path: '/security/ipsec', icon: 'IconLink', done: true },
      { title: '资源策略', path: '/security/resources', icon: 'IconRelation', done: true },
      { title: '安全中心', path: '/security/center', icon: 'IconSafe', done: true },
      { title: '审计中心', path: '/security/audit', icon: 'IconFile', done: true }
    ]
  },
  {
    label: '系统',
    children: [
      { title: '系统管理', path: '/system/manage', icon: 'IconSettings', done: true }
    ]
  }
];

export const FIRST_PATH = '/monitor/overview';

/** 由路径反查所属分组与叶子（面包屑/标题用）。 */
export function locate(path: string): { group?: NavGroup; leaf?: NavLeaf } {
  for (const g of NAV) {
    const leaf = g.children.find((c) => c.path === path);
    if (leaf) return { group: g, leaf };
  }
  return {};
}
