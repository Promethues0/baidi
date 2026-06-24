/**
 * 白帝控制台导航 · 对齐《白帝零信任控制中心》设计稿的分组 IA。
 * 四组：监控中心 / 业务管理 / 安全防护 / 系统。
 */
export interface NavLeaf {
  title: string;
  path: string;
  icon: string;                   // Arco 图标组件名
  badge?: string;                 // 右侧角标文案
  badgeKind?: 'count' | 'alert';  // count=灰色计数；alert=红色告警
  done?: boolean;                 // 是否已按设计稿落地（否则 ComingSoon 占位）
}
export interface NavGroup {
  label: string;
  children: NavLeaf[];
}

export const NAV: NavGroup[] = [
  {
    label: '监控中心',
    children: [
      { title: '安全概览', path: '/monitor/overview', icon: 'IconDashboard', done: true },
      { title: '在线用户', path: '/monitor/online', icon: 'IconUser', badge: '10', badgeKind: 'count', done: true },
      { title: '用户状态', path: '/monitor/userstate', icon: 'IconExclamationCircle', badge: '2', badgeKind: 'alert', done: true }
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
