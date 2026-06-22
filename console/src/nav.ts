/**
 * 白帝控制台导航 · 围绕「一次零信任访问决策的生命周期」组织（区别于烛龙六中心功能字典）。
 * 七大工作域：态势 → 访问者 → 资源 → 策略 → 网关 → 洞察 → 系统。
 */
export interface NavLeaf {
  title: string;
  path: string;
  done?: boolean; // 是否已按白帝规范重做（否则落 ComingSoon 占位）
}
export interface NavGroup {
  key: string;
  title: string;
  icon: string; // Arco 图标组件名
  children: NavLeaf[];
}

export const NAV: NavGroup[] = [
  {
    key: 'posture', title: '态势', icon: 'IconDashboard',
    children: [
      { title: '安全监控大屏', path: '/posture/dashboard', done: true },
      { title: '运行总览', path: '/posture/overview' }
    ]
  },
  {
    key: 'subject', title: '访问者', icon: 'IconUserGroup',
    children: [
      { title: '用户目录', path: '/subject/users' },
      { title: '组织与角色', path: '/subject/orgs' },
      { title: '认证源与策略', path: '/subject/auth' },
      { title: '终端设备与信任', path: '/subject/devices' },
      { title: '终端合规基线', path: '/subject/baseline' }
    ]
  },
  {
    key: 'resource', title: '资源', icon: 'IconApps',
    children: [
      { title: '应用发布', path: '/resource/apps' },
      { title: '应用授权', path: '/resource/authz' },
      { title: '权限审批', path: '/resource/approval' },
      { title: '对象库', path: '/resource/objects' }
    ]
  },
  {
    key: 'policy', title: '策略', icon: 'IconSafe',
    children: [
      { title: '全局策略', path: '/policy/global' },
      { title: '用户策略', path: '/policy/user' },
      { title: '安全基线', path: '/policy/baseline' },
      { title: '策略仿真器', path: '/policy/simulator' }
    ]
  },
  {
    key: 'gateway', title: '网关', icon: 'IconStorage',
    children: [
      { title: '区域与节点', path: '/gateway/zones' },
      { title: 'SSL 接入', path: '/gateway/ssl' },
      { title: 'IPSec 组网', path: '/gateway/ipsec' },
      { title: '地址转换 NAT', path: '/gateway/nat' },
      { title: 'SPA 服务隐身', path: '/gateway/spa' }
    ]
  },
  {
    key: 'insight', title: '洞察', icon: 'IconHistory',
    children: [
      { title: '统一日志', path: '/insight/logs' },
      { title: '高级查询与导出', path: '/insight/export' },
      { title: '审计链', path: '/insight/chain' },
      { title: '日志外送', path: '/insight/forward' }
    ]
  },
  {
    key: 'system', title: '系统', icon: 'IconSettings',
    children: [
      { title: '管理员（三权分立）', path: '/system/admins' },
      { title: '证书与密钥', path: '/system/certs' },
      { title: 'License', path: '/system/license' },
      { title: '集群', path: '/system/cluster' },
      { title: '升级', path: '/system/upgrade' },
      { title: '开放平台', path: '/system/openapi' }
    ]
  }
];

export const FIRST_PATH = '/posture/dashboard';

/** 由路径反查所属分组与叶子标题（面包屑/标题用）。 */
export function locate(path: string): { group?: NavGroup; leaf?: NavLeaf } {
  for (const g of NAV) {
    const leaf = g.children.find((c) => c.path === path);
    if (leaf) return { group: g, leaf };
  }
  return {};
}
