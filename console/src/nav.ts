/**
 * 白帝控制台导航 · 六中心 IA（PRD v1 第 6 章）
 * M1（SSL 先行）：概览 / 身份 / 资源 / 策略 / 网关 / 审计 —— 已点亮 SSL 执行点相关页面，
 * 其余标 soon（占位，随 M1/M2 落地）。
 */
export interface NavLeaf {
  key: string;
  title: string;
  path: string;
  soon?: boolean;
}
export interface NavGroup {
  title: string;
  children: NavLeaf[];
}
export interface NavCenter {
  key: string;
  title: string;
  icon: string; // Arco icon component name
  groups: NavGroup[];
}

export const NAV: NavCenter[] = [
  {
    key: 'overview',
    title: '概览',
    icon: 'IconDashboard',
    groups: [
      { title: '', children: [
        { key: 'ov-monitor', title: '安全监控大屏', path: '/monitor/dashboard' },
        { key: 'ov-home', title: '运行总览', path: '/overview' }
      ] }
    ]
  },
  {
    key: 'identity',
    title: '身份中心',
    icon: 'IconUserGroup',
    groups: [
      {
        title: '账号与组织',
        children: [
          { key: 'id-users', title: '用户管理', path: '/identity/users' },
          { key: 'id-devices', title: '终端设备管理', path: '/identity/devices' },
          { key: 'id-org', title: '组织树', path: '/identity/org' },
          { key: 'id-groups', title: '用户组（动态组）', path: '/identity/groups' }
        ]
      },
      {
        title: '认证',
        children: [
          { key: 'id-auth', title: '认证方式与 MFA', path: '/identity/auth' },
          { key: 'id-idp', title: 'IdP 联邦', path: '/identity/idp' }
        ]
      },
      {
        title: '策略与安全',
        children: [
          { key: 'id-authpolicy', title: '认证策略', path: '/identity/auth-policy' },
          { key: 'id-pwdpolicy', title: '口令策略', path: '/identity/pwd-policy' },
          { key: 'id-secpolicy', title: '账号安全', path: '/identity/sec-policy' },
          { key: 'id-waiver', title: '认证豁免', path: '/identity/waiver' },
          { key: 'id-compliance', title: '终端合规基线', path: '/identity/compliance' }
        ]
      }
    ]
  },
  {
    key: 'resource',
    title: '资源中心',
    icon: 'IconApps',
    groups: [
      {
        title: '资源',
        children: [
          { key: 'rs-objects', title: '统一资源对象', path: '/resource/objects' },
          { key: 'rs-approval', title: '资源审批', path: '/resource/approval' },
          { key: 'rs-portal', title: '应用门户编排', path: '/resource/portal' }
        ]
      },
      {
        title: '对象库',
        children: [{ key: 'rs-lib', title: '地址/服务/时间对象', path: '/resource/library' }]
      }
    ]
  },
  {
    key: 'policy',
    title: '策略中心',
    icon: 'IconSafe',
    groups: [
      {
        title: '访问策略',
        children: [
          { key: 'po-list', title: '统一策略', path: '/policy' },
          { key: 'po-sim', title: '策略仿真器', path: '/policy/simulator' },
          { key: 'po-loginsim', title: '登录流仿真', path: '/policy/login-sim' }
        ]
      },
      {
        title: '主动防御',
        children: [
          { key: 'po-defense', title: '主动防御', path: '/defense/policy' },
          { key: 'po-correlate', title: '关联规则', path: '/defense/correlate' },
          { key: 'po-iprep', title: 'IP 信誉名单', path: '/policy/iprep' }
        ]
      }
    ]
  },
  {
    key: 'gateway',
    title: '网关中心',
    icon: 'IconStorage',
    groups: [
      {
        title: '',
        children: [
          { key: 'gw-list', title: '网关清单', path: '/gateway' },
          { key: 'gw-ssl', title: 'SSL 接入点', path: '/gateway/ssl' },
          { key: 'gw-mesh', title: 'Mesh 中继/连接器', path: '/gateway/mesh' },
          { key: 'gw-ipsec', title: 'IPSec 站点编排', path: '/gateway/ipsec' }
        ]
      }
    ]
  },
  {
    key: 'audit',
    title: '审计中心',
    icon: 'IconHistory',
    groups: [
      {
        title: '',
        children: [
          { key: 'au-events', title: '统一事件', path: '/audit/events' },
          { key: 'au-chain', title: '审计链（HMAC-SM3）', path: '/audit/chain' }
        ]
      }
    ]
  },
  {
    key: 'system',
    title: '系统管理',
    icon: 'IconSettings',
    groups: [
      {
        title: '安全基础设施',
        children: [
          { key: 'sy-certs', title: '证书与密钥', path: '/system/certs' },
          { key: 'sy-license', title: 'License 与容量', path: '/system/license' },
          { key: 'sy-rbac', title: '管理员权限', path: '/system/rbac' }
        ]
      },
      {
        title: '运行与合规',
        children: [
          { key: 'sy-logging', title: '日志外发（Syslog/SNMP）', path: '/system/logging' },
          { key: 'sy-notify', title: '告警通知', path: '/system/notify' },
          { key: 'sy-time', title: '时间与 NTP', path: '/system/time' },
          { key: 'sy-ha', title: '高可用（HA）', path: '/system/ha' },
          { key: 'sy-backup', title: '备份与恢复', path: '/system/backup' },
          { key: 'sy-report', title: '运营报表', path: '/system/report' }
        ]
      },
      {
        title: '诊断',
        children: [{ key: 'sy-diag', title: '系统诊断', path: '/system/diag' }]
      }
    ]
  }
];

export const FIRST_PATH = '/monitor/dashboard';
