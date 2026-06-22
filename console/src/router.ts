import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import AppLayout from '@/layout/AppLayout.vue';

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    component: AppLayout,
    redirect: '/monitor/dashboard',
    children: [
      { path: 'overview', component: () => import('@/views/Overview.vue'), meta: { title: '运行总览' } },
      { path: 'monitor/dashboard', component: () => import('@/views/MonitorDashboard.vue'), meta: { title: '安全监控大屏' } },
      { path: 'policy', component: () => import('@/views/Policy.vue'), meta: { title: '统一策略' } },
      { path: 'policy/simulator', component: () => import('@/views/PolicySimulator.vue'), meta: { title: '策略仿真器' } },
      { path: 'defense/policy', component: () => import('@/views/DefensePolicy.vue'), meta: { title: '主动防御' } },
      { path: 'policy/login-sim', component: () => import('@/views/LoginFlowSim.vue'), meta: { title: '登录流仿真' } },
      { path: 'policy/iprep', component: () => import('@/views/IdentityIPRep.vue'), meta: { title: 'IP 信誉名单' } },
      { path: 'defense/correlate', component: () => import('@/views/DefenseCorrelate.vue'), meta: { title: '关联规则' } },
      { path: 'gateway', component: () => import('@/views/Gateways.vue'), meta: { title: '网关清单' } },
      { path: 'identity/users', component: () => import('@/views/IdentityUsers.vue'), meta: { title: '用户管理' } },
      { path: 'identity/devices', component: () => import('@/views/IdentityDevices.vue'), meta: { title: '终端设备管理' } },
      { path: 'identity/org', component: () => import('@/views/IdentityOrg.vue'), meta: { title: '组织树' } },
      { path: 'identity/groups', component: () => import('@/views/IdentityGroups.vue'), meta: { title: '用户组（动态组）' } },
      { path: 'identity/auth', component: () => import('@/views/IdentityAuth.vue'), meta: { title: '认证方式与 MFA' } },
      { path: 'identity/auth-policy', component: () => import('@/views/IdentityAuthPolicy.vue'), meta: { title: '认证策略' } },
      { path: 'identity/pwd-policy', component: () => import('@/views/IdentityPwdPolicy.vue'), meta: { title: '口令策略' } },
      { path: 'identity/sec-policy', component: () => import('@/views/IdentitySecPolicy.vue'), meta: { title: '账号安全' } },
      { path: 'identity/waiver', component: () => import('@/views/IdentityWaiver.vue'), meta: { title: '认证豁免' } },
      { path: 'identity/compliance', component: () => import('@/views/IdentityCompliance.vue'), meta: { title: '终端合规基线' } },
      { path: 'identity/idp', component: () => import('@/views/IdentityIdp.vue'), meta: { title: 'IdP 联邦' } },
      { path: 'resource/objects', component: () => import('@/views/ResourceObjects.vue'), meta: { title: '统一资源对象' } },
      // 资源授权已并入统一策略「按资源」视图（点3 去冗余）；旧路径重定向，appauth 后端已退役
      { path: 'resource/auth', redirect: '/policy?view=resource' },
      { path: 'resource/approval', component: () => import('@/views/ResourceApproval.vue'), meta: { title: '资源审批' } },
      { path: 'resource/portal', component: () => import('@/views/ResourcePortal.vue'), meta: { title: '应用门户编排' } },
      { path: 'resource/library', component: () => import('@/views/ResourceLibrary.vue'), meta: { title: '对象库' } },
      { path: 'gateway/ssl', component: () => import('@/views/GatewaySsl.vue'), meta: { title: 'SSL 接入点' } },
      { path: 'gateway/mesh', component: () => import('@/views/GatewayMesh.vue'), meta: { title: 'Mesh 中继/连接器' } },
      { path: 'gateway/ipsec', component: () => import('@/views/GatewayIpsec.vue'), meta: { title: 'IPSec 站点编排' } },
      { path: 'audit/events', component: () => import('@/views/AuditEvents.vue'), meta: { title: '统一事件' } },
      { path: 'audit/chain', component: () => import('@/views/AuditChain.vue'), meta: { title: '审计链' } },
      { path: 'system/certs', component: () => import('@/views/SystemCerts.vue'), meta: { title: '证书与密钥' } },
      { path: 'system/license', component: () => import('@/views/SystemLicense.vue'), meta: { title: 'License 与容量' } },
      { path: 'system/logging', component: () => import('@/views/SystemLogging.vue'), meta: { title: '日志外发' } },
      { path: 'system/notify', component: () => import('@/views/SystemNotify.vue'), meta: { title: '告警通知' } },
      { path: 'system/rbac', component: () => import('@/views/IdentityRBAC.vue'), meta: { title: '管理员权限' } },
      { path: 'system/report', component: () => import('@/views/SystemReport.vue'), meta: { title: '运营报表' } },
      { path: 'system/time', component: () => import('@/views/SystemTime.vue'), meta: { title: '时间与 NTP' } },
      { path: 'system/ha', component: () => import('@/views/SystemHA.vue'), meta: { title: '高可用' } },
      { path: 'system/backup', component: () => import('@/views/SystemBackup.vue'), meta: { title: '备份与恢复' } },
      { path: 'system/diag', component: () => import('@/views/SystemDiag.vue'), meta: { title: '系统诊断' } },
      // 其余路径统一落到占位页（含 soon 项与未单独建页的叶子）
      { path: ':pathMatch(.*)*', component: () => import('@/views/ComingSoon.vue'), meta: { title: '建设中' } }
    ]
  }
];

export default createRouter({
  history: createWebHistory(),
  routes
});
