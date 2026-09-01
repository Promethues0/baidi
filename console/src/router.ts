import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import AppLayout from '@/layout/AppLayout.vue';
import { NAV, FIRST_PATH } from '@/nav';
import { getToken } from '@/lib/api';

// 已按设计稿落地的页面 → 真实组件；其余 NAV 叶子 → ComingSoon 占位
const BUILT: Record<string, RouteRecordRaw['component']> = {
  '/monitor/overview': () => import('@/views/Overview.vue'),
  '/monitor/alerts': () => import('@/views/Alerts.vue'),
  '/monitor/online': () => import('@/views/Online.vue'),
  '/monitor/userstate': () => import('@/views/UserState.vue'),
  '/monitor/devicestat': () => import('@/views/DeviceStat.vue'),
  '/business/policy': () => import('@/views/Policy.vue'),
  '/business/objects': () => import('@/views/Objects.vue'),
  '/security/ipsec': () => import('@/views/Ipsec.vue'),
  '/security/nat': () => import('@/views/Nat.vue'),
  '/system/upgrade': () => import('@/views/Upgrade.vue'),
  '/business/apps': () => import('@/views/Apps.vue'),
  '/business/users': () => import('@/views/Users.vue'),
  '/business/devices': () => import('@/views/Devices.vue'),
  '/business/jit': () => import('@/views/Jit.vue'),
  '/business/auth': () => import('@/views/Auth.vue'),
  '/security/audit': () => import('@/views/Audit.vue'),
  '/security/report': () => import('@/views/Reports.vue'),
  '/security/gateway': () => import('@/views/Gateway.vue'),
  '/security/resources': () => import('@/views/Resources.vue'),
  '/security/center': () => import('@/views/Security.vue'),
  '/system/manage': () => import('@/views/System.vue')
};

const leafRoutes: RouteRecordRaw[] = NAV.flatMap((g) =>
  g.children.map((c): RouteRecordRaw => ({
    path: c.path.slice(1),
    component: BUILT[c.path] ?? (() => import('@/views/ComingSoon.vue'))
  }))
);

const routes: RouteRecordRaw[] = [
  // 管理员登录
  { path: '/login', component: () => import('@/views/Login.vue') },
  // 终端用户门户（B/S 免客户端，独立于管理控制台 chrome）
  { path: '/portal/login', component: () => import('@/views/PortalLogin.vue') },
  { path: '/portal', redirect: '/portal/apps' },
  { path: '/portal/apps', component: () => import('@/views/PortalApps.vue') },
  { path: '/portal/requests', component: () => import('@/views/PortalRequests.vue') },
  { path: '/portal/security', component: () => import('@/views/PortalSecurity.vue') },
  { path: '/portal/downloads', component: () => import('@/views/PortalDownloads.vue') },
  // 态势大屏（全屏 NOC，脱离控制台 chrome；非 public，受登录守卫保护）
  { path: '/screen', component: () => import('@/views/BigScreen.vue') },
  // 运维诊断（系统自检，脱离控制台 chrome；非 public，受登录守卫保护）
  { path: '/diag', component: () => import('@/views/Diag.vue') },
  {
    path: '/',
    component: AppLayout,
    redirect: FIRST_PATH,
    children: [
      ...leafRoutes,
      { path: ':pathMatch(.*)*', component: () => import('@/views/ComingSoon.vue') }
    ]
  }
];

const router = createRouter({ history: createWebHistory(), routes });

// 免登录路径白名单：只有两个登录页与公开的下载中心真正免认证。
// ★不能把 /portal/* 整段视为 public——门户里的「我的申请」「我的安全」（passkey 管理）
// 都是需要身份的页面，整段豁免会让它们裸奔。
const PUBLIC_PATHS = new Set(['/login', '/portal/login', '/portal/downloads']);

/**
 * 令牌里的角色（**只用于路由分流，不是安全判定**）。
 *
 * ★这里不做签名校验，也不该做：前端没有公钥，也永远不该成为判定方。
 * 真正的闸是后端 auth.Middleware + requireAdmin/requirePerm——把这段删掉，
 * 系统的安全性一点不变。它解决的是另一个问题：门户终端用户（role=user）
 * 登录后直接访问 /monitor/overview 时，此前守卫只看"有没有 token"就放行，
 * 于是他会看到一整套**管理台外壳**（21 个菜单、侧栏角标、系统管理入口），
 * 每一页再逐个报 403。既像是权限漏了，也让人以为自己该有这些菜单。
 */
function tokenRole(): string {
  const t = getToken();
  if (!t) return '';
  try {
    const seg = t.split('.')[1];
    if (!seg) return '';
    const json = atob(seg.replace(/-/g, '+').replace(/_/g, '/'));
    return String((JSON.parse(json) as { role?: string }).role ?? '');
  } catch {
    return ''; // 解不出来就当不可判定：不拦（真闸在后端）
  }
}

// 登录守卫：非白名单路由需已登录；门户页未登录回门户登录页，管理台回管理台登录页。
router.beforeEach((to) => {
  if (PUBLIC_PATHS.has(to.path)) return true;
  if (!getToken()) return to.path.startsWith('/portal') ? '/portal/login' : '/login';
  // 终端用户不进管理台外壳（含大屏与运维诊断）——把他送回门户，而不是让他
  // 在一套点不动的管理菜单里逐页碰 403。★只在**确定**是 user 时分流：
  // 解不出角色（旧令牌 / 格式变化）一律放行，宁可多显示也不误伤管理员。
  if (!to.path.startsWith('/portal') && tokenRole() === 'user') return '/portal/apps';
  return true;
});

export default router;
