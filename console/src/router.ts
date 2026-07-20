import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import AppLayout from '@/layout/AppLayout.vue';
import { NAV, FIRST_PATH } from '@/nav';
import { getToken } from '@/lib/api';

// 已按设计稿落地的页面 → 真实组件；其余 NAV 叶子 → ComingSoon 占位
const BUILT: Record<string, RouteRecordRaw['component']> = {
  '/monitor/overview': () => import('@/views/Overview.vue'),
  '/monitor/online': () => import('@/views/Online.vue'),
  '/monitor/userstate': () => import('@/views/UserState.vue'),
  '/business/policy': () => import('@/views/Policy.vue'),
  '/business/objects': () => import('@/views/Objects.vue'),
  '/security/ipsec': () => import('@/views/Ipsec.vue'),
  '/business/apps': () => import('@/views/Apps.vue'),
  '/business/users': () => import('@/views/Users.vue'),
  '/business/devices': () => import('@/views/Devices.vue'),
  '/business/auth': () => import('@/views/Auth.vue'),
  '/security/audit': () => import('@/views/Audit.vue'),
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

// 管理台登录守卫：非 /login、非 /portal/* 的路由需已登录，否则跳登录页
router.beforeEach((to) => {
  const isPublic = to.path === '/login' || to.path.startsWith('/portal');
  if (!isPublic && !getToken()) return '/login';
  return true;
});

export default router;
