import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import AppLayout from '@/layout/AppLayout.vue';
import { NAV, FIRST_PATH } from '@/nav';

// 已按设计稿落地的页面 → 真实组件；其余 NAV 叶子 → ComingSoon 占位
const BUILT: Record<string, () => Promise<unknown>> = {
  '/monitor/overview': () => import('@/views/Overview.vue'),
  '/business/policy': () => import('@/views/Policy.vue'),
  '/business/apps': () => import('@/views/Apps.vue'),
  '/business/users': () => import('@/views/Users.vue'),
  '/business/devices': () => import('@/views/Devices.vue'),
  '/business/auth': () => import('@/views/Auth.vue'),
  '/security/audit': () => import('@/views/Audit.vue'),
  '/security/gateway': () => import('@/views/Gateway.vue'),
  '/security/center': () => import('@/views/Security.vue'),
  '/system/manage': () => import('@/views/System.vue')
};

const leafRoutes: RouteRecordRaw[] = NAV.flatMap((g) =>
  g.children.map((c) => ({
    path: c.path.slice(1),
    component: (BUILT[c.path] ?? (() => import('@/views/ComingSoon.vue'))) as RouteRecordRaw['component']
  }))
);

const routes: RouteRecordRaw[] = [
  // 终端用户门户（B/S 免客户端，独立于管理控制台 chrome）
  { path: '/portal/login', component: () => import('@/views/PortalLogin.vue') },
  { path: '/portal', redirect: '/portal/apps' },
  { path: '/portal/apps', component: () => import('@/views/PortalApps.vue') },
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

export default createRouter({ history: createWebHistory(), routes });
