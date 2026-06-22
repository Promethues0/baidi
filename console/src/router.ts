import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import AppLayout from '@/layout/AppLayout.vue';
import { NAV, FIRST_PATH } from '@/nav';

// 已按白帝规范重做的页面 → 真实组件；其余 NAV 叶子 → ComingSoon 占位（保持新设计语言一致）
const BUILT: Record<string, () => Promise<unknown>> = {
  '/posture/dashboard': () => import('@/views/Overview.vue')
};

const leafRoutes: RouteRecordRaw[] = NAV.flatMap((g) =>
  g.children.map((c) => ({
    path: c.path.slice(1),
    component: (BUILT[c.path] ?? (() => import('@/views/ComingSoon.vue'))) as RouteRecordRaw['component']
  }))
);

const routes: RouteRecordRaw[] = [
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
