import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import { authed } from '@/lib/store';

const routes: RouteRecordRaw[] = [
  { path: '/login', component: () => import('@/views/Login.vue'), meta: { full: true } },
  { path: '/', redirect: '/connect' },
  { path: '/connect', component: () => import('@/views/Connect.vue') },
  { path: '/apps', component: () => import('@/views/Apps.vue') },
  { path: '/profile', component: () => import('@/views/Profile.vue') }
];

const router = createRouter({ history: createWebHistory(), routes });

router.beforeEach((to) => {
  if (to.path !== '/login' && !authed()) return '/login';
  if (to.path === '/login' && authed()) return '/connect';
  return true;
});

export default router;
