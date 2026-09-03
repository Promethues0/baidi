import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import { authed } from '@/lib/store';

const routes: RouteRecordRaw[] = [
  { path: '/login', component: () => import('@/views/Login.vue'), meta: { full: true } },
  { path: '/', redirect: '/connect' },
  { path: '/connect', component: () => import('@/views/Connect.vue') },
  { path: '/apps', component: () => import('@/views/Apps.vue') },
  { path: '/profile', component: () => import('@/views/Profile.vue') },
  /**
   * 兜底路由。**这条不是防御性冗余，是修一个真机上必然发生的缺陷。**
   *
   * 原生壳加载的是 `https://appassets.local/index.html`（MainActivity.loadUrl，
   * 由 WebViewAssetLoader 映射到打包进 assets 的 dist），于是 vue-router 在
   * createWebHistory 下看到的路径就是 **`/index.html`**——上面五条一条都匹配不上。
   *
   * 未登录时看不出来：beforeEach 判 `to.path !== '/login' && !authed()` 成立，
   * 直接重定向去 `/login`，一切正常。**而一旦登录过，下次打开应用就露馅**：
   * authed() 为真 → beforeEach 放行 → 解析到一条不存在的路由 → `<router-view>` 渲染空，
   * 界面上只剩状态栏和底部三个 tab，内容区一片空白。2026-09-03 在 OPPO PKU110 上实测：
   * `location.pathname` = `/index.html`、`#app` 里只有外壳的 1203 字符、
   * `document.body.innerText` 只有「接入/应用/我的」。用户手动点一下 tab 才会好——
   * 因为那是客户端跳转，路径这才变成 `/connect`。
   *
   * 影响面比"少看一页"大：App.vue 的 onMounted 会 adoptRunningTunnel（认领原生仍在跑的隧道
   * 并开始监视），空白页照样挂载所以它会跑，但用户看不到任何接入态——一条正在运行的 VPN
   * 在界面上完全不存在，他多半会再点一次接入。
   *
   * 放在最后一条：vue-router 按声明顺序匹配，catch-all 排在前面会吞掉所有真实路由。
   */
  { path: '/:pathMatch(.*)*', redirect: '/connect' }
];

const router = createRouter({ history: createWebHistory(), routes });

router.beforeEach((to) => {
  if (to.path !== '/login' && !authed()) return '/login';
  if (to.path === '/login' && authed()) return '/connect';
  return true;
});

export default router;
