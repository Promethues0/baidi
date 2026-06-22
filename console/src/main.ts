import { createApp } from 'vue';
import ArcoVue from '@arco-design/web-vue';
import ArcoVueIcon from '@arco-design/web-vue/es/icon';
import { createPinia } from 'pinia';
import '@arco-design/web-vue/dist/arco.css';
import '@/styles/tokens.css';
import '@/styles/app.css';
import App from './App.vue';
import LiveBadge from '@/components/LiveBadge.vue';
import { startNetmapSync, hydratePolicies } from './policy-store';
import router from './router';

createApp(App)
  .use(createPinia())
  .use(ArcoVue, { componentPrefix: 'a' })
  .use(ArcoVueIcon)
  .use(router)
  .component('LiveBadge', LiveBadge) // 全局注册：各视图直接 <LiveBadge :live="live" />
  .mount('#app');

// 先用控制面真实策略填充 store，再起 netmap 同步（让快照基线建立在真实数据上）。
hydratePolicies().finally(startNetmapSync);
