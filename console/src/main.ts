import { createApp } from 'vue';
import ArcoVue from '@arco-design/web-vue';
import ArcoVueIcon from '@arco-design/web-vue/es/icon';
import { createPinia } from 'pinia';
import '@arco-design/web-vue/dist/arco.css';
import '@/styles/tokens.css';
import '@/styles/app.css';
import App from './App.vue';
import router from './router';

createApp(App)
  .use(createPinia())
  .use(ArcoVue, { componentPrefix: 'a' })
  .use(ArcoVueIcon)
  .use(router)
  .mount('#app');
