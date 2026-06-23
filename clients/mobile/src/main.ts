import { createApp } from 'vue';
import ArcoVue from '@arco-design/web-vue';
import ArcoVueIcon from '@arco-design/web-vue/es/icon';
import '@arco-design/web-vue/dist/arco.css';
import '@/styles/tokens.css';
import '@/styles/app.css';
import router from './router';
import App from './App.vue';

createApp(App).use(router).use(ArcoVue, { componentPrefix: 'a' }).use(ArcoVueIcon).mount('#app');
