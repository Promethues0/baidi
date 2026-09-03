<template>
  <div class="m-app">
    <div class="m-statusbar" />
    <div :class="['m-body', { 'm-body--full': isFull }]">
      <router-view />
    </div>

    <nav v-if="!isFull" class="m-tabbar">
      <div v-for="t in tabs" :key="t.path" class="m-tab" :class="{ on: route.path === t.path }" @click="go(t.path)">
        <component :is="t.icon" />
        <span>{{ t.label }}</span>
      </div>
    </nav>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { IconLink, IconApps, IconUser } from '@arco-design/web-vue/es/icon';
import { session } from '@/lib/store';
import { adoptRunningTunnel } from '@/lib/vpn';

const route = useRoute();
const router = useRouter();

// 隧道被抢占 / 被系统回收 / 引擎停机（vpn.ts 的监视写入 session.dropReason）：
// 挂在根组件上弹，是因为中断可能发生在用户停在「应用」「我的」页的时候——那时 Connect.vue 根本没挂载。
watch(() => session.dropReason, (r) => { if (r) Message.error({ content: '接入已中断：' + r, duration: 6000 }); });

// 「引擎在跑、门没敲开」：**刻意不复用上面那条**——对一次从来没有建立起来的接入弹
// 「接入已中断」是错的（用户会去找"是谁把我断了"，而其实它一次都没通过）。措辞、颜色、
// 下一步动作三样都不同：这条是可恢复的中间态（敲门每 15s 自动重试），故用 warning 不用 error。
// 只在**从空翻成非空**那一次弹：健康行原文每轮改写，逐轮弹会把屏幕刷满，
// 而常驻的那份在「接入」页上（弹窗一闪而过不算「看见」）。
watch(() => session.notReady, (r, old) => {
  if (r && !old) Message.warning({ content: '隧道未就绪：' + r, duration: 6000 });
});

// webview 重载 / Activity 被系统重建后，原生 VPN 仍在跑而 session.connected 从 false 起算：
// 挂载时读一次原生真实运行态把它认领回来（读不到就什么都不做）。放在根组件上是因为
// 重建后落在哪一页取决于路由，而隧道是全局的。
onMounted(() => { adoptRunningTunnel(); });
const isFull = computed(() => route.meta.full === true);

const tabs = [
  { path: '/connect', label: '接入', icon: IconLink },
  { path: '/apps', label: '应用', icon: IconApps },
  { path: '/profile', label: '我的', icon: IconUser }
];
function go(p: string) { if (route.path !== p) router.push(p); }
</script>
