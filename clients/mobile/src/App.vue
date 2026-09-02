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
import { computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Message } from '@arco-design/web-vue';
import { IconLink, IconApps, IconUser } from '@arco-design/web-vue/es/icon';
import { session } from '@/lib/store';

const route = useRoute();
const router = useRouter();

// 隧道被抢占 / 被系统回收 / 引擎停机（vpn.ts 的监视写入 session.dropReason）：
// 挂在根组件上弹，是因为中断可能发生在用户停在「应用」「我的」页的时候——那时 Connect.vue 根本没挂载。
watch(() => session.dropReason, (r) => { if (r) Message.error({ content: '接入已中断：' + r, duration: 6000 }); });
const isFull = computed(() => route.meta.full === true);

const tabs = [
  { path: '/connect', label: '接入', icon: IconLink },
  { path: '/apps', label: '应用', icon: IconApps },
  { path: '/profile', label: '我的', icon: IconUser }
];
function go(p: string) { if (route.path !== p) router.push(p); }
</script>
