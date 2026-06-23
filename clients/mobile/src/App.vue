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
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { IconLink, IconApps, IconUser } from '@arco-design/web-vue/es/icon';

const route = useRoute();
const router = useRouter();
const isFull = computed(() => route.meta.full === true);

const tabs = [
  { path: '/connect', label: '接入', icon: IconLink },
  { path: '/apps', label: '应用', icon: IconApps },
  { path: '/profile', label: '我的', icon: IconUser }
];
function go(p: string) { if (route.path !== p) router.push(p); }
</script>
