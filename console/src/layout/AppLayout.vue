<template>
  <a-layout class="bd-shell">
    <!-- 左侧 Sider：品牌 + 七大工作域两级菜单（Arco Pro 模型，区别于烛龙顶部六中心横条） -->
    <a-layout-sider
      class="bd-sider"
      :width="220"
      :collapsed="collapsed"
      :collapsed-width="48"
      :collapsible="false"
    >
      <div class="bd-brand" :class="{ mini: collapsed }">
        <span class="bd-brand__mark">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L3 7V12C3 16.55 6.84 20.74 12 22C17.16 20.74 21 16.55 21 12V7L12 2Z" fill="currentColor" />
            <path d="M9.6 12.2 L11.3 13.9 L14.7 10.2" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none" />
          </svg>
        </span>
        <span v-if="!collapsed" class="bd-brand__txt">白帝<i>零信任访问控制</i></span>
      </div>

      <a-menu
        class="bd-menu"
        :selected-keys="[route.path]"
        :open-keys="openKeys"
        :collapsed="collapsed"
        accordion
        @menu-item-click="onLeaf"
        @sub-menu-click="onSub"
      >
        <a-sub-menu v-for="g in NAV" :key="g.key">
          <template #icon><component :is="g.icon" /></template>
          <template #title>{{ g.title }}</template>
          <a-menu-item v-for="c in g.children" :key="c.path">{{ c.title }}</a-menu-item>
        </a-sub-menu>
      </a-menu>
    </a-layout-sider>

    <a-layout>
      <!-- 顶栏：折叠 + 面包屑 + 搜索 + 主题 + 用户 -->
      <a-layout-header class="bd-header">
        <button class="bd-iconbtn" @click="collapsed = !collapsed">
          <component :is="collapsed ? 'IconMenuUnfold' : 'IconMenuFold'" />
        </button>
        <a-breadcrumb class="bd-crumb">
          <a-breadcrumb-item>{{ loc.group?.title ?? '白帝' }}</a-breadcrumb-item>
          <a-breadcrumb-item>{{ loc.leaf?.title ?? '' }}</a-breadcrumb-item>
        </a-breadcrumb>
        <div class="bd-header__spacer" />
        <a-input-search class="bd-search" placeholder="搜索用户 / 应用 / 策略" allow-clear />
        <a-tooltip :content="dark ? '切换浅色' : '切换深色'">
          <button class="bd-iconbtn" @click="toggleTheme">
            <component :is="dark ? 'IconSun' : 'IconMoon'" />
          </button>
        </a-tooltip>
        <a-dropdown>
          <button class="bd-user"><icon-user /><span>管理员</span><icon-down /></button>
          <template #content>
            <a-doption><template #icon><icon-export /></template>退出登录</a-doption>
          </template>
        </a-dropdown>
      </a-layout-header>

      <a-layout-content class="bd-content">
        <RouterView />
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { NAV, locate } from '@/nav';

const route = useRoute();
const router = useRouter();

const collapsed = ref(false);
const dark = ref(false);
const openKeys = ref<string[]>([]);

const loc = computed(() => locate(route.path));

watch(
  () => route.path,
  () => { openKeys.value = loc.value.group ? [loc.value.group.key] : []; },
  { immediate: true }
);

function onLeaf(key: string) {
  if (key !== route.path) router.push(key);
}
function onSub(key: string) {
  openKeys.value = openKeys.value.includes(key) ? [] : [key];
}
function toggleTheme() {
  dark.value = !dark.value;
  document.body.toggleAttribute('arco-theme', dark.value);
  if (dark.value) document.body.setAttribute('arco-theme', 'dark');
  else document.body.removeAttribute('arco-theme');
}
</script>

<style scoped>
.bd-shell { height: 100vh; }
.bd-sider { background: var(--color-bg-1); border-right: 1px solid var(--color-border-2); }

.bd-brand {
  height: var(--bd-header-h); display: flex; align-items: center; gap: 10px;
  padding: 0 16px; border-bottom: 1px solid var(--color-border-2); overflow: hidden;
}
.bd-brand.mini { padding: 0; justify-content: center; }
.bd-brand__mark { color: var(--bd-brand); display: inline-flex; }
.bd-brand__txt { font-size: 18px; font-weight: 700; letter-spacing: 1px; white-space: nowrap; }
.bd-brand__txt i {
  font-style: normal; font-weight: 400; font-size: 11px; letter-spacing: 0;
  color: var(--color-text-3); margin-left: 6px;
}
.bd-menu { border: none; }

.bd-header {
  height: var(--bd-header-h); display: flex; align-items: center; gap: 12px;
  padding: 0 16px; background: var(--color-bg-1); border-bottom: 1px solid var(--color-border-2);
}
.bd-header__spacer { flex: 1; }
.bd-crumb { font-size: 13px; }
.bd-search { width: 240px; }

.bd-iconbtn {
  width: 32px; height: 32px; border: none; background: transparent; cursor: pointer;
  border-radius: 6px; color: var(--color-text-2); display: inline-flex;
  align-items: center; justify-content: center; font-size: 16px;
}
.bd-iconbtn:hover { background: var(--color-fill-2); color: var(--color-text-1); }
.bd-user {
  height: 32px; border: none; background: transparent; cursor: pointer; border-radius: 6px;
  padding: 0 8px; display: inline-flex; align-items: center; gap: 6px; color: var(--color-text-1);
}
.bd-user:hover { background: var(--color-fill-2); }
.bd-content { overflow: auto; background: var(--color-fill-2); }
</style>
