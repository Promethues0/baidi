<template>
  <div class="zl-shell">
    <!-- 顶栏：品牌 + 六中心 + 操作 -->
    <header class="zl-top">
      <div class="zl-brand">
        <div class="zl-brand__mark">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L3 7V12C3 16.55 6.84 20.74 12 22C17.16 20.74 21 16.55 21 12V7L12 2Z" fill="currentColor" opacity="0.92"/>
            <path d="M10 15.5L7 12.5L8.41 11.09L10 12.67L15.59 7.08L17 8.5L10 15.5Z" fill="#fff"/>
          </svg>
        </div>
        <span class="zl-brand__name">白帝 <i>· 零信任访问控制系统</i></span>
      </div>

      <nav class="zl-centers">
        <button
          v-for="c in NAV"
          :key="c.key"
          class="zl-center"
          :class="{ on: c.key === activeCenter }"
          @click="goCenter(c)"
        >{{ c.title }}</button>
      </nav>

      <div class="zl-top__right">
        <a-tooltip :content="ui.theme === 'dark' ? '切换浅色' : '切换深色'">
          <button class="zl-iconbtn" @click="ui.toggleTheme()">
            <component :is="ui.theme === 'dark' ? 'IconSun' : 'IconMoon'" />
          </button>
        </a-tooltip>
        <a-dropdown>
          <button class="zl-user"><icon-user /><span>管理员</span><icon-down /></button>
          <template #content>
            <a-doption><template #icon><icon-export /></template>退出登录</a-doption>
          </template>
        </a-dropdown>
      </div>
    </header>

    <div class="zl-body">
      <!-- 侧栏：当前中心的二级菜单 -->
      <aside class="zl-side">
        <template v-for="(g, gi) in activeGroups" :key="gi">
          <div v-if="g.title" class="zl-side__group">{{ g.title }}</div>
          <button
            v-for="leaf in g.children"
            :key="leaf.key"
            class="zl-side__item"
            :class="{ on: leaf.path === route.path }"
            @click="goLeaf(leaf)"
          >
            <span>{{ leaf.title }}</span>
            <span v-if="leaf.soon" class="zl-side__soon">建设中</span>
          </button>
        </template>
      </aside>

      <main class="zl-main">
        <RouterView />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter, RouterView } from 'vue-router';
import { NAV, type NavCenter, type NavLeaf } from '@/nav';
import { useUiStore } from '@/store';

const route = useRoute();
const router = useRouter();
const ui = useUiStore();

const activeCenter = computed(() => {
  // 用路径首段匹配中心；找不到则归到概览
  const seg = '/' + (route.path.split('/')[1] || 'overview');
  const hit = NAV.find((c) => c.groups.some((g) => g.children.some((l) => l.path.startsWith(seg))));
  return hit?.key || 'overview';
});
const activeGroups = computed(() => NAV.find((c) => c.key === activeCenter.value)?.groups || []);

function goCenter(c: NavCenter) {
  const first = c.groups[0]?.children[0];
  if (first) router.push(first.path);
}
function goLeaf(leaf: NavLeaf) {
  router.push(leaf.path);
}
</script>

<style scoped>
.zl-shell { display: flex; flex-direction: column; height: 100vh; }
.zl-top {
  height: 56px; flex: none; display: flex; align-items: center; gap: 28px;
  padding: 0 20px; background: var(--surface); border-bottom: 1px solid var(--line);
}
.zl-brand { display: flex; align-items: center; gap: 10px; min-width: 230px; }
.zl-brand__mark { color: var(--accent); display: flex; }
.zl-brand__name { font-size: 15px; font-weight: 700; color: var(--ink); white-space: nowrap; letter-spacing: -0.01em; }
.zl-brand__name i { font-style: normal; font-weight: 500; color: var(--ink-3); font-size: 13px; }

.zl-centers { display: flex; gap: 4px; flex: 1; }
.zl-center {
  border: 0; background: transparent; cursor: pointer; padding: 7px 15px; border-radius: var(--r-sm);
  font-size: 14px; font-weight: 550; color: var(--ink-2); font-family: var(--font-cn);
  transition: background .14s, color .14s, transform .12s ease;
}
.zl-center:hover { background: var(--surface-2); color: var(--ink); }
.zl-center:active { transform: translateY(1px); }
.zl-center.on { background: var(--accent-soft); color: var(--accent-2); font-weight: 650; }
.zl-center:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.zl-top__right { display: flex; align-items: center; gap: 8px; }
.zl-iconbtn {
  width: 34px; height: 34px; border-radius: var(--r-sm); border: 1px solid var(--line);
  background: var(--surface); color: var(--ink-2); cursor: pointer; display: flex;
  align-items: center; justify-content: center; font-size: 16px;
  transition: background .14s, color .14s, border-color .14s, transform .12s ease;
}
.zl-iconbtn:hover { color: var(--accent-2); border-color: var(--accent-line); background: var(--accent-soft); }
.zl-iconbtn:active { transform: translateY(1px); }
.zl-iconbtn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.zl-user {
  display: flex; align-items: center; gap: 6px; border: 0; background: transparent;
  cursor: pointer; color: var(--ink-2); font-size: 13.5px; padding: 6px 8px; border-radius: var(--r-sm);
  transition: background .14s, color .14s;
}
.zl-user:hover { background: var(--surface-2); }
.zl-user:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

.zl-body { flex: 1; display: flex; min-height: 0; }
.zl-side {
  width: 216px; flex: none; background: var(--surface); border-right: 1px solid var(--line);
  padding: 12px 10px; overflow-y: auto;
}
.zl-side__group {
  font-size: 13px; font-weight: 650; color: var(--ink-3); letter-spacing: .02em;
  padding: 12px 10px 6px;
}
.zl-side__item {
  width: 100%; display: flex; align-items: center; justify-content: space-between;
  border: 0; background: transparent; cursor: pointer; text-align: left;
  padding: 9px 12px; border-radius: var(--r-sm); margin-bottom: 2px;
  font-size: 12.5px; color: var(--ink-2); font-family: var(--font-cn);
  transition: background .14s, color .14s, transform .12s ease;
}
.zl-side__item:hover { background: var(--surface-2); color: var(--ink); }
.zl-side__item:active { transform: translateY(1px); }
.zl-side__item.on { background: var(--accent-soft); color: var(--accent-2); font-weight: 650; }
.zl-side__item:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.zl-side__soon {
  font-size: 10.5px; color: var(--ink-3); border: 1px solid var(--line-2);
  border-radius: var(--r-pill); padding: 0 7px; line-height: 16px;
}
.zl-main { flex: 1; overflow-y: auto; background: var(--bg); }
</style>
