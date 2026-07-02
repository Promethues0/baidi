<template>
  <div class="dk-win">
    <!-- 标题栏（Tauri 下为拖拽区） -->
    <header class="dk-titlebar" data-tauri-drag-region>
      <span class="dk-dots">
        <button class="r" title="关闭" @click="win('close')"><span>✕</span></button>
        <button class="y" title="最小化" @click="win('min')"><span>−</span></button>
        <button class="g" title="最大化" @click="win('max')"><span>+</span></button>
      </span>
      <span class="dk-brand">
        <span class="dk-brand__mark">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
            <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
        </span>
        白帝安全接入客户端
      </span>
      <div class="dk-titlebar__sp" />
      <span class="dk-state" :class="{ on: session.connected }">
        <i class="dot" />{{ session.connected ? '已接入企业内网' : authedNow ? '已认证 · 待接入' : '未登录' }}
      </span>
    </header>

    <div class="dk-body">
      <!-- 左侧图标导航 -->
      <nav class="dk-rail">
        <button v-for="t in TABS" :key="t.key" class="dk-rail__it" :class="{ on: tab === t.key }" @click="tab = t.key">
          <component :is="t.icon" />
          <span>{{ t.label }}</span>
        </button>
        <div class="dk-rail__sp" />
        <button v-if="authedNow" class="dk-rail__it dk-rail__quit" @click="doLogout">
          <icon-export /><span>退出</span>
        </button>
      </nav>

      <main class="dk-content">
        <Connect v-if="tab === 'connect'" />
        <Apps v-else-if="tab === 'apps'" />
        <Diagnostics v-else-if="tab === 'diag'" />
        <Settings v-else @logout="doLogout" />
      </main>
    </div>

    <!-- 隧道运行中退出的二次确认（避免遗留无管控 root 数据面） -->
    <a-modal v-model:visible="quitAsk" title="隧道仍在运行" :footer="false" :mask-closable="false" :width="380">
      <p class="dk-quit__msg">接入仍在运行，直接退出会遗留一个无管控的数据面（root）进程。建议先断开再退出。</p>
      <div class="dk-quit__btns">
        <button class="dk-btn dk-btn--ghost" @click="quitAsk = false">取消</button>
        <button class="dk-btn dk-btn--ghost" :disabled="quitting" @click="quitAnyway">仍要退出</button>
        <button class="dk-btn" :disabled="quitting" @click="disconnectAndQuit">{{ quitting ? '断开中…' : '断开并退出' }}</button>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { session, logout, authed } from '@/lib/store';
import { tauriRuntime, tunnelStop, forceQuit } from '@/lib/tunnel';
import Connect from '@/views/Connect.vue';
import Apps from '@/views/Apps.vue';
import Diagnostics from '@/views/Diagnostics.vue';
import Settings from '@/views/Settings.vue';

const tab = ref<'connect' | 'apps' | 'diag' | 'settings'>('connect');
const authedNow = computed(() => authed());

/* 退出确认（Rust 托盘「退出白帝」若隧道在跑会发 quit-request 事件） */
const quitAsk = ref(false);
const quitting = ref(false);
onMounted(async () => {
  if (!tauriRuntime()) return;
  const mod = '@tauri-apps/api/event';
  const { listen } = (await import(/* @vite-ignore */ mod)) as { listen: (e: string, cb: () => void) => Promise<unknown> };
  await listen('quit-request', () => { quitAsk.value = true; });
});
async function disconnectAndQuit() {
  quitting.value = true;
  try { await tunnelStop(); } catch { /* ignore */ }
  await forceQuit();
}
async function quitAnyway() { await forceQuit(); }

/* 自定义标题栏窗控（frameless）：经 Tauri 窗口 API 真实最小化/最大化/关闭 */
async function win(a: 'min' | 'max' | 'close') {
  if (!tauriRuntime()) return;
  const mod = '@tauri-apps/api/window';
  const { getCurrentWindow } = (await import(/* @vite-ignore */ mod)) as {
    getCurrentWindow: () => { minimize: () => Promise<void>; toggleMaximize: () => Promise<void>; close: () => Promise<void> };
  };
  const w = getCurrentWindow();
  if (a === 'min') await w.minimize();
  else if (a === 'max') await w.toggleMaximize();
  else await w.close();
}

const TABS = [
  { key: 'connect', label: '接入', icon: 'IconLink' },
  { key: 'apps', label: '应用', icon: 'IconApps' },
  { key: 'diag', label: '诊断', icon: 'IconBug' },
  { key: 'settings', label: '设置', icon: 'IconSettings' }
] as const;

function doLogout() { logout(); tab.value = 'connect'; }
</script>

<style scoped>
.dk-win { display: flex; flex-direction: column; height: 100vh; background: var(--bd-fill-1); }

.dk-titlebar {
  height: 38px; flex: none; display: flex; align-items: center; gap: 10px; padding: 0 12px;
  background: #fff; border-bottom: 1px solid var(--bd-border); user-select: none;
}
.dk-dots { display: flex; gap: 8px; align-items: center; }
.dk-dots button {
  width: 12px; height: 12px; border-radius: 50%; border: none; padding: 0; cursor: pointer;
  display: inline-flex; align-items: center; justify-content: center; line-height: 1;
  font-size: 9px; font-weight: 700; color: transparent; transition: filter .12s;
}
.dk-dots button > span { transform: translateY(-.5px); }
.dk-dots:hover button { color: rgba(0, 0, 0, .55); }   /* macOS：悬停整组显符号 */
.dk-dots button:active { filter: brightness(.85); }
.dk-dots .r { background: #FF5F57; }
.dk-dots .y { background: #FEBC2E; }
.dk-dots .g { background: #28C840; }
.dk-brand { display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600; margin-left: 6px; }
.dk-brand__mark {
  width: 20px; height: 20px; border-radius: 6px; display: inline-flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
}
.dk-titlebar__sp { flex: 1; }
.dk-state { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--bd-t3); }
.dk-state .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--bd-t4); }
.dk-state.on { color: var(--bd-success); }
.dk-state.on .dot { background: var(--bd-success); box-shadow: 0 0 0 3px rgba(0, 180, 42, .18); }

.dk-body { display: flex; flex: 1; overflow: hidden; }
.dk-rail {
  width: 74px; flex: none; background: #fff; border-right: 1px solid var(--bd-border);
  display: flex; flex-direction: column; align-items: center; padding: 12px 0;
}
.dk-rail__it {
  width: 58px; height: 56px; border: none; background: transparent; border-radius: 10px; cursor: pointer;
  display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 5px;
  font-size: 12px; color: var(--bd-t3); margin-bottom: 6px; transition: all .12s;
}
.dk-rail__it :deep(svg), .dk-rail__it i { font-size: 19px; }
.dk-rail__it:hover { background: var(--bd-fill-2); color: var(--bd-t1); }
.dk-rail__it.on { background: var(--bd-primary-1); color: var(--bd-primary); font-weight: 500; }
.dk-rail__sp { flex: 1; }
.dk-rail__quit { color: var(--bd-t3); }
.dk-rail__quit:hover { color: var(--bd-danger); }

.dk-content { flex: 1; overflow-y: auto; }

.dk-quit__msg { font-size: 13px; color: var(--bd-t2); line-height: 1.7; margin: 0 0 18px; }
.dk-quit__btns { display: flex; justify-content: flex-end; gap: 10px; }
.dk-quit__btns .dk-btn { height: 34px; padding: 0 16px; font-size: 13px; }
</style>
