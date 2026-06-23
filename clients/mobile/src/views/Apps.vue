<template>
  <div class="m-page">
    <div class="m-page__title">应用门户</div>
    <div class="m-page__sub">已授权可访问的企业应用 · 高敏类需先申请</div>

    <div v-if="!session.connected" class="ap__warn"><icon-info-circle /> 未接入企业内网，隧道类应用需先在「接入」开启</div>

    <div class="ap__grid">
      <button v-for="a in apps" :key="a.id" class="ap__tile" :class="{ locked: !a.accessible }" @click="open(a)">
        <span class="ap__ic" :style="{ background: iconBg(a.mode) }"><component :is="modeIcon(a.mode)" /></span>
        <div class="ap__name">{{ a.name }}</div>
        <div class="ap__addr m-mono">{{ a.addr }}</div>
        <span v-if="a.sensitivity === 'high'" class="ap__tag">高敏 · 需申请</span>
      </button>
    </div>
    <div v-if="!apps.length && loaded" class="ap__empty">暂无可访问应用</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { IconCompass, IconCodeSquare, IconPublic } from '@arco-design/web-vue/es/icon';
import { api, type PortalTile, type PortalAppsResp } from '@/lib/api';
import { session } from '@/lib/store';

const apps = ref<PortalTile[]>([]);
const loaded = ref(false);

function modeIcon(m: string) { return m === 'tunnel' ? IconCodeSquare : m === 'global' ? IconPublic : IconCompass; }
function iconBg(m: string) { return m === 'tunnel' ? '#722ED1' : m === 'global' ? '#00B42A' : '#165DFF'; }

function open(a: PortalTile) {
  if (!a.accessible) { Message.warning(`「${a.name}」为高敏应用，需提交访问申请审批`); return; }
  if (a.mode === 'tunnel' && !session.connected) { Message.warning('请先在「接入」开启企业内网隧道'); return; }
  Message.success(`正在打开「${a.name}」（${a.mode === 'web' ? 'Web 代理' : a.mode === 'global' ? '全网资源' : '隧道访问'}）`);
}

async function load() {
  try {
    const r = await api<PortalAppsResp>('/portal/apps');
    apps.value = r.apps;
  } catch { /* 降级 */ } finally { loaded.value = true; }
}
onMounted(load);
</script>

<style scoped>
.ap__warn { display: flex; align-items: center; gap: 7px; margin: 14px 0 4px; padding: 10px 12px; font-size: 13px;
  color: var(--bd-warning); background: var(--bd-tag-gold-bg, #FFF7E8); border-radius: 10px; }
.ap__grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 14px; }
.ap__tile { position: relative; text-align: left; background: #fff; border: 1px solid var(--bd-border); border-radius: var(--bd-radius);
  padding: 14px; cursor: pointer; display: flex; flex-direction: column; gap: 4px; }
.ap__tile:active { background: var(--bd-fill-1); }
.ap__tile.locked { opacity: 0.7; }
.ap__ic { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center;
  color: #fff; font-size: 21px; margin-bottom: 6px; }
.ap__name { font-size: 14px; font-weight: 600; color: var(--bd-t1); }
.ap__addr { font-size: 11px; color: var(--bd-t3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ap__tag { margin-top: 4px; align-self: flex-start; font-size: 10px; padding: 1px 7px; border-radius: 4px;
  background: var(--bd-tag-red-bg, #FFECE8); color: var(--bd-danger); }
.ap__empty { text-align: center; color: var(--bd-t3); padding: 40px 0; font-size: 13px; }
</style>
