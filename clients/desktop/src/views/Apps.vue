<template>
  <div class="ap">
    <div class="ap__head">
      <div>
        <div class="dk-page__title">应用中心</div>
        <div class="dk-page__sub">已授权的业务应用 · 经安全隧道一键直达</div>
      </div>
      <a-tag v-if="live !== null" :color="live ? 'green' : 'orange'" bordered>{{ live ? '已连控制中心' : '未连' }}</a-tag>
    </div>

    <div v-if="!authedNow" class="ap__empty">
      <icon-lock /> 请先在「接入」页登录后查看可访问应用
    </div>

    <div v-else class="ap__grid">
      <div v-for="a in apps" :key="a.id" class="dk-card ap__card">
        <div class="ap__top">
          <span class="ap__ic" :style="{ background: meta(a.mode).bg }"><component :is="meta(a.mode).icon" :style="{ color: meta(a.mode).color }" /></span>
          <span v-if="!a.accessible" class="ap__sens"><icon-lock />需申请</span>
        </div>
        <div class="ap__name">{{ a.name }}</div>
        <div class="ap__addr dk-mono">{{ a.addr }}</div>
        <button v-if="a.accessible" class="dk-btn ap__btn" @click="openApp(a)"><icon-link />访问</button>
        <button v-else class="dk-btn dk-btn--ghost ap__btn" @click="apply(a)">申请权限</button>
      </div>
      <div v-if="!apps.length" class="ap__empty">暂无可访问应用</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { api, type PortalAppsResp, type PortalTile } from '@/lib/api';
import { authed, session } from '@/lib/store';

const authedNow = computed(() => authed());
const apps = ref<PortalTile[]>([]);
const live = ref<boolean | null>(null);

const META: Record<PortalTile['mode'], { icon: string; color: string; bg: string }> = {
  tunnel: { icon: 'icon-code', color: '#722ED1', bg: '#F5E8FF' },
  web: { icon: 'icon-common', color: '#165DFF', bg: '#F2F7FF' },
  global: { icon: 'icon-public', color: '#00B42A', bg: '#E8FFEA' }
};
function meta(m: PortalTile['mode']) { return META[m]; }

function openApp(a: PortalTile) {
  if (!session.connected) { Message.warning('请先在「接入」页接入企业内网'); return; }
  Message.success(`正在通过安全隧道打开「${a.name}」…`);
}
function apply(a: PortalTile) { Message.info(`已提交「${a.name}」权限申请，待审批`); }

onMounted(async () => {
  if (!authedNow.value) return;
  try { apps.value = (await api<PortalAppsResp>('/portal/apps')).apps; live.value = true; }
  catch { live.value = false; }
});
</script>

<style scoped>
.ap { padding: 22px 24px; }
.ap__head { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 18px; }
.ap__grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr)); gap: 14px; }
.ap__card { padding: 16px; }
.ap__top { display: flex; align-items: center; justify-content: space-between; }
.ap__ic { width: 40px; height: 40px; border-radius: 10px; display: inline-flex; align-items: center; justify-content: center; font-size: 20px; }
.ap__sens { font-size: 11px; color: var(--bd-warning); background: var(--bd-tag-gold-bg); padding: 2px 7px; border-radius: 4px; display: inline-flex; align-items: center; gap: 3px; }
.ap__name { font-size: 14px; font-weight: 600; margin-top: 12px; color: var(--bd-t1); }
.ap__addr { font-size: 11.5px; color: var(--bd-t3); margin-top: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ap__btn { width: 100%; height: 34px; justify-content: center; margin-top: 14px; }
.ap__empty { grid-column: 1 / -1; display: flex; align-items: center; justify-content: center; gap: 8px; height: 180px; color: var(--bd-t3); font-size: 13px; }
</style>
