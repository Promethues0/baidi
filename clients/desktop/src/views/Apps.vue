<template>
  <div class="ap">
    <div class="ap__head">
      <div>
        <div class="dk-page__title">应用中心</div>
        <div class="dk-page__sub">已发布的业务应用 · 已授权的经安全隧道一键直达</div>
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
          <!-- 「被降权」与「没授权」下一步动作不同：前者申请必然被否（降权否决压过 JIT 授予），
               该做的是修终端。剖面早就下发了 degraded 这一格，这里此前一律画成「需申请」。 -->
          <span v-if="a.degraded" class="ap__sens ap__sens--deg"><icon-exclamation-circle-fill />终端降级</span>
          <span v-else-if="!a.accessible" class="ap__sens">
            <icon-lock />{{ a.sensitivity === 'high' ? '高敏 · 需申请' : '未授权 · 可申请' }}
          </span>
        </div>
        <div class="ap__name">{{ a.name }}</div>
        <!-- 显示接入地址（VIP），不是内网真实地址：终端只需知道「往哪连」，
             内网拓扑属于最小知悉之外的信息。鼠标悬停可看真实后端，便于排障。 -->
        <div class="ap__addr dk-mono" :title="a.backend ? `真实后端 ${a.backend}` : ''">{{ a.url || a.backend }}</div>
        <button v-if="a.accessible" class="dk-btn ap__btn" @click="openApp(a)"><icon-link />访问</button>
        <button
          v-else-if="a.degraded"
          class="dk-btn dk-btn--ghost ap__btn"
          disabled
          title="终端环境不合规，已暂停高敏资源访问。修复后重新上报即自动恢复；此状态下提交申请无效"
        >请先修复终端</button>
        <button v-else class="dk-btn dk-btn--ghost ap__btn" @click="apply(a)">申请权限</button>
      </div>
      <div v-if="!apps.length" class="ap__empty">{{ loadErr || '暂无可访问应用' }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { fetchProfile, type ProfileApp } from '@/lib/api';
import { authed, session, setProfile, setProfileError } from '@/lib/store';
import { openAppUrl, tauriRuntime } from '@/lib/tunnel';

const authedNow = computed(() => authed());
const apps = ref<ProfileApp[]>([]);
const live = ref<boolean | null>(null);
const loadErr = ref('');

const META: Record<ProfileApp['mode'], { icon: string; color: string; bg: string }> = {
  tunnel: { icon: 'icon-code', color: '#722ED1', bg: '#F5E8FF' },
  web: { icon: 'icon-common', color: '#165DFF', bg: '#F2F7FF' },
  global: { icon: 'icon-public', color: '#00B42A', bg: '#E8FFEA' }
};
function meta(m: ProfileApp['mode']) { return META[m]; }

/**
 * 真正打开应用。此前这里只弹一句「正在通过安全隧道打开…」的 toast，什么都没做——
 * 界面看着完整，实际是纯装饰。现在：
 *  - web 模式：调 Rust 侧 open_app_url 用系统浏览器打开 VIP 地址，流量经 utun → 隧道 → 网关 → 后端；
 *  - tunnel 模式（SSH / 数据库等）：没有通用的「打开」语义，改为把接入地址放进剪贴板，
 *    让用户粘进自己的终端/客户端。这比假装打开诚实，也确实可用。
 */
async function openApp(a: ProfileApp) {
  // global 模式（全网资源）不经隧道，直连即可，故不要求已接入。
  if (a.mode !== 'global' && !session.connected) {
    Message.warning('请先在「接入」页接入企业内网——未接入时该地址不会被隧道接管');
    return;
  }
  if (a.mode === 'web' || /^https?:\/\//.test(a.url)) {
    try {
      if (tauriRuntime()) await openAppUrl(a.url);
      else window.open(a.url, '_blank', 'noopener');
      Message.success(`已打开「${a.name}」（${a.url}）`);
    } catch (e) {
      Message.error(`打开失败：${String(e)}`);
    }
    return;
  }
  try {
    await navigator.clipboard.writeText(a.url);
    Message.success(`「${a.name}」接入地址已复制：${a.url}`);
  } catch {
    Message.info(`「${a.name}」接入地址：${a.url}`);
  }
}

function apply(a: ProfileApp) {
  // 不说死「高敏」：走到这里只说明「此刻没有这个资源的访问权」，它可能是高敏，
  // 也可能只是一条你不在授权名单里的普通资源（服务端判定见 control 侧 appAccessState）。
  Message.info(`请到门户「我的申请」提交「${a.name}」的访问申请（审批通过后获得限时授予，到期自动回收）`);
}

/**
 * 应用清单直接取自接入剖面，而不是 /portal/apps。
 * 原因：剖面里的每个应用都带着 VIP / 资源 id / 可点 URL，是「能真的连上」的那份数据；
 * portal/apps 只有展示用的内网地址，点了也到不了。同一份数据支撑展示与路由，
 * 也杜绝了「列表里有、隧道里没路由」的错配。
 */
onMounted(async () => {
  if (!authedNow.value) return;
  try {
    const p = await fetchProfile();
    setProfile(p);
    apps.value = p.apps;
    live.value = true;
    if (p.warnings?.length) Message.warning(p.warnings[0]);
  } catch (e) {
    live.value = false;
    loadErr.value = '控制中心不可达，无法获取可访问应用';
    setProfileError(String(e));
  }
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
/* 红而非金：降级与"需申请"是两回事——申请审批在这个状态下无效（与门户 PortalApps.vue 同一套配色约定） */
.ap__sens--deg { color: var(--bd-danger); background: var(--bd-tag-red-bg, #FFECE8); }
.ap__name { font-size: 14px; font-weight: 600; margin-top: 12px; color: var(--bd-t1); }
.ap__addr { font-size: 11.5px; color: var(--bd-t3); margin-top: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ap__btn { width: 100%; height: 34px; justify-content: center; margin-top: 14px; }
.ap__empty { grid-column: 1 / -1; display: flex; align-items: center; justify-content: center; gap: 8px; height: 180px; color: var(--bd-t3); font-size: 13px; }
</style>
