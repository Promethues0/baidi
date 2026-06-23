<template>
  <div class="m-page">
    <div class="pf__card">
      <span class="pf__av">{{ initial }}</span>
      <div>
        <div class="pf__name">{{ session.user || '未登录' }}</div>
        <div class="pf__role">企业终端用户</div>
      </div>
    </div>

    <div class="m-card pf__list">
      <div class="pf__row"><span>接入状态</span><b :class="{ ok: session.connected }">{{ session.connected ? '已接入' : '未接入' }}</b></div>
      <div class="pf__row"><span>控制中心</span><b :class="ctlOk === null ? '' : ctlOk ? 'ok' : 'bad'">{{ ctlOk === null ? '检测中…' : ctlOk ? '连通' : '不可达' }}</b></div>
      <div class="pf__row"><span>数据面</span><b>{{ platformLabel() }}</b></div>
      <div class="pf__row"><span>客户端版本</span><b>v0.1.0</b></div>
    </div>

    <div class="m-card pf__diag">
      <div class="pf__diag-h"><icon-pulse /> 链路诊断</div>
      <div v-for="d in results" :key="d.k" class="pf__d">
        <component :is="d.ok ? IconCheckCircleFill : IconCloseCircleFill" :class="['pf__d-ic', d.ok ? 'ok' : 'bad']" />
        <span>{{ d.k }}</span><em>{{ d.v }}</em>
      </div>
      <button class="m-btn m-btn--ghost" :disabled="diaging" @click="diag">{{ diaging ? '检测中…' : '一键诊断' }}</button>
    </div>

    <button class="m-btn m-btn--danger" @click="doLogout">退出登录</button>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { IconCheckCircleFill, IconCloseCircleFill } from '@arco-design/web-vue/es/icon';
import { ping } from '@/lib/api';
import { session, logout } from '@/lib/store';
import { platformLabel } from '@/lib/vpn';

const router = useRouter();
const initial = computed(() => (session.user || '?').slice(0, 1).toUpperCase());
const ctlOk = ref<boolean | null>(null);

const results = reactive<{ k: string; v: string; ok: boolean }[]>([]);
const diaging = ref(false);

async function checkCtl() { ctlOk.value = await ping(); }

async function diag() {
  diaging.value = true; results.length = 0;
  const ok = await ping();
  results.push({ k: '控制中心 /healthz', v: ok ? '连通' : '不可达', ok });
  results.push({ k: '身份令牌', v: session.token ? '有效' : '缺失', ok: !!session.token });
  results.push({ k: '隧道接入', v: session.connected ? '已建立' : '未接入', ok: session.connected });
  diaging.value = false;
}

function doLogout() { logout(); router.replace('/login'); }

onMounted(checkCtl);
</script>

<style scoped>
.pf__card { display: flex; align-items: center; gap: 14px; padding: 6px 2px 18px; }
.pf__av { width: 54px; height: 54px; border-radius: 16px; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-purple)); color: #fff; font-size: 24px; font-weight: 700; }
.pf__name { font-size: 18px; font-weight: 700; color: var(--bd-t1); }
.pf__role { font-size: 12px; color: var(--bd-t3); margin-top: 3px; }
.pf__list { margin-bottom: 14px; }
.pf__row { display: flex; justify-content: space-between; align-items: center; padding: 11px 0; border-bottom: 1px solid var(--bd-fill-2); font-size: 14px; color: var(--bd-t3); }
.pf__row:last-child { border-bottom: none; }
.pf__row b { color: var(--bd-t1); font-weight: 600; }
.pf__row b.ok { color: var(--bd-success); }
.pf__row b.bad { color: var(--bd-danger); }
.pf__diag { margin-bottom: 16px; }
.pf__diag-h { display: flex; align-items: center; gap: 6px; font-weight: 600; color: var(--bd-t1); margin-bottom: 10px; }
.pf__d { display: flex; align-items: center; gap: 8px; padding: 7px 0; font-size: 13px; color: var(--bd-t2); }
.pf__d em { font-style: normal; margin-left: auto; color: var(--bd-t3); }
.pf__d-ic { font-size: 16px; }
.pf__d-ic.ok { color: var(--bd-success); }
.pf__d-ic.bad { color: var(--bd-danger); }
</style>
