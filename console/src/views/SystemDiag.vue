<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">系统诊断<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">控制面真实运行态 · 服务健康 · 连通性探测（真实 TCP）· 数据来自 zhulong-control 进程 runtime</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <a-tooltip content="每 3 秒自动刷新"><a-switch v-model="auto" size="small" /></a-tooltip>
        <span style="font-size:12px;color:var(--ink-3)">自动刷新</span>
        <a-button size="small" @click="loadDiag"><template #icon><icon-refresh /></template>刷新</a-button>
      </div>
    </div>

    <!-- 顶部 runtime 卡片 -->
    <div class="diag-cards">
      <div class="dcard"><div class="dcard-k">主机名</div><div class="dcard-v data">{{ d.hostname || '—' }}</div></div>
      <div class="dcard"><div class="dcard-k">运行时长</div><div class="dcard-v data">{{ uptimeStr }}</div></div>
      <div class="dcard"><div class="dcard-k">CPU 核心</div><div class="dcard-v data">{{ d.runtime?.numCPU ?? '—' }}</div></div>
      <div class="dcard"><div class="dcard-k">Goroutine</div><div class="dcard-v data">{{ d.runtime?.goroutines ?? '—' }}</div></div>
      <div class="dcard"><div class="dcard-k">内存占用</div><div class="dcard-v data">{{ mb(d.runtime?.memAllocMB) }} <i>/ {{ mb(d.runtime?.memSysMB) }} MB</i></div></div>
      <div class="dcard"><div class="dcard-k">运行环境</div><div class="dcard-v data" style="font-size:12.5px">{{ d.runtime?.go }} · {{ d.runtime?.goos }}/{{ d.runtime?.goarch }}</div></div>
    </div>

    <div class="zl-grid" style="grid-template-columns: minmax(0,1fr) 360px; margin-top:16px;">
      <!-- 服务健康表 -->
      <div class="zl-card" style="overflow:hidden">
        <div class="zl-card__title" style="padding:14px 16px;border-bottom:1px solid var(--line)">服务健康（systemd 单元 + 内置子系统）</div>
        <table class="svc-tbl">
          <thead><tr><th>服务</th><th>单元</th><th>状态</th><th>详情</th></tr></thead>
          <tbody>
            <tr v-for="s in d.services || []" :key="s.name">
              <td class="svc-name">{{ s.name }}</td>
              <td class="data" style="font-size:11.5px;color:var(--ink-3)">{{ s.unit }}</td>
              <td><span class="svc-dot" :class="s.status" /><span class="svc-st">{{ stLabel(s.status) }}</span></td>
              <td class="data" style="font-size:11.5px">{{ s.detail }}</td>
            </tr>
            <tr v-if="!(d.services||[]).length"><td colspan="4" class="svc-empty">控制面不可达 · 无法获取服务状态</td></tr>
          </tbody>
        </table>
      </div>

      <!-- 连通性探测工具 -->
      <div class="zl-card zl-card__pad">
        <div class="zl-card__title" style="margin-bottom:12px">连通性探测<span class="tool-tag">真实 TCP DialTimeout</span></div>
        <div style="display:flex;gap:8px">
          <a-input v-model="target" placeholder="host:port，如 oa.corp:443" size="small" @keyup.enter="probe" allow-clear />
          <a-button type="primary" size="small" :loading="probing" @click="probe">探测</a-button>
        </div>
        <div class="probe-presets">
          <span>快捷：</span>
          <a v-for="p in presets" :key="p" @click="target=p; probe()">{{ p }}</a>
        </div>
        <div class="probe-results">
          <div v-for="(r,i) in results" :key="i" class="probe-row" :class="r.reachable ? 'ok' : 'bad'">
            <span class="pr-glyph">{{ r.reachable ? '✓' : '✕' }}</span>
            <div class="pr-main">
              <div class="pr-target data">{{ r.target }}</div>
              <div class="pr-detail">{{ r.reachable ? `可达 · ${r.ms}ms · 对端 ${r.remote}` : `不可达 · ${r.error}` }}</div>
            </div>
            <span class="pr-ms data" v-if="r.reachable">{{ r.ms }}ms</span>
          </div>
          <div v-if="!results.length" class="probe-empty">输入目标地址，对网关 / 上游资源做真实 TCP 连通性探测。</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { Message } from '@arco-design/web-vue';

const d = ref<any>({});
const live = ref(false);
const auto = ref(true);
const target = ref('');
const probing = ref(false);
const results = ref<any[]>([]);
const presets = ['oa.corp:443', 'gitlab.corp:443', '127.0.0.1:5273'];
let timer: any = null;

const mb = (v: number | undefined) => (v == null ? '—' : v.toFixed(1));
const uptimeStr = computed(() => {
  const s = d.value.uptime ?? 0;
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h > 0 ? `${h}时 ${m}分` : m > 0 ? `${m}分 ${sec}秒` : `${sec}秒`;
});
const stLabel = (s: string) => ({ up: '运行中', idle: '空闲', down: '已停止' }[s] || s);

async function loadDiag() {
  try {
    const r = await fetch('/ctl/api/system/diagnostics');
    if (!r.ok) throw new Error();
    d.value = await r.json();
    live.value = true;
  } catch { live.value = false; }
}

async function probe() {
  const t = target.value.trim();
  if (!t) return;
  probing.value = true;
  try {
    const r = await fetch('/ctl/api/system/probe?target=' + encodeURIComponent(t));
    const res = await r.json();
    results.value.unshift(res);
    if (results.value.length > 6) results.value.pop();
  } catch { Message.error('探测失败：控制面不可达'); }
  probing.value = false;
}

watch(auto, (v) => { v ? start() : stop(); });
function start() { stop(); timer = setInterval(loadDiag, 3000); }
function stop() { if (timer) { clearInterval(timer); timer = null; } }

onMounted(() => { loadDiag(); if (auto.value) start(); });
onUnmounted(stop);
</script>

<style scoped>
.diag-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.dcard { background: var(--surface); border: 1px solid var(--line); border-radius: var(--r-md); padding: 12px 14px; min-width: 0; }
.dcard-k { font-size: 11.5px; color: var(--ink-3); margin-bottom: 5px; }
.dcard-v { font-size: 18px; font-weight: 700; color: var(--ink); word-break: break-all; } .dcard-v i { font-size: 11px; font-weight: 400; color: var(--ink-3); font-style: normal; }

.svc-tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.svc-tbl th { text-align: left; font-size: 11.5px; font-weight: 650; color: var(--ink-3); padding: 9px 16px; background: var(--surface-2); border-bottom: 1px solid var(--line); }
.svc-tbl td { padding: 11px 16px; border-bottom: 1px solid var(--line); }
.svc-name { font-weight: 600; color: var(--ink); }
.svc-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 7px; vertical-align: middle; }
.svc-dot.up { background: var(--ok); box-shadow: 0 0 0 3px color-mix(in oklch, var(--ok) 20%, transparent); }
.svc-dot.idle { background: var(--warn); }
.svc-dot.down { background: var(--danger); }
.svc-st { font-size: 12.5px; color: var(--ink-2); }
.svc-empty { text-align: center; color: var(--ink-3); padding: 24px; }

.tool-tag { font-size: 10.5px; font-weight: 400; color: var(--accent-2); background: var(--accent-soft); padding: 1px 8px; border-radius: var(--r-pill); margin-left: 8px; }
.probe-presets { display: flex; gap: 10px; align-items: center; margin: 10px 0; font-size: 11.5px; color: var(--ink-3); flex-wrap: wrap; }
.probe-presets a { color: var(--accent-2); cursor: pointer; }
.probe-presets a:hover { text-decoration: underline; }
.probe-results { display: flex; flex-direction: column; gap: 8px; margin-top: 4px; }
.probe-row { display: flex; align-items: center; gap: 10px; padding: 9px 11px; border-radius: var(--r-md); border: 1px solid var(--line); }
.probe-row.ok { background: color-mix(in oklch, var(--ok) 7%, transparent); }
.probe-row.bad { background: color-mix(in oklch, var(--danger) 7%, transparent); }
.pr-glyph { width: 20px; height: 20px; border-radius: 50%; display: grid; place-items: center; font-size: 12px; font-weight: 700; flex: none; color: #fff; }
.probe-row.ok .pr-glyph { background: var(--ok); } .probe-row.bad .pr-glyph { background: var(--danger); }
.pr-main { flex: 1; min-width: 0; }
.pr-target { font-size: 12.5px; font-weight: 600; color: var(--ink); }
.pr-detail { font-size: 11px; color: var(--ink-3); margin-top: 1px; }
.pr-ms { font-size: 13px; font-weight: 700; color: var(--ink-2); }
.probe-empty { font-size: 12px; color: var(--ink-3); padding: 12px 0; }
</style>
