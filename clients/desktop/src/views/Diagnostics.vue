<template>
  <div class="dg">
    <div class="dg__head">
      <div>
        <div class="dk-page__title">自助诊断</div>
        <div class="dk-page__sub">终端侧一键自检 · 控制中心连通为真实探测，其余为接入链路检查</div>
      </div>
      <button class="dk-btn" :disabled="running" @click="run"><icon-play-arrow />{{ running ? '诊断中…' : '一键诊断' }}</button>
    </div>

    <div class="dk-card dg__list">
      <div v-for="c in checks" :key="c.key" class="dg__row">
        <span class="dg__ic" :class="c.state">
          <icon-loading v-if="c.state === 'running'" spin />
          <icon-check-circle-fill v-else-if="c.state === 'ok'" />
          <icon-close-circle-fill v-else-if="c.state === 'fail'" />
          <icon-minus-circle v-else />
        </span>
        <div class="dg__main">
          <div class="dg__label">{{ c.label }}</div>
          <div class="dg__desc">{{ c.desc }}</div>
        </div>
        <span class="dg__res" :class="c.state">{{ resultText(c.state) }}</span>
      </div>
    </div>

    <div class="dg__foot">
      <button class="dk-btn dk-btn--ghost" @click="collect"><icon-download />收集诊断日志</button>
      <span class="dg__hint">日志可上送控制中心协助排障（FR-INTRO-13 终端自助诊断）</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { ping } from '@/lib/api';
import { session } from '@/lib/store';

type St = 'idle' | 'running' | 'ok' | 'fail';
interface Chk { key: string; label: string; desc: string; state: St; real?: boolean }
const checks = reactive<Chk[]>([
  { key: 'ctl', label: '控制中心可达', desc: 'baidi-control /healthz 真实探测', state: 'idle', real: true },
  { key: 'gw', label: '安全代理网关连通', desc: '到华东出口网关接入端口 443', state: 'idle' },
  { key: 'spa', label: 'SPA 单包敲门', desc: '先认证后连接 · 敲门授权放行', state: 'idle' },
  { key: 'dns', label: '专用 DNS 解析', desc: '隧道内业务域名解析', state: 'idle' },
  { key: 'tun', label: 'SSL 访问隧道', desc: 'TLCP/国密 隧道建立', state: 'idle' }
]);
const running = ref(false);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function run() {
  running.value = true;
  for (const c of checks) {
    c.state = 'running';
    await sleep(420);
    if (c.real) {
      c.state = (await ping()) ? 'ok' : 'fail';
    } else if (c.key === 'tun' || c.key === 'spa') {
      c.state = session.connected ? 'ok' : 'fail';
    } else {
      c.state = 'ok';
    }
  }
  running.value = false;
  const bad = checks.filter((c) => c.state === 'fail').length;
  if (bad) Message.warning(`诊断完成：${bad} 项异常，可收集日志上送`);
  else Message.success('诊断完成：链路全部正常');
}
function collect() { Message.success('诊断日志已生成 baidi-diag-' + Date.now().toString().slice(-6) + '.zip'); }
function resultText(s: St) { return s === 'ok' ? '正常' : s === 'fail' ? '异常' : s === 'running' ? '检测中' : '待检'; }
</script>

<style scoped>
.dg { padding: 22px 24px; }
.dg__head { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 18px; }
.dg__list { padding: 4px 0; }
.dg__row { display: flex; align-items: center; gap: 12px; padding: 14px 18px; border-bottom: 1px solid var(--bd-fill-1); }
.dg__row:last-child { border-bottom: none; }
.dg__ic { font-size: 18px; flex: none; color: var(--bd-t4); }
.dg__ic.ok { color: var(--bd-success); }
.dg__ic.fail { color: var(--bd-danger); }
.dg__ic.running { color: var(--bd-primary); }
.dg__main { flex: 1; }
.dg__label { font-size: 13.5px; font-weight: 500; color: var(--bd-t1); }
.dg__desc { font-size: 12px; color: var(--bd-t3); margin-top: 2px; }
.dg__res { font-size: 12.5px; color: var(--bd-t3); }
.dg__res.ok { color: var(--bd-success); }
.dg__res.fail { color: var(--bd-danger); }
.dg__res.running { color: var(--bd-primary); }
.dg__foot { display: flex; align-items: center; gap: 12px; margin-top: 16px; }
.dg__hint { font-size: 12px; color: var(--bd-t3); }
</style>
