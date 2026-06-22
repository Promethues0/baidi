<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">网关清单</h1>
        <div class="zl-page__sub">同一镜像按角色裁剪启用 · 资源水位实时（ZL-FR-406）</div>
      </div>
      <a-button type="primary" @click="show = true"><template #icon><icon-plus /></template>纳管网关</a-button>
    </div>
    <div class="zl-card">
      <a-table :data="rows" :pagination="false" :bordered="false" row-key="name" :row-class="()=>'row-click'" @row-click="(r:any)=>openGw(r)">
        <template #columns>
          <a-table-column title="网关" data-index="name">
            <template #cell="{ record }">
              <span class="data" style="font-weight:600;color:var(--ink)">{{ record.name }}</span>
            </template>
          </a-table-column>
          <a-table-column title="角色" data-index="role" :width="120" />
          <a-table-column title="能力" :width="160">
            <template #cell="{ record }">
              <span v-for="m in record.modes" :key="m" class="zl-mode-pill" :class="`zl-mode--${m}`" style="margin-right:4px">{{ m }}</span>
            </template>
          </a-table-column>
          <a-table-column title="CPU" :width="120">
            <template #cell="{ record }">
              <a-progress :percent="record.cpu/100" :show-text="false" size="small" :status="record.cpu>80?'danger':'normal'" />
              <span class="data" style="font-size:11.5px;color:var(--ink-3)">{{ record.cpu }}%</span>
            </template>
          </a-table-column>
          <a-table-column title="内存" :width="120">
            <template #cell="{ record }">
              <a-progress :percent="record.mem/100" :show-text="false" size="small" :status="record.mem>85?'danger':'normal'" />
              <span class="data" style="font-size:11.5px;color:var(--ink-3)">{{ record.mem }}%</span>
            </template>
          </a-table-column>
          <a-table-column title="会话" align="right" :width="80" data-index="sessions" />
          <a-table-column title="状态" align="center" :width="90">
            <template #cell="{ record }">
              <span class="zl-badge" :class="badge(record.status)">{{ text(record.status) }}</span>
            </template>
          </a-table-column>
        </template>
      </a-table>
    </div>

    <a-modal v-model:visible="show" title="纳管网关 · 接入引导" width="560px" @ok="enroll" ok-text="完成（等待首联）">
      <a-form :model="form" layout="vertical">
        <a-form-item label="网关名称" required><a-input v-model="form.name" placeholder="zl-gw-branch-bj" /></a-form-item>
        <a-form-item label="部署角色（同一镜像按角色裁剪，ZL-FR-406）">
          <a-select v-model="form.role">
            <a-option>ALL-IN-ONE</a-option><a-option>接入网关</a-option><a-option>站点网关</a-option>
          </a-select>
        </a-form-item>
      </a-form>
      <div class="gwm-step">① 在目标主机（8C/16G，云主机或工控机）执行离线安装包：</div>
      <pre class="gwm-code data">sudo ./zhulong-installer --role={{ roleArg }} \
  --join-token={{ token }} \
  --control=https://sdp.acme.com</pre>
      <a-button size="mini" @click="copyCmd"><template #icon><icon-copy /></template>复制命令</a-button>
      <div class="gwm-step">② 一次性接入令牌 10 分钟有效；首联后 systemd 五单元自启，水位回传本清单。</div>
    </a-modal>

    <a-drawer v-model:visible="drawer" :width="440" :footer="false">
      <template #title>网关详情 · {{ cur?.name }}</template>
      <div v-if="cur">
        <div class="gwd-row"><span>角色</span><b>{{ cur.role }}</b></div>
        <div class="gwd-row"><span>能力</span><b><span v-for="m in cur.modes" :key="m" class="zl-mode-pill" :class="`zl-mode--${m}`" style="margin-right:4px">{{ m }}</span></b></div>
        <div class="gwd-row"><span>版本</span><b class="data">{{ cur.version }}</b><a-button size="mini" style="margin-left:auto">升级（A/B 分区）</a-button></div>

        <div class="gwd-sec">systemd 单元（appliance 进程模型，PRD 4.1）</div>
        <div v-for="u in units" :key="u.name" class="gwd-unit">
          <span class="data gwd-unit__n">{{ u.name }}</span>
          <span class="gwd-unit__d">{{ u.desc }}</span>
          <span class="zl-badge" :class="u.state==='running'?'zl-badge--ok':u.state==='n/a'?'zl-badge--idle':'zl-badge--danger'">{{ u.state }}</span>
        </div>

        <div class="gwd-sec">资源水位（NFR-R1 预算 · CI 超 20% 门禁）</div>
        <div class="gwd-meter"><span>CPU</span><a-progress :percent="cur.cpu/100" :show-text="false" size="small" /><b class="data">{{ cur.cpu }}%</b></div>
        <div class="gwd-meter"><span>内存</span><a-progress :percent="cur.mem/100" :show-text="false" size="small" /><b class="data">{{ cur.mem }}%</b></div>
        <div class="gwd-meter"><span>会话</span><a-progress :percent="cur.sessions/1000" :show-text="false" size="small" /><b class="data">{{ cur.sessions }}/1000</b></div>

        <div class="gwd-sec">诊断</div>
        <a-space>
          <a-button size="small">网络诊断</a-button><a-button size="small">抓包工具</a-button><a-button size="small">信息收集</a-button>
        </a-space>
      </div>
    </a-drawer>
  </div>
</template>
<script setup lang="ts">
import { computed, reactive, ref, onMounted } from 'vue';
import { Message } from '@arco-design/web-vue';
import { gateways, type Gateway } from '@/mock';
import { listGateways } from '@/services/gateways';
import { gwStatus } from '@/lib/status';

// 初值用 mock 种子，控制面可达时替换为真实清单（不可达则降级保留种子）。
const rows = ref<Gateway[]>([...gateways]);
onMounted(async () => {
  try {
    rows.value = await listGateways();
  } catch {
    /* 控制面未起：保留 mock 种子 */
  }
});
const badge = (s: string) => gwStatus(s).badge;
const text = (s: string) => gwStatus(s).label;

const show = ref(false);
const form = reactive({ name: '', role: '接入网关' });
const token = ref('ZL-' + Math.random().toString(36).slice(2, 10).toUpperCase());
const roleArg = computed(() => ({ 'ALL-IN-ONE': 'aio', '接入网关': 'access', '站点网关': 'site' }[form.role]));
const copyCmd = () => { navigator.clipboard?.writeText(`sudo ./zhulong-installer --role=${roleArg.value} --join-token=${token.value} --control=https://sdp.acme.com`); Message.success('安装命令已复制'); };
const enroll = () => {
  if (!form.name) return Message.warning('请填写网关名称');
  const modes = form.role === 'ALL-IN-ONE' ? ['ssl', 'mesh', 'ipsec'] : form.role === '接入网关' ? ['ssl', 'mesh'] : ['ipsec', 'mesh'];
  rows.value.push({ name: form.name, role: form.role, modes: modes as any, status: 'offline', cpu: 0, mem: 0, sessions: 0, version: '—（待首联）' });
  Message.success(`${form.name} 已登记 · 等待安装首联（令牌 10 分钟有效）`);
  form.name = ''; token.value = 'ZL-' + Math.random().toString(36).slice(2, 10).toUpperCase();
};

const drawer = ref(false);
const cur = ref<Gateway | null>(null);
const openGw = (r: Gateway) => { cur.value = r; drawer.value = true; };
const units = computed(() => {
  if (!cur.value) return [];
  const on = cur.value.status !== 'offline';
  const has = (m: string) => cur.value!.modes.includes(m as any);
  return [
    { name: 'zhulong-control', desc: '控制面单体（策略+IdP+控制台）', state: cur.value.role === 'ALL-IN-ONE' ? (on ? 'running' : 'dead') : 'n/a' },
    { name: 'zhulong-ssl-gw', desc: 'SSL/SDP 引擎（Tongsuo）', state: has('ssl') ? (on ? 'running' : 'dead') : 'n/a' },
    { name: 'zhulong-mesh', desc: 'Mesh 角色集（derp/连接器）', state: has('mesh') ? (on ? 'running' : 'dead') : 'n/a' },
    { name: 'zhulong-ipsec', desc: 'strongSwan + 数据面驱动', state: has('ipsec') ? (on ? 'running' : 'dead') : 'n/a' },
    { name: 'zhulong-agent', desc: '升级/备份/自监控/日志轮转', state: on ? 'running' : 'dead' }
  ];
});
</script>
<style scoped>
:deep(.row-click) { cursor: pointer; }
.gwm-step { font-size: 12px; color: var(--ink-2); margin: 12px 0 8px; line-height: 1.6; }
.gwm-code { margin: 0 0 8px; background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--r-md); padding: 10px 12px; font-size: 11.5px; color: var(--accent-2); white-space: pre-wrap; }
.gwd-row { display: flex; align-items: center; gap: 12px; padding: 8px 0; font-size: 12.5px; }
.gwd-row > span { color: var(--ink-3); min-width: 48px; }
.gwd-row b { color: var(--ink); font-weight: 600; }
.gwd-sec { font-size: 11.5px; font-weight: 700; color: var(--ink-3); margin: 16px 0 8px; }
.gwd-unit { display: flex; align-items: center; gap: 10px; padding: 7px 0; border-bottom: 1px solid var(--line); }
.gwd-unit__n { font-size: 12px; font-weight: 650; color: var(--ink); min-width: 122px; }
.gwd-unit__d { flex: 1; font-size: 11px; color: var(--ink-3); }
.gwd-meter { display: flex; align-items: center; gap: 10px; padding: 6px 0; font-size: 12px; color: var(--ink-3); }
.gwd-meter > span { min-width: 36px; }
.gwd-meter b { min-width: 64px; text-align: right; color: var(--ink); }
</style>
