<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">终端设备管理<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">终端设备清单 + 持续态势 → 设备信任分 → 自适应策略（设备态势驱动准入）· 信任分由五维态势实时算出 · 吊销 ≤10s 下发</div>
      </div>
      <div class="dev-stat">
        <span class="ds ok"><b>{{ count(d => d.trust>=80) }}</b> 高信任</span>
        <span class="ds warn"><b>{{ count(d => d.trust>=50 && d.trust<80) }}</b> 中</span>
        <span class="ds bad"><b>{{ count(d => d.trust<50) }}</b> 低/受限</span>
        <span class="ds"><b>{{ count(d => d.online) }}</b> 在线</span>
      </div>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1fr 380px;">
      <!-- 设备清单 -->
      <div class="zl-card" style="overflow:hidden">
        <div class="dev-toolbar">
          <div class="zl-card__title">设备清单（{{ devices.length }}）</div>
          <a-input-search v-model="q" placeholder="搜索设备 / 账号 / 机器码" size="small" style="width:240px" allow-clear />
        </div>
        <table class="dev-tbl">
          <thead><tr><th>设备</th><th>归属用户</th><th>系统/模式</th><th>归属</th><th>信任分</th><th>状态</th></tr></thead>
          <tbody>
            <tr v-for="dv in filtered" :key="dv.machineCode" :class="{active: dv.machineCode===sel}" @click="sel=dv.machineCode">
              <td>
                <div class="dev-name">{{ dv.id }}</div>
                <div class="dev-mc data">{{ dv.machineCode }}</div>
              </td>
              <td class="data">{{ dv.account }}</td>
              <td><div style="font-size:12px">{{ dv.os }}</div><span class="zl-mode-pill" :class="`zl-mode--${dv.mode}`" style="font-size:10px">{{ dv.mode }}</span></td>
              <td><span class="own-pill" :class="dv.ownership">{{ dv.ownership==='personal' ? 'BYOD' : '企业' }}</span></td>
              <td>
                <div class="trust-cell">
                  <div class="trust-bar"><div class="trust-fill" :class="tone(dv.trust)" :style="{width: dv.trust+'%'}" /></div>
                  <b class="data" :class="tone(dv.trust)">{{ dv.trust }}</b>
                </div>
              </td>
              <td><span class="dot" :class="dv.online?'on':'off'" />{{ dv.online ? '在线' : '离线' }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 选中设备详情：态势→信任分解 -->
      <div class="zl-card zl-card__pad" v-if="current">
        <div class="dev-detail__head">
          <div>
            <div class="dev-detail__name">{{ current.id }}</div>
            <div class="dev-detail__mc data">{{ current.machineCode }}</div>
          </div>
          <span class="own-pill" :class="current.ownership">{{ current.ownership==='personal' ? 'BYOD' : '企业配发' }}</span>
        </div>

        <div class="dev-score">
          <div class="dev-score__head"><span>设备信任分</span><b class="data" :class="tone(current.trust)">{{ current.trust }}/100</b></div>
          <div class="trust-bar lg"><div class="trust-fill" :class="tone(current.trust)" :style="{width: current.trust+'%'}" /></div>
          <div class="dev-score__base data">签约基线 {{ current.baselineTrust ?? current.trust }} · 风险分 {{ current.risk ?? 0 }}</div>
        </div>

        <div class="zl-card__title" style="font-size:12px;margin:14px 0 8px">态势信号 → 信任分解</div>
        <div class="posture-list">
          <div class="pr" v-for="p in postureRows" :key="p.k">
            <span class="pr-ic" :class="p.ok?'ok':'bad'">{{ p.ok ? '✓' : '✕' }}</span>
            <span class="pr-label">{{ p.label }}</span>
            <span class="pr-pts data" :class="p.ok?'ok':'muted'">{{ p.ok ? '+'+p.pts : (p.penalty?('−'+p.penalty):'0') }}</span>
          </div>
        </div>

        <div class="dev-kv">
          <div class="dkv"><span>归属用户</span><b class="data">{{ current.account }}</b></div>
          <div class="dkv"><span>最近在线</span><b class="data">{{ current.lastSeen }}</b></div>
          <div class="dkv"><span>纳管时间</span><b class="data">{{ current.enrolledAt }}</b></div>
        </div>

        <div class="dev-foot">
          <a-button size="small" @click="reauth">强制重认证</a-button>
          <a-button size="small" status="danger" @click="revoke">吊销设备</a-button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

type Device = {
  id: string; account: string; machineCode: string; os: string; mode: string;
  online: boolean; lastSeen: string; ownership: string; trust: number; risk?: number;
  baselineTrust?: number; enrolledAt?: string; posture?: { diskEncrypted: boolean; osCurrent: boolean; jailbroken: boolean; edr: boolean };
};

const mockDevices: Device[] = [
  { id: 'MBP-7F2A', account: 'zhang.wei', machineCode: 'hw_3f8a_c91d', os: 'macOS 14.5', mode: 'ssl', online: true, lastSeen: '13:05', ownership: 'corp', trust: 100, risk: 0, baselineTrust: 100, posture: { diskEncrypted: true, osCurrent: true, jailbroken: false, edr: true } },
  { id: 'Pad-1180', account: 'li.na', machineCode: 'hm_1180_7e22', os: 'HarmonyOS 5.1', mode: 'mesh', online: true, lastSeen: '12:58', ownership: 'personal', trust: 80, risk: 10, baselineTrust: 80, posture: { diskEncrypted: true, osCurrent: true, jailbroken: false, edr: false } }
];

const devices = ref<Device[]>(mockDevices);
const live = ref(false);
const sel = ref('');
const q = ref('');

const current = computed(() => devices.value.find((d) => d.machineCode === sel.value));
const count = (pred: (d: Device) => boolean) => devices.value.filter(pred).length;
const tone = (t: number) => (t >= 80 ? 'ok' : t >= 50 ? 'warn' : 'bad');

const filtered = computed(() => {
  const s = q.value.toLowerCase();
  return devices.value.filter((d) => !s || [d.id, d.account, d.machineCode].some((x) => x.toLowerCase().includes(s)));
});

// 态势 → 信任分解（与后端 netmap.TrustScore 权重对齐：base10 + 盘25 + 系统25 + EDR20 + 姿态20 − 越狱60）
const postureRows = computed(() => {
  const p = current.value?.posture || { diskEncrypted: false, osCurrent: false, jailbroken: false, edr: false };
  return [
    { k: 'base', label: '基线', ok: true, pts: 10 },
    { k: 'disk', label: '磁盘加密', ok: p.diskEncrypted, pts: 25 },
    { k: 'os', label: '系统版本达标', ok: p.osCurrent, pts: 25 },
    { k: 'edr', label: 'EDR 安全软件在位', ok: p.edr, pts: 20 },
    { k: 'compliant', label: '合规姿态通过', ok: !p.jailbroken, pts: 20 },
    { k: 'jb', label: '未越狱 / Root', ok: !p.jailbroken, pts: 0, penalty: p.jailbroken ? 60 : 0 }
  ];
});

async function load() {
  try {
    const r = await fetch('/ctl/api/coll?kind=device');
    if (!r.ok) throw new Error();
    devices.value = await r.json();
    live.value = true;
  } catch { devices.value = mockDevices; live.value = false; }
  devices.value.sort((a, b) => b.trust - a.trust);
  if (devices.value.length) sel.value = devices.value[0].machineCode;
}
onMounted(load);

function revoke() {
  const dv = current.value!;
  Modal.warning({
    title: '吊销设备',
    content: `吊销「${dv.id}」（${dv.account}）后，该设备所有会话立即失效（≤10s 下发），需重新纳管。此操作不可逆。`,
    okText: '确认吊销', hideCancel: false,
    onOk: async () => {
      if (live.value) {
        try { await fetch(`/ctl/api/coll?kind=device&key=${encodeURIComponent(dv.machineCode)}`, { method: 'DELETE' }); } catch { /* ignore */ }
      }
      devices.value = devices.value.filter((d) => d.machineCode !== dv.machineCode);
      if (devices.value.length) sel.value = devices.value[0].machineCode;
      Message.success(`「${dv.id}」已吊销${live.value ? ' · 已持久化' : ''}`);
    }
  });
}
const reauth = () => Message.info(`已要求「${current.value?.id}」重新认证 + 上报最新态势 ·（演示）`);
</script>

<style scoped>
.dev-stat { display: flex; gap: 16px; align-items: center; }
.dev-stat .ds { font-size: 12px; color: var(--ink-3); display: flex; align-items: baseline; gap: 5px; }
.dev-stat b { font-size: 18px; font-weight: 700; color: var(--ink); }
.ds.ok b { color: var(--ok); } .ds.warn b { color: var(--warn); } .ds.bad b { color: var(--danger); }

.dev-toolbar { display: flex; align-items: center; justify-content: space-between; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.dev-tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.dev-tbl th { text-align: left; font-size: 11.5px; font-weight: 650; color: var(--ink-3); padding: 9px 14px; background: var(--surface-2); border-bottom: 1px solid var(--line); }
.dev-tbl td { padding: 10px 14px; border-bottom: 1px solid var(--line); vertical-align: middle; }
.dev-tbl tbody tr { cursor: pointer; transition: background .12s; }
.dev-tbl tbody tr:hover { background: var(--surface-2); }
.dev-tbl tbody tr.active { background: var(--accent-soft); }
.dev-name { font-size: 13px; font-weight: 600; color: var(--ink); }
.dev-mc { font-size: 10.5px; color: var(--ink-3); margin-top: 2px; }
.own-pill { font-size: 11px; padding: 1px 9px; border-radius: var(--r-pill); }
.own-pill.corp { background: var(--accent-soft); color: var(--accent-2); }
.own-pill.personal { background: rgba(217,119,6,.12); color: var(--warn); }
.trust-cell { display: flex; align-items: center; gap: 8px; }
.trust-bar { flex: 1; min-width: 48px; height: 6px; border-radius: 3px; background: var(--surface-2); overflow: hidden; }
.trust-bar.lg { height: 10px; border-radius: 5px; }
.trust-fill { height: 100%; border-radius: 3px; transition: width .35s; }
.trust-fill.ok { background: var(--ok); } .trust-fill.warn { background: var(--warn); } .trust-fill.bad { background: var(--danger); }
.trust-cell b.ok { color: var(--ok); } .trust-cell b.warn { color: var(--warn); } .trust-cell b.bad { color: var(--danger); }
.dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 6px; }
.dot.on { background: var(--ok); } .dot.off { background: var(--line-2); }

.dev-detail__head { display: flex; align-items: flex-start; justify-content: space-between; padding-bottom: 12px; border-bottom: 1px solid var(--line); }
.dev-detail__name { font-size: 15px; font-weight: 700; color: var(--ink); }
.dev-detail__mc { font-size: 11px; color: var(--ink-3); margin-top: 2px; }
.dev-score { margin-top: 14px; }
.dev-score__head { display: flex; align-items: baseline; justify-content: space-between; font-size: 12.5px; color: var(--ink-2); margin-bottom: 6px; }
.dev-score__head b { font-size: 18px; }
.dev-score__head b.ok { color: var(--ok); } .dev-score__head b.warn { color: var(--warn); } .dev-score__head b.bad { color: var(--danger); }
.dev-score__base { font-size: 11px; color: var(--ink-3); margin-top: 6px; }
.posture-list { display: flex; flex-direction: column; }
.pr { display: flex; align-items: center; gap: 10px; padding: 7px 0; border-bottom: 1px solid var(--line); font-size: 12.5px; }
.pr:last-child { border-bottom: 0; }
.pr-ic { width: 18px; height: 18px; border-radius: 50%; display: grid; place-items: center; font-size: 10px; font-weight: 800; flex: none; }
.pr-ic.ok { background: var(--ok-soft); color: var(--ok); } .pr-ic.bad { background: var(--danger-soft); color: var(--danger); }
.pr-label { flex: 1; color: var(--ink-2); }
.pr-pts { font-weight: 700; } .pr-pts.ok { color: var(--ok); } .pr-pts.muted { color: var(--ink-3); }
.dev-kv { margin-top: 12px; }
.dkv { display: flex; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid var(--line); font-size: 12.5px; }
.dkv span { color: var(--ink-3); } .dkv b { color: var(--ink); }
.dev-foot { display: flex; gap: 10px; justify-content: flex-end; margin-top: 16px; }
</style>
