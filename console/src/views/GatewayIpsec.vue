<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">IPSec 站点编排<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">站点互联全生命周期：策略 → IKE SA → Child SA · 判定走统一模型（ZL-FR-607 / PUC-11）</div>
      </div>
      <a-button type="primary" @click="show = true"><template #icon><icon-plus /></template>新建站点隧道</a-button>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1.55fr 1fr;">
      <!-- 隧道列表 -->
      <div class="zl-card">
        <a-table :data="rows" :pagination="false" :bordered="false" row-key="id"
                 :row-class="(r:any)=> r.id===sel?.id ? 'row-on':''" @row-click="(r:any)=>sel=r">
          <template #columns>
            <a-table-column title="隧道">
              <template #cell="{ record }">
                <div style="display:flex;flex-direction:column;gap:2px">
                  <span class="data" style="font-weight:600;color:var(--ink);font-size:12.5px">{{ record.id }}</span>
                  <span style="font-size:11.5px;color:var(--ink-3)">{{ record.local }} ↔ {{ record.remote }}</span>
                </div>
              </template>
            </a-table-column>
            <a-table-column title="套件" :width="150">
              <template #cell="{ record }">
                <span class="zl-badge" :class="record.suite.startsWith('国密') ? 'zl-badge--accent' : 'zl-badge--idle'">{{ record.suite }}</span>
              </template>
            </a-table-column>
            <a-table-column title="Child SA" align="center" :width="84">
              <template #cell="{ record }"><span class="data">{{ record.childSa }}</span></template>
            </a-table-column>
            <a-table-column title="状态" align="center" :width="90">
              <template #cell="{ record }">
                <span class="zl-badge" :class="stBadge(record.status)">{{ stText(record.status) }}</span>
              </template>
            </a-table-column>
          </template>
        </a-table>
        <div class="idp-note">
          <icon-info-circle /> IPSec 执行点粒度为站点/子网；与用户级策略冲突时取交集并在此可视化提示，不允许静默放大权限（ZL-FR-107）。
        </div>
      </div>

      <!-- SA 生命周期面板 -->
      <div class="zl-card zl-card__pad" v-if="sel">
        <div class="zl-card__title">SA 生命周期 · <span class="data" style="color:var(--accent-2)">{{ sel.id }}</span></div>

        <div class="sa-sel">
          <div class="sa-sel__k">Traffic Selector</div>
          <div v-for="s in sel.selectors" :key="s" class="sa-sel__v data">{{ s }}</div>
        </div>

        <div class="sa-steps">
          <div v-for="(p, i) in phases" :key="p.phase" class="sa-step" :class="stepCls(i)">
            <span class="sa-step__glyph">{{ stepGlyph(i) }}</span>
            <div>
              <div class="sa-step__p data">{{ p.phase }}</div>
              <div class="sa-step__d">{{ p.desc }}</div>
            </div>
          </div>
        </div>

        <div class="fed-grid" style="margin-top: 14px;">
          <div class="fed-kv"><span>IKE 版本</span><b class="data">{{ sel.ike }}</b></div>
          <div class="fed-kv"><span>下次 Rekey</span><b class="data">{{ sel.rekeyIn }}</b></div>
          <div class="fed-kv"><span>接收</span><b class="data">{{ sel.rx }}</b></div>
          <div class="fed-kv"><span>发送</span><b class="data">{{ sel.tx }}</b></div>
        </div>

        <a-space style="margin-top: 14px;">
          <a-button size="small" type="primary" :disabled="sel.status==='established'" :loading="busy==='up'" @click="initiate(sel)">发起协商</a-button>
          <a-button size="small" status="warning" :disabled="sel.status!=='established'" :loading="busy==='rekey'" @click="rekey(sel)">Rekey</a-button>
          <a-button size="small" status="danger" :disabled="sel.status==='down'" @click="teardown(sel)">拆除</a-button>
        </a-space>
      </div>
    </div>

    <a-modal v-model:visible="show" title="新建站点隧道" width="560px" @ok="add" ok-text="创建并发起协商">
      <a-form :model="form" layout="vertical" auto-label-width>
        <a-form-item label="本端网关">
          <a-select v-model="form.local">
            <a-option v-for="g in localOptions" :key="g.name" :value="g.name">{{ g.name }}</a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="本端地址" required>
          <a-input v-model="form.localAddr" placeholder="本端公网 IP / 域名（随所选网关自动填充，可改）" />
        </a-form-item>
        <a-form-item label="对端名称" required><a-input v-model="form.remoteName" placeholder="例如：北京分支" /></a-form-item>
        <a-form-item label="对端地址" required><a-input v-model="form.remoteAddr" placeholder="公网 IP 或域名" /></a-form-item>
        <a-form-item label="Traffic Selector（本端 ↔ 对端）" required>
          <a-input v-model="form.selector" placeholder="10.8.0.0/16 ↔ 10.40.0.0/16" />
        </a-form-item>
        <a-form-item label="加密套件预设">
          <a-radio-group v-model="form.suite" @change="applySuite">
            <a-radio value="国密 SM2/SM3/SM4">国密 SM2/SM3/SM4</a-radio>
            <a-radio value="AES-GCM/SHA2">AES-GCM/SHA2</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-collapse :bordered="false" style="margin:-4px 0 4px">
          <a-collapse-item header="算法套件（按 IKE 阶段，可逐项调整）" key="alg">
            <div class="alg-phase">阶段一 · IKE_SA</div>
            <a-grid :cols="2" :col-gap="20" :row-gap="4">
              <a-grid-item>
                <a-form-item label="加密算法">
                  <a-select v-model="form.ikeEnc"><a-option v-for="o in encOpts" :key="o" :value="o">{{ o }}</a-option></a-select>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="认证算法">
                  <a-select v-model="form.ikeAuth"><a-option v-for="o in authOpts" :key="o" :value="o">{{ o }}</a-option></a-select>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="DH 组">
                  <a-select v-model="form.dhGroup"><a-option v-for="d in dhOpts" :key="d.v" :value="d.v">{{ d.label }}</a-option></a-select>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="PRF 算法">
                  <a-select v-model="form.ikePrf" allow-clear placeholder="默认（跟随认证）"><a-option v-for="o in authOpts" :key="o" :value="o">{{ o }}</a-option></a-select>
                </a-form-item>
              </a-grid-item>
            </a-grid>
            <div class="alg-phase">阶段二 · CHILD_SA（ESP）</div>
            <a-grid :cols="2" :col-gap="20" :row-gap="4">
              <a-grid-item>
                <a-form-item label="加密算法">
                  <a-select v-model="form.espEnc"><a-option v-for="o in encOpts" :key="o" :value="o">{{ o }}</a-option></a-select>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="认证算法">
                  <a-select v-model="form.espAuth"><a-option v-for="o in authOpts" :key="o" :value="o">{{ o }}</a-option></a-select>
                </a-form-item>
              </a-grid-item>
            </a-grid>
            <p class="zl-form-hint">弱算法（DES/3DES/MD5/SHA1/DH≤5）仅供老旧设备互通，新建议用 SM4/SM3 或 AES256/SHA256+。</p>
          </a-collapse-item>
          <a-collapse-item header="高级组网参数（DPD / 生命周期 / NAT-T / PFS）" key="adv">
            <a-grid :cols="2" :col-gap="20" :row-gap="4">
              <a-grid-item>
                <a-form-item label="协商模式" field="ikeMode">
                  <a-select v-model="form.ikeMode">
                    <a-option value="main">主模式（main）</a-option>
                    <a-option value="aggressive">野蛮模式（aggressive，IKEv1）</a-option>
                  </a-select>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="DPD 动作" field="dpdAction">
                  <a-select v-model="form.dpdAction">
                    <a-option value="hold">hold（按需重连）</a-option>
                    <a-option value="restart">restart（立即重连）</a-option>
                    <a-option value="clear">clear（清除）</a-option>
                  </a-select>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="DPD 周期" field="dpdDelay">
                  <a-input-number v-model="form.dpdDelay" :min="0" placeholder="30" style="width:160px">
                    <template #suffix>秒</template>
                  </a-input-number>
                  <template #extra>0 = 沿用默认 30s</template>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="DPD 超时" field="dpdTimeout">
                  <a-input-number v-model="form.dpdTimeout" :min="0" placeholder="120" style="width:160px">
                    <template #suffix>秒</template>
                  </a-input-number>
                  <template #extra>0 = 沿用默认 120s</template>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="IKE 生命周期" field="ikeLifetime">
                  <a-input-number v-model="form.ikeLifetime" :min="0" placeholder="14400" style="width:160px">
                    <template #suffix>秒</template>
                  </a-input-number>
                  <template #extra>0 = 沿用默认 14400s</template>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="ESP 生命周期" field="espLifetime">
                  <a-input-number v-model="form.espLifetime" :min="0" placeholder="3600" style="width:160px">
                    <template #suffix>秒</template>
                  </a-input-number>
                  <template #extra>0 = 沿用默认 3600s</template>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="抗重放窗口" field="replayWindow">
                  <a-input-number v-model="form.replayWindow" :min="0" placeholder="128" style="width:160px">
                    <template #suffix>包</template>
                  </a-input-number>
                  <template #extra>0 = 沿用默认 128</template>
                </a-form-item>
              </a-grid-item>
              <a-grid-item>
                <a-form-item label="流量协议限定" field="tsProto">
                  <a-select v-model="form.tsProto" allow-clear placeholder="全部协议">
                    <a-option value="tcp">tcp</a-option>
                    <a-option value="udp">udp</a-option>
                    <a-option value="icmp">icmp</a-option>
                  </a-select>
                </a-form-item>
              </a-grid-item>
              <a-grid-item :span="2">
                <a-form-item label="安全增强 / 穿越">
                  <a-space size="large" wrap>
                    <a-checkbox v-model="form.pfs">启用 PFS（完美前向保密）</a-checkbox>
                    <a-checkbox v-model="form.natt">强制 NAT-T 穿越</a-checkbox>
                    <a-checkbox v-model="form.peerIsFqdn">对端为动态地址/域名</a-checkbox>
                  </a-space>
                </a-form-item>
              </a-grid-item>
            </a-grid>
          </a-collapse-item>
        </a-collapse>
      </a-form>
      <p class="zl-form-hint">站点级策略与用户级策略冲突时取交集（ZL-FR-107）；SA 生命周期（IKE_SA_INIT → IKE_AUTH → CHILD_SA → REKEY）建后可视。</p>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { ipsecTunnels, ikeLifecycle, type IpsecTunnel } from '@/mock';
import { saStatus } from '@/lib/status';

const rows = ref<IpsecTunnel[]>([...ipsecTunnels]);
const sel = ref<IpsecTunnel | null>(rows.value[0]);
const live = ref(false); // 数据是否来自真实 zhulong-control（经 /ctl 反代）

// 本端网关清单（含真实公网地址）：live 拉 /ctl/api/gateways，不可达时用静态种子。
// 站点隧道的 local_addrs 必须是网关真实地址，不能再下发占位符 1.1.1.1。
type Gw = { name: string; addr: string };
const STATIC_GW: Gw[] = [
  { name: 'zl-gw-hq-01', addr: '124.223.225.77' },
  { name: 'zl-gw-dmz-02', addr: '124.223.225.78' },
  { name: 'zl-gw-branch-sh', addr: '116.62.131.21' },
];
const gateways = ref<Gw[]>([]);
const localOptions = computed<Gw[]>(() => (gateways.value.length ? gateways.value : STATIC_GW));
const gwAddr = (name: string) => localOptions.value.find((g) => g.name === name)?.addr ?? '';

async function loadGateways() {
  try {
    const r = await fetch('/ctl/api/gateways');
    if (r.ok) {
      const list: any[] = await r.json();
      if (Array.isArray(list) && list.length) gateways.value = list.map((g) => ({ name: g.name, addr: g.addr || '' }));
    }
  } catch { /* 控制面不可达：沿用静态网关清单 */ }
  if (!form.localAddr) form.localAddr = gwAddr(form.local); // 初始回填所选网关地址
}

// 从 zhulong-control 拉取真实 IPSEC 策略 + 活跃 SA，映射为 UI 隧道行
async function loadReal() {
  try {
    const [polR, saR] = await Promise.all([fetch('/ctl/ipsec/policies'), fetch('/ctl/ipsec/sas')]);
    if (!polR.ok) return;
    const pols: any[] = await polR.json();
    const sas: any[] = saR.ok ? await saR.json() : [];
    if (!Array.isArray(pols) || pols.length === 0) return;
    rows.value = pols.map((p) => {
      const sa = sas.find((s) => s.name === p.name);
      const gm = p.espEnc === 'SM4' && p.espAuth === 'SM3';
      const up = sa?.state === 'up';
      return {
        id: p.name, local: p.localAddr, remote: p.peerAddr,
        selectors: [`${p.srcTs} ↔ ${p.dstTs}`],
        ike: p.ikeVersion === 'V1' ? 'IKEv1' : 'IKEv2',
        suite: gm ? '国密 SM2/SM3/SM4' : `${p.espEnc}-${p.espAuth}`,
        status: up ? 'established' : p.enabled ? 'connecting' : 'down',
        childSa: up ? 1 : 0, rekeyIn: up ? '~7980s' : '—',
        rx: sa ? String(sa.inBytes) : '0', tx: sa ? String(sa.outBytes) : '0'
      } as IpsecTunnel;
    });
    sel.value = rows.value[0] ?? null;
    live.value = true;
  } catch { /* control 未起：保留 mock 演示数据 */ }
}
onMounted(() => { loadGateways(); loadReal(); });

// 穷举支持的算法（与后端 ipsec.proposalToken/dhToken/prfToken 对齐）
const encOpts = ['DES', '3DES', 'AES128', 'AES192', 'AES256', 'SM4'];
const authOpts = ['MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'SM3'];
const dhOpts = [
  { v: '1', label: '1 (MODP768)' }, { v: '2', label: '2 (MODP1024)' }, { v: '5', label: '5 (MODP1536)' },
  { v: '14', label: '14 (MODP2048)' }, { v: '15', label: '15 (MODP3072)' }, { v: '16', label: '16 (MODP4096)' },
  { v: '17', label: '17 (MODP6144)' }, { v: '18', label: '18 (MODP8192)' },
];

const show = ref(false);
const form = reactive({
  local: 'zl-gw-hq-01', localAddr: '', remoteName: '', remoteAddr: '', selector: '', suite: '国密 SM2/SM3/SM4',
  // 按 IKE 阶段的算法套件（默认=国密预设）
  ikeEnc: 'SM4', ikeAuth: 'SM3', dhGroup: '14', ikePrf: '', espEnc: 'SM4', espAuth: 'SM3',
  // 高级组网参数（零值=后端沿用默认，向后兼容）
  ikeMode: 'main', dpdAction: 'hold', dpdDelay: 0, dpdTimeout: 0,
  ikeLifetime: 0, espLifetime: 0, replayWindow: 0, tsProto: '',
  pfs: false, natt: false, peerIsFqdn: false,
});

// applySuite：预设快速填充各阶段算法（用户仍可在算法套件里逐项覆盖）。
function applySuite(val: string | number | boolean) {
  if (String(val).startsWith('国密')) {
    Object.assign(form, { ikeEnc: 'SM4', ikeAuth: 'SM3', dhGroup: '14', ikePrf: '', espEnc: 'SM4', espAuth: 'SM3' });
  } else {
    Object.assign(form, { ikeEnc: 'AES256', ikeAuth: 'SHA256', dhGroup: '14', ikePrf: '', espEnc: 'AES256', espAuth: 'SHA256' });
  }
}
// 切换本端网关时回填其真实公网地址（用户仍可手改作兜底）
watch(() => form.local, (name) => { form.localAddr = gwAddr(name); });
const add = async () => {
  if (!form.remoteName || !form.remoteAddr || !form.selector) return Message.warning('对端与 selector 为必填');
  const localAddr = (form.localAddr || gwAddr(form.local)).trim();
  if (!localAddr) return Message.warning('本端网关地址未知，请填写本端地址');
  const name = 'tun-' + form.remoteName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const gm = form.suite.startsWith('国密');
  // 国密双证走 IKEv2 主模式；野蛮模式(IKEv1) 与 SM2 证书流程不兼容，强制回退并提示。
  const aggressive = form.ikeMode === 'aggressive' && !gm;
  if (form.ikeMode === 'aggressive' && gm) Message.info('国密 SM2 套件走 IKEv2 主模式，已忽略野蛮模式');
  const [src, dst] = form.selector.split('↔').map((s) => s.trim());
  const policy = {
    name, enabled: true, localAddr, peerAddr: form.remoteAddr,
    srcTs: src || '10.8.0.0/16', dstTs: dst || '10.40.0.0/16',
    auth: gm ? 'sm2' : 'rsa', localId: form.local, peerId: form.remoteName,
    ikeVersion: aggressive ? 'V1' : 'V2',
    // 按 IKE 阶段下发用户所选算法（穷举矩阵），不再由套件硬编码
    ikeEnc: form.ikeEnc, ikeAuth: form.ikeAuth, dhGroup: form.dhGroup, ikePrf: form.ikePrf || '',
    espEnc: form.espEnc, espAuth: form.espAuth,
    dpdAction: form.dpdAction || 'hold',
    // 高级参数：仅传非零值，零值由后端按默认渲染（向后兼容）
    ikeMode: aggressive ? 'aggressive' : '',
    natt: form.natt, peerIsFqdn: form.peerIsFqdn, pfs: form.pfs,
    dpdDelay: form.dpdDelay || 0, dpdTimeout: form.dpdTimeout || 0,
    ikeLifetime: form.ikeLifetime || 0, espLifetime: form.espLifetime || 0,
    replayWindow: form.replayWindow || 0, tsProto: form.tsProto || '',
  };
  try {
    const r = await fetch('/ctl/ipsec/policies', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(policy) });
    if (r.ok) {
      await loadReal();
      Message.success(`隧道 ${name} 已下发 zhulong-control · ${gm ? '国密 SM4/SM3' : '通用'}套件协商中`);
      show.value = false; Object.assign(form, { remoteName: '', remoteAddr: '', selector: '' });
      return;
    }
  } catch { /* 落到本地 mock 追加 */ }
  const t: IpsecTunnel = { id: name, local: form.local, remote: `${form.remoteName} · ${form.remoteAddr}`, selectors: [form.selector], ike: 'IKEv2', suite: form.suite as any, status: 'connecting', childSa: 0, rekeyIn: '—', rx: '0', tx: '0' };
  rows.value.push(t); sel.value = t;
  Message.success(`隧道 ${t.id} 已创建 · IKE_SA_INIT 协商中`);
  show.value = false; Object.assign(form, { remoteName: '', remoteAddr: '', selector: '' });
};
const phases = ikeLifecycle;

/* —— SA 操作（live 调 zhulong-control，否则本地状态机推进 + 阶段动画）—— */
const busy = ref<'' | 'up' | 'rekey'>('');
async function ctlAction(name: string, action: string) {
  if (!live.value) return true; // 演示：本地推进
  try {
    const r = await fetch(`/ctl/ipsec/sa?name=${encodeURIComponent(name)}&action=${action}`, { method: 'POST' });
    return r.ok;
  } catch { return false; }
}
async function initiate(t: IpsecTunnel) {
  busy.value = 'up';
  t.status = 'connecting';
  const ok = await ctlAction(t.id, 'initiate');
  setTimeout(() => {
    busy.value = '';
    if (!ok && live.value) { t.status = 'down'; return Message.error(`${t.id} 协商失败`); }
    t.status = 'established'; t.childSa = 1; t.rekeyIn = '~7980s';
    Message.success(`${t.id} 已建立 · IKE_SA_INIT → IKE_AUTH → CHILD_SA 完成${live.value ? '' : '（演示）'}`);
  }, 900);
}
async function rekey(t: IpsecTunnel) {
  busy.value = 'rekey';
  const ok = await ctlAction(t.id, 'rekey');
  setTimeout(() => {
    busy.value = '';
    if (!ok && live.value) return Message.error(`${t.id} Rekey 失败`);
    t.rekeyIn = '~8000s';
    Message.success(`${t.id} 已重新协商密钥 · 新 CHILD_SA 平滑切换，无丢包`);
  }, 700);
}
function teardown(t: IpsecTunnel) {
  Modal.warning({
    title: `拆除隧道「${t.id}」？`, hideCancel: false, okText: '确认拆除', cancelText: '取消',
    content: '拆除后该站点子网经此隧道的流量中断，依赖它的用户级策略取交集后同步收敛。进入审计链。',
    onOk: async () => {
      const ok = await ctlAction(t.id, 'terminate');
      if (!ok && live.value) return Message.error(`${t.id} 拆除失败`);
      t.status = 'down'; t.childSa = 0; t.rekeyIn = '—';
      Message.success(`${t.id} 已拆除 · CHILD_SA / IKE_SA 已删除`);
    }
  });
}

// 按隧道状态推导各阶段呈现：established=前三步完成；connecting=走到第2步；down=未开始
const doneCount = computed(() => (sel.value?.status === 'established' ? 3 : sel.value?.status === 'connecting' ? 1 : 0));
const stepCls = (i: number) => (i < doneCount.value ? 'done' : i === doneCount.value && sel.value?.status === 'connecting' ? 'run' : '');
const stepGlyph = (i: number) => (i < doneCount.value ? '✓' : i === doneCount.value && sel.value?.status === 'connecting' ? '…' : '·');

const stBadge = (s: string) => saStatus(s).badge;
const stText = (s: string) => saStatus(s).label;
</script>

<style scoped>
.alg-phase { font-size: 11.5px; font-weight: 700; color: var(--accent-2); margin: 4px 0 6px; }
.alg-phase ~ .alg-phase { margin-top: 12px; }
.zl-form-hint { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin: 6px 0 0; }
:deep(.row-on) { background: var(--accent-soft) !important; }
:deep(.arco-table-tr) { cursor: pointer; }
.idp-note { display: flex; gap: 8px; align-items: flex-start; padding: 12px 16px; font-size: 12px; color: var(--ink-3); border-top: 1px solid var(--line); line-height: 1.6; }
.sa-sel { background: var(--surface-2); border-radius: var(--r-md); padding: 10px 14px; margin: 12px 0; }
.sa-sel__k { font-size: 11px; color: var(--ink-3); margin-bottom: 4px; }
.sa-sel__v { font-size: 12.5px; color: var(--ink); }
.sa-steps { display: flex; flex-direction: column; }
.sa-step { display: flex; gap: 10px; align-items: flex-start; padding: 8px 0; opacity: 0.55; }
.sa-step.done, .sa-step.run { opacity: 1; }
.sa-step__glyph {
  width: 20px; height: 20px; border-radius: 50%; flex: none; display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 700; background: var(--surface-3); color: var(--ink-3);
}
.sa-step.done .sa-step__glyph { background: var(--ok-soft); color: var(--ok); }
.sa-step.run .sa-step__glyph { background: var(--warn-soft); color: var(--warn); }
.sa-step__p { font-size: 12.5px; font-weight: 650; color: var(--ink); }
.sa-step__d { font-size: 11.5px; color: var(--ink-3); margin-top: 1px; }
.fed-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; background: var(--line); border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; }
.fed-kv { background: var(--surface); padding: 10px 12px; display: flex; flex-direction: column; gap: 4px; }
.fed-kv span { font-size: 11px; color: var(--ink-3); }
.fed-kv b { font-size: 12.5px; color: var(--ink); font-weight: 600; }
</style>
