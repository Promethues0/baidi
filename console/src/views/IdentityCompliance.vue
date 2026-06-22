<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">终端合规基线<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">合规检测项 → 不达标扣信任分 → 处置建议 · 空基线 = 不影响信任分（旧行为）</div>
      </div>
      <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>{{ tab === 'baseline' ? '新建检测项' : '新建处置映射' }}</a-button>
    </div>

    <!-- 说明文案：weight=0 纯告警；处置为建议（自动收权待联动策略引擎） -->
    <div class="cp-tip">
      <span class="cp-tip__ic">ⓘ</span>
      <span>检测项 <b>weight=0</b> 为纯告警不扣分；处置动作仅为<b>建议</b>，自动收权待与策略引擎联动。条件按检测维度逐项判定，不达标即触发对应处置建议。</span>
    </div>

    <a-tabs v-model:active-key="tab" type="rounded">
      <!-- Tab1：检测项基线 -->
      <a-tab-pane key="baseline" title="检测项基线">
        <div class="zl-card">
          <a-table :data="baselines" :pagination="false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="检测项名称" data-index="name" :width="200">
                <template #cell="{ record }">
                  <span style="font-weight:600;color:var(--ink)">{{ record.name }}</span>
                  <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
                </template>
              </a-table-column>
              <a-table-column title="分类" data-index="category" :width="110">
                <template #cell="{ record }">
                  <span style="font-size:12px;color:var(--ink-2)">{{ record.category || '—' }}</span>
                </template>
              </a-table-column>
              <a-table-column title="检测维度" :width="130">
                <template #cell="{ record }">
                  <span style="font-size:12px;color:var(--ink-2)">{{ detectLabel(record.detectKey) }}</span>
                </template>
              </a-table-column>
              <a-table-column title="期望" align="center" :width="110">
                <template #cell="{ record }">
                  <span class="zl-badge" :class="record.expect ? 'zl-badge--ok' : 'zl-badge--idle'">{{ record.expect ? '应满足' : '应不存在' }}</span>
                </template>
              </a-table-column>
              <a-table-column title="扣分" align="center" :width="86">
                <template #cell="{ record }">
                  <span v-if="record.weight > 0" class="data" style="font-weight:650;color:var(--accent-2)">-{{ record.weight }}</span>
                  <span v-else class="zl-badge zl-badge--idle">纯告警</span>
                </template>
              </a-table-column>
              <a-table-column title="严重级" align="center" :width="96">
                <template #cell="{ record }">
                  <span class="zl-badge" :class="sevClass(record.severity)">{{ sevLabel(record.severity) }}</span>
                </template>
              </a-table-column>
              <a-table-column title="启用" align="center" :width="80">
                <template #cell="{ record }">
                  <a-switch v-model="record.enabled" size="small" @change="toggleBaseline(record)" />
                </template>
              </a-table-column>
              <a-table-column title="" align="center" :width="120">
                <template #cell="{ record }">
                  <a-space>
                    <a-button size="mini" @click="openEdit(record)">编辑</a-button>
                    <a-button size="mini" type="text" status="danger" @click="del(record)">删除</a-button>
                  </a-space>
                </template>
              </a-table-column>
            </template>
            <template #empty>
              <div class="cp-empty">
                <div class="cp-empty__big">未配置检测项 · 不影响信任分（旧行为）</div>
                <div class="cp-empty__sub">空基线即不对终端合规做任何扣分。需要把姿态合规纳入信任评分时再新建检测项；weight=0 可先纯告警观察。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>

      <!-- Tab2：处置映射 -->
      <a-tab-pane key="remediation" title="处置映射">
        <div class="zl-card">
          <a-table :data="policies" :pagination="false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="映射名称" data-index="name" :width="200">
                <template #cell="{ record }">
                  <span style="font-weight:600;color:var(--ink)">{{ record.name }}</span>
                  <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
                </template>
              </a-table-column>
              <a-table-column title="触发条件">
                <template #cell="{ record }">
                  <span style="font-size:12px;color:var(--ink-2)">{{ detectLabel(record.condition.detectKey) }} <b style="color:var(--accent-2)">不达标</b></span>
                </template>
              </a-table-column>
              <a-table-column title="处置动作" align="center" :width="120">
                <template #cell="{ record }">
                  <span class="zl-badge" :class="actClass(record.action)">{{ actLabel(record.action) }}</span>
                </template>
              </a-table-column>
              <a-table-column title="灰度" align="center" :width="110">
                <template #cell="{ record }">
                  <span class="data" style="font-size:12px;color:var(--ink-2)">{{ record.graceMin > 0 ? record.graceMin + ' 分钟' : '即时' }}</span>
                </template>
              </a-table-column>
              <a-table-column title="启用" align="center" :width="80">
                <template #cell="{ record }">
                  <a-switch v-model="record.enabled" size="small" @change="togglePolicy(record)" />
                </template>
              </a-table-column>
              <a-table-column title="" align="center" :width="120">
                <template #cell="{ record }">
                  <a-space>
                    <a-button size="mini" @click="openEdit(record)">编辑</a-button>
                    <a-button size="mini" type="text" status="danger" @click="del(record)">删除</a-button>
                  </a-space>
                </template>
              </a-table-column>
            </template>
            <template #empty>
              <div class="cp-empty">
                <div class="cp-empty__big">未配置处置映射 · 不达标仅扣分不收权</div>
                <div class="cp-empty__sub">没有任何处置映射时，检测项不达标只反映在信任分上，不触发放行 / 告警 / 限制 / 拒绝动作。自动收权待与策略引擎联动。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>
    </a-tabs>

    <!-- 检测项 编辑 / 新建 -->
    <a-modal v-if="tab === 'baseline'" v-model:visible="show" :title="editing ? '编辑检测项' : '新建检测项'" width="560px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="bForm" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="检测项标识（key）" required>
              <a-input v-model="bForm.key" placeholder="例如：av-present" :disabled="editing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="检测项名称" required>
              <a-input v-model="bForm.name" placeholder="例如：安全软件在运行" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="分类（category）">
          <a-input v-model="bForm.category" placeholder="例如：端点防护 / 数据安全 / 系统更新" />
        </a-form-item>

        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="检测维度（detectKey）">
              <a-select v-model="bForm.detectKey">
                <a-option v-for="d in detectOpts" :key="d.value" :value="d.value">{{ d.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="严重级（severity）">
              <a-select v-model="bForm.severity">
                <a-option v-for="s in sevOpts" :key="s.value" :value="s.value">{{ s.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="期望状态（expect）">
          <a-switch v-model="bForm.expect" />
          <span class="cp-hint" style="margin-left:10px">开启 = 期望满足（如安全软件应在运行）；关闭 = 期望不存在（如设备不应越狱 / Root）。</span>
        </a-form-item>

        <a-form-item label="不达标扣分（weight）">
          <a-input-number v-model="bForm.weight" :min="0" :style="{width:'200px'}">
            <template #suffix>分</template>
          </a-input-number>
          <div class="cp-hint">不达标时从终端信任分中扣除；0 = 纯告警不扣分（仅记录，便于先观察再上扣分）。</div>
        </a-form-item>

        <a-form-item label="启用本检测项">
          <a-switch v-model="bForm.enabled" />
          <span class="cp-hint" style="margin-left:10px">关闭 = 不参与合规判定（既不扣分也不告警）。</span>
        </a-form-item>
      </a-form>
      <div class="cp-modal-note">提示：检测项调整 ≤60s 下发在线端点 · 写审计。新增 weight&gt;0 的检测项会改变终端信任分，建议先以 weight=0 纯告警观察后再上扣分。</div>
    </a-modal>

    <!-- 处置映射 编辑 / 新建 -->
    <a-modal v-else v-model:visible="show" :title="editing ? '编辑处置映射' : '新建处置映射'" width="560px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="pForm" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="映射标识（key）" required>
              <a-input v-model="pForm.key" placeholder="例如：rm-jailbreak-deny" :disabled="editing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="映射名称" required>
              <a-input v-model="pForm.name" placeholder="例如：越狱设备拒绝接入" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="触发条件（condition）">
          <div class="cp-cond">
            <a-select v-model="pForm.condition.detectKey" :style="{flex:'1'}">
              <a-option v-for="d in detectOpts" :key="d.value" :value="d.value">{{ d.label }}</a-option>
            </a-select>
            <a-input model-value="不达标（op=fail）" readonly :style="{width:'160px'}" />
          </div>
          <div class="cp-hint">当所选检测维度判定为不达标（op 固定为 fail）时，触发下方处置动作。</div>
        </a-form-item>

        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="处置动作（action）">
              <a-select v-model="pForm.action">
                <a-option v-for="a in actOpts" :key="a.value" :value="a.value">{{ a.label }}</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="灰度（graceMin）">
              <a-input-number v-model="pForm.graceMin" :min="0" :style="{width:'100%'}">
                <template #suffix>分钟</template>
              </a-input-number>
            </a-form-item>
          </a-grid-item>
        </a-grid>
        <div class="cp-hint" style="margin-top:-8px">灰度 = 触发后给用户的整改宽限时间；0 = 即时执行。处置动作当前为建议，自动收权待与策略引擎联动。</div>

        <a-form-item label="启用本映射">
          <a-switch v-model="pForm.enabled" />
          <span class="cp-hint" style="margin-left:10px">关闭 = 不触发该处置（检测项仍按基线扣分）。</span>
        </a-form-item>
      </a-form>
      <div class="cp-modal-note">提示：处置映射调整 ≤60s 下发在线端点 · 写审计。deny / restrict 为强约束建议，联动策略引擎前不自动收权。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

/* —— 类型 —— */
// 检测项基线文档（kind=compbaseline，每条一文档）。
interface Baseline {
  key: string;
  name: string;
  category: string;
  detectKey: 'edr' | 'diskEncrypted' | 'osCurrent' | 'jailbroken';
  expect: boolean;          // true=应满足 / false=应不存在
  weight: number;           // 0=纯告警不扣分
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
}
// 处置映射文档（kind=remediationpolicy，每条一文档）。
interface Policy {
  key: string;
  name: string;
  condition: { detectKey: 'edr' | 'diskEncrypted' | 'osCurrent' | 'jailbroken'; op: 'fail' };
  action: 'allow' | 'alert' | 'restrict' | 'deny';
  graceMin: number;         // 0=即时
  enabled: boolean;
}

/* —— 选项与中文化 —— */
const detectOpts = [
  { value: 'edr', label: '安全软件' },
  { value: 'diskEncrypted', label: '磁盘加密' },
  { value: 'osCurrent', label: '系统补丁' },
  { value: 'jailbroken', label: '越狱 / Root' }
];
const sevOpts = [
  { value: 'low', label: 'low（低）' },
  { value: 'medium', label: 'medium（中）' },
  { value: 'high', label: 'high（高）' },
  { value: 'critical', label: 'critical（严重）' }
];
const actOpts = [
  { value: 'allow', label: 'allow 放行' },
  { value: 'alert', label: 'alert 告警' },
  { value: 'restrict', label: 'restrict 限制' },
  { value: 'deny', label: 'deny 拒绝' }
];
const detectLabel = (k: string) => detectOpts.find((d) => d.value === k)?.label ?? k;
const sevLabel = (s: string) => ({ low: '低', medium: '中', high: '高', critical: '严重' } as Record<string, string>)[s] ?? s;
const sevClass = (s: string) =>
  s === 'critical' ? 'zl-badge--danger' : s === 'high' ? 'zl-badge--warn' : s === 'medium' ? 'zl-badge--accent' : 'zl-badge--idle';
const actLabel = (a: string) => actOpts.find((x) => x.value === a)?.label ?? a;
const actClass = (a: string) =>
  a === 'deny' ? 'zl-badge--danger' : a === 'restrict' ? 'zl-badge--warn' : a === 'alert' ? 'zl-badge--accent' : 'zl-badge--ok';

/* —— 前端默认（mock，加载后端后覆盖；与后端 seed 同形） —— */
const baselineFallback: Baseline[] = [
  { key: 'av-present', name: '安全软件在运行', category: '端点防护', detectKey: 'edr', expect: true, weight: 20, severity: 'high', enabled: true },
  { key: 'disk-enc', name: '磁盘已加密', category: '数据安全', detectKey: 'diskEncrypted', expect: true, weight: 15, severity: 'medium', enabled: true },
  { key: 'no-jailbreak', name: '设备未越狱 / Root', category: '设备完整性', detectKey: 'jailbroken', expect: false, weight: 40, severity: 'critical', enabled: true }
];
const policyFallback: Policy[] = [
  { key: 'rm-jailbreak-deny', name: '越狱设备拒绝接入', condition: { detectKey: 'jailbroken', op: 'fail' }, action: 'deny', graceMin: 0, enabled: true },
  { key: 'rm-av-alert', name: '无安全软件告警提醒', condition: { detectKey: 'edr', op: 'fail' }, action: 'alert', graceMin: 30, enabled: true }
];

const baselines = ref<Baseline[]>(baselineFallback.map((b) => ({ ...b })));
const policies = ref<Policy[]>(policyFallback.map((p) => ({ ...p, condition: { ...p.condition } })));

const tab = ref<'baseline' | 'remediation'>('baseline');
const liveBaseline = ref(false);
const livePolicy = ref(false);
// 页头徽标：两 tab 任一持久化即视为 live。
const live = computed(() => liveBaseline.value || livePolicy.value);

/* —— 加载（两 tab 各自探活；失败保留前端默认 mock 降级） —— */
async function loadBaselines() {
  try {
    const r = await fetch('/ctl/api/coll?kind=compbaseline');
    if (!r.ok) return;
    const docs = await r.json();
    baselines.value = docs.map((d: any) => ({
      key: d.key ?? d.k,
      name: d.name ?? '',
      category: d.category ?? '',
      detectKey: ['edr', 'diskEncrypted', 'osCurrent', 'jailbroken'].includes(d.detectKey) ? d.detectKey : 'edr',
      expect: typeof d.expect === 'boolean' ? d.expect : true,
      weight: typeof d.weight === 'number' ? d.weight : 0,
      severity: ['low', 'medium', 'high', 'critical'].includes(d.severity) ? d.severity : 'medium',
      enabled: typeof d.enabled === 'boolean' ? d.enabled : true
    }));
    liveBaseline.value = true;
  } catch { liveBaseline.value = false; }
}
async function loadPolicies() {
  try {
    const r = await fetch('/ctl/api/coll?kind=remediationpolicy');
    if (!r.ok) return;
    const docs = await r.json();
    policies.value = docs.map((d: any) => ({
      key: d.key ?? d.k,
      name: d.name ?? '',
      condition: {
        detectKey: ['edr', 'diskEncrypted', 'osCurrent', 'jailbroken'].includes(d.condition?.detectKey) ? d.condition.detectKey : 'edr',
        op: 'fail'
      },
      action: ['allow', 'alert', 'restrict', 'deny'].includes(d.action) ? d.action : 'alert',
      graceMin: typeof d.graceMin === 'number' ? d.graceMin : 0,
      enabled: typeof d.enabled === 'boolean' ? d.enabled : true
    }));
    livePolicy.value = true;
  } catch { livePolicy.value = false; }
}
onMounted(() => { loadBaselines(); loadPolicies(); });

/* —— 持久化（POST 单条文档，后端写审计） —— */
async function persistBaseline(b: Baseline) {
  if (!liveBaseline.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=compbaseline', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: b.key, doc: { ...b } })
    });
    return res.ok;
  } catch { return false; }
}
async function persistPolicy(p: Policy) {
  if (!livePolicy.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=remediationpolicy', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: p.key, doc: { ...p, condition: { ...p.condition } } })
    });
    return res.ok;
  } catch { return false; }
}

/* —— 行内启用开关：即时 toggle，写失败回滚 —— */
async function toggleBaseline(b: Baseline) {
  const ok = await persistBaseline(b);
  if (!ok && liveBaseline.value) { b.enabled = !b.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`检测项「${b.name}」已${b.enabled ? '启用' : '停用'}${liveBaseline.value ? ' · 已持久化' : ''}`);
}
async function togglePolicy(p: Policy) {
  const ok = await persistPolicy(p);
  if (!ok && livePolicy.value) { p.enabled = !p.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`处置映射「${p.name}」已${p.enabled ? '启用' : '停用'}${livePolicy.value ? ' · 已持久化' : ''}`);
}

/* —— 新建 / 编辑 —— */
const show = ref(false);
const editing = ref(false);
const bForm = reactive<Baseline>({ key: '', name: '', category: '', detectKey: 'edr', expect: true, weight: 0, severity: 'medium', enabled: true });
const pForm = reactive<Policy>({ key: '', name: '', condition: { detectKey: 'edr', op: 'fail' }, action: 'alert', graceMin: 0, enabled: true });

function resetForms() {
  Object.assign(bForm, { key: '', name: '', category: '', detectKey: 'edr', expect: true, weight: 0, severity: 'medium', enabled: true });
  Object.assign(pForm, { key: '', name: '', action: 'alert', graceMin: 0, enabled: true });
  pForm.condition = { detectKey: 'edr', op: 'fail' };
}
function openCreate() { editing.value = false; resetForms(); show.value = true; }
function openEdit(r: any) {
  editing.value = true;
  if (tab.value === 'baseline') {
    // 克隆，避免引用污染列表行。
    Object.assign(bForm, JSON.parse(JSON.stringify(r)));
  } else {
    const clone: Policy = JSON.parse(JSON.stringify(r));
    Object.assign(pForm, clone);
    pForm.condition = { ...clone.condition, op: 'fail' };
  }
  show.value = true;
}

async function submit() {
  if (tab.value === 'baseline') {
    if (!bForm.key) return Message.warning('请填写检测项标识（key）');
    if (!bForm.name) return Message.warning('请填写检测项名称');
    if (!editing.value && baselines.value.some((x) => x.key === bForm.key)) return Message.warning(`检测项标识「${bForm.key}」已存在`);
    const doc: Baseline = { ...bForm, condition: undefined } as any;
    delete (doc as any).condition;
    if (editing.value) {
      const i = baselines.value.findIndex((x) => x.key === doc.key);
      if (liveBaseline.value && !(await persistBaseline(doc))) return Message.error('保存失败');
      if (i >= 0) baselines.value[i] = doc;
      Message.success(`检测项「${doc.name}」已更新${liveBaseline.value ? ' · 已持久化' : '（mock）'}`);
    } else {
      if (liveBaseline.value && !(await persistBaseline(doc))) return Message.error('创建失败');
      baselines.value.push(doc);
      Message.success(`检测项「${doc.name}」已创建${liveBaseline.value ? ' · 已持久化' : '（mock）'}`);
    }
  } else {
    if (!pForm.key) return Message.warning('请填写映射标识（key）');
    if (!pForm.name) return Message.warning('请填写映射名称');
    if (!editing.value && policies.value.some((x) => x.key === pForm.key)) return Message.warning(`映射标识「${pForm.key}」已存在`);
    const doc: Policy = { key: pForm.key, name: pForm.name, condition: { detectKey: pForm.condition.detectKey, op: 'fail' }, action: pForm.action, graceMin: pForm.graceMin, enabled: pForm.enabled };
    if (editing.value) {
      const i = policies.value.findIndex((x) => x.key === doc.key);
      if (livePolicy.value && !(await persistPolicy(doc))) return Message.error('保存失败');
      if (i >= 0) policies.value[i] = doc;
      Message.success(`处置映射「${doc.name}」已更新${livePolicy.value ? ' · 已持久化' : '（mock）'}`);
    } else {
      if (livePolicy.value && !(await persistPolicy(doc))) return Message.error('创建失败');
      policies.value.push(doc);
      Message.success(`处置映射「${doc.name}」已创建${livePolicy.value ? ' · 已持久化' : '（mock）'}`);
    }
  }
  show.value = false;
}

/* —— 删除（二次确认 + DELETE） —— */
function del(r: any) {
  const isBaseline = tab.value === 'baseline';
  const noun = isBaseline ? '检测项' : '处置映射';
  Modal.warning({
    title: `删除${noun}「${r.name}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: isBaseline
      ? '删除后该检测项不再参与合规判定（不扣分、不告警）。此操作进入审计链。'
      : '删除后该处置映射失效，对应检测项不达标将不再触发处置动作（仍按基线扣分）。此操作进入审计链。',
    onOk: async () => {
      const kind = isBaseline ? 'compbaseline' : 'remediationpolicy';
      const isLive = isBaseline ? liveBaseline.value : livePolicy.value;
      if (isLive) {
        try {
          const res = await fetch(`/ctl/api/coll?kind=${kind}&key=${encodeURIComponent(r.key)}`, { method: 'DELETE' });
          if (!res.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      if (isBaseline) baselines.value = baselines.value.filter((x) => x.key !== r.key);
      else policies.value = policies.value.filter((x) => x.key !== r.key);
      Message.success(`${noun}「${r.name}」已删除${isLive ? ' · 已持久化' : ''}`);
    }
  });
}
</script>

<style scoped>
:deep(.arco-table-tr) { cursor: default; }

/* 顶部说明条 */
.cp-tip { display: flex; align-items: flex-start; gap: 10px; background: var(--accent-soft); border: 1px solid var(--line); border-radius: var(--r-md); padding: 11px 14px; margin-bottom: 16px; font-size: 12.5px; color: var(--ink-2); line-height: 1.6; }
.cp-tip__ic { color: var(--accent-2); font-weight: 700; flex-shrink: 0; }
.cp-tip b { color: var(--accent-2); font-weight: 700; }

/* 空态 */
.cp-empty { padding: 30px 16px; text-align: center; }
.cp-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.cp-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 560px; margin-left: auto; margin-right: auto; }

/* 处置映射条件行 */
.cp-cond { display: flex; align-items: center; gap: 10px; width: 100%; }

.cp-hint { font-size: 11px; color: var(--ink-3); margin-top: 6px; line-height: 1.5; }
.cp-modal-note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin-top: 4px; }
</style>
