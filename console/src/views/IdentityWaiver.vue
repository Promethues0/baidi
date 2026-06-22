<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">认证豁免<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">在授信终端 / 网络 / 域条件下放宽二次认证 · 无规则 = 无豁免 = 最严（默认安全）</div>
      </div>
      <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>新建规则</a-button>
    </div>

    <!-- 安全提示：豁免只会放宽，删除即恢复严格 -->
    <div class="wv-tip">
      <span class="wv-tip__ic">⚠</span>
      <span>认证豁免规则<b>只会放宽</b>命中会话的二次认证要求，不会收紧任何策略。删除规则即<b>恢复严格</b>（按认证策略最严执行）。条件按「与」组合，全部满足才放宽。</span>
    </div>

    <div class="zl-card">
      <a-table :data="rules" :pagination="false" :bordered="false" row-key="key">
        <template #columns>
          <a-table-column title="规则名称" data-index="name" :width="220">
            <template #cell="{ record }">
              <span style="font-weight:600;color:var(--ink)">{{ record.name }}</span>
              <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
            </template>
          </a-table-column>
          <a-table-column title="豁免类型" align="center" :width="150">
            <template #cell="{ record }">
              <span class="zl-badge zl-badge--accent">{{ typeLabel(record.type) }}</span>
            </template>
          </a-table-column>
          <a-table-column title="生效条件（全部满足）">
            <template #cell="{ record }">
              <span style="font-size:12px;color:var(--ink-2)">{{ condSummary(record) }}</span>
            </template>
          </a-table-column>
          <a-table-column title="启用" align="center" :width="86">
            <template #cell="{ record }">
              <a-switch v-model="record.enabled" size="small" @change="toggle(record)" />
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
        <!-- 空态：未配置豁免规则 = 所有会话按认证策略最严执行 -->
        <template #empty>
          <div class="wv-empty">
            <div class="wv-empty__big">未配置豁免规则 · 所有会话按认证策略最严执行</div>
            <div class="wv-empty__sub">默认安全：没有任何豁免即意味着每个会话都按最严的认证策略走二次认证。需要在授信条件下放宽时再新建规则。</div>
          </div>
        </template>
      </a-table>
    </div>

    <!-- 新建 / 编辑规则 -->
    <a-modal v-model:visible="show" :title="editing ? '编辑豁免规则' : '新建豁免规则'" width="560px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="form" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="规则标识（key）" required>
              <a-input v-model="form.key" placeholder="例如：wv-office" :disabled="editing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="规则名称" required>
              <a-input v-model="form.name" placeholder="例如：总部办公网免二次认证" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="豁免类型">
          <a-select v-model="form.type">
            <a-option value="skipMfa">免二次认证（skipMfa）</a-option>
            <a-option value="quickLogin">凭票快速上线（quickLogin）</a-option>
          </a-select>
        </a-form-item>

        <a-form-item label="生效条件（按「与」组合，开启的条件全部满足才放宽）">
          <div class="wv-conds">
            <div class="wv-cond">
              <div class="wv-cond__main">
                <b>授信终端</b>
                <span>设备已注册且姿态合规（trustedDevice）</span>
              </div>
              <a-switch v-model="form.conditions.trustedDevice" size="small" />
            </div>
            <div class="wv-cond">
              <div class="wv-cond__main">
                <b>命中网络</b>
                <span>来源命中下方授信地址对象（trustedNetwork）</span>
              </div>
              <a-switch v-model="form.conditions.trustedNetwork" size="small" />
            </div>
            <div class="wv-cond">
              <div class="wv-cond__main">
                <b>域内主机</b>
                <span>已加入 Windows 域（windowsDomain）</span>
              </div>
              <a-switch v-model="form.conditions.windowsDomain" size="small" />
            </div>
          </div>
        </a-form-item>

        <!-- 命中网络开启时：选择授信地址对象（来自对象库 cat=addr） -->
        <a-form-item v-if="form.conditions.trustedNetwork" label="授信网络（引用地址对象）">
          <a-select v-model="form.networkRef" multiple allow-search placeholder="选择地址对象，命中其一即满足" :style="{width:'100%'}">
            <a-option v-for="o in addrOpts" :key="o" :value="o">{{ o }}</a-option>
          </a-select>
          <div class="wv-hint">引用对象库「地址」分类对象（cat=addr），对象变更自动传播；未选则该条件不约束。</div>
        </a-form-item>

        <!-- 域内主机开启时：填写域名 -->
        <a-form-item v-if="form.conditions.windowsDomain" label="域名（domainName）">
          <a-input v-model="form.domainName" placeholder="例如：corp.com" />
        </a-form-item>

        <!-- 凭票快速上线类型：凭票有效期 -->
        <a-form-item v-if="form.type === 'quickLogin'" label="凭票有效期">
          <a-input-number v-model="form.ticketValidityDays" :min="0" :style="{width:'200px'}">
            <template #suffix>天</template>
          </a-input-number>
          <div class="wv-hint">在有效期内复用上次认证凭票免重新登录；0 = 不限制（不设过期，仅在凭票存续期内有效）。</div>
        </a-form-item>

        <a-form-item label="启用本规则">
          <a-switch v-model="form.enabled" />
          <span class="wv-hint" style="margin-left:10px">关闭 = 不启用 = 不放宽（不影响最严策略）。</span>
        </a-form-item>
      </a-form>
      <div class="wv-modal-note">提示：豁免只放宽不收紧，命中即跳过对应二次认证；规则删除或停用后立即恢复严格执行。改动 ≤60s 下发在线端点 · 写审计。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

// 一条豁免规则文档（kind=waiver，每条一文档，key 为文档键）。
interface Waiver {
  key: string;
  name: string;
  type: 'skipMfa' | 'quickLogin';
  conditions: { trustedDevice: boolean; trustedNetwork: boolean; windowsDomain: boolean };
  networkRef: string[];
  domainName: string;
  ticketValidityDays: number;
  enabled: boolean;
}

// 前端默认带 1 条示例（wv-office），加载后端后整体覆盖。
const fallback: Waiver[] = [
  {
    key: 'wv-office', name: '总部办公网免二次认证', type: 'skipMfa',
    conditions: { trustedDevice: true, trustedNetwork: true, windowsDomain: false },
    networkRef: ['addr/总部办公网'], domainName: '', ticketValidityDays: 0, enabled: true
  }
];

const rules = ref<Waiver[]>(fallback.map((r) => ({ ...r, conditions: { ...r.conditions }, networkRef: [...r.networkRef] })));
const live = ref(false);

// 授信网络候选项：从对象库 cat=addr 的对象取其 key（如 "addr/总部办公网"）；加载失败给静态兜底。
const addrOpts = ref<string[]>(['addr/总部办公网']);

function typeLabel(t: string) {
  return t === 'quickLogin' ? '凭票快速上线' : '免二次认证';
}
// 条件摘要（列表「生效条件」列）。
function condSummary(r: Waiver) {
  const parts: string[] = [];
  if (r.conditions.trustedDevice) parts.push('授信终端');
  if (r.conditions.trustedNetwork) parts.push(r.networkRef.length ? `命中网络（${r.networkRef.join('、')}）` : '命中网络（未选对象=不约束）');
  if (r.conditions.windowsDomain) parts.push(r.domainName ? `域内主机（${r.domainName}）` : '域内主机');
  let s = parts.length ? parts.join(' 且 ') : '无条件（任意会话即放宽，谨慎）';
  if (r.type === 'quickLogin') s += r.ticketValidityDays > 0 ? ` · 凭票 ${r.ticketValidityDays} 天` : ' · 凭票不限期';
  return s;
}

// 豁免规则来自控制面 /ctl/api/coll?kind=waiver（持久化，每条一文档），不可达时降级 mock。
async function loadRules() {
  try {
    const r = await fetch('/ctl/api/coll?kind=waiver');
    if (!r.ok) return;
    const docs = await r.json();
    rules.value = docs.map((d: any) => ({
      key: d.key ?? d.k,
      name: d.name ?? '',
      type: d.type === 'quickLogin' ? 'quickLogin' : 'skipMfa',
      conditions: {
        trustedDevice: !!d.conditions?.trustedDevice,
        trustedNetwork: !!d.conditions?.trustedNetwork,
        windowsDomain: !!d.conditions?.windowsDomain
      },
      networkRef: Array.isArray(d.networkRef) ? d.networkRef : [],
      domainName: d.domainName ?? '',
      ticketValidityDays: typeof d.ticketValidityDays === 'number' ? d.ticketValidityDays : 0,
      enabled: typeof d.enabled === 'boolean' ? d.enabled : true
    }));
    live.value = true;
  } catch { live.value = false; }
}

// 授信地址对象：取对象库 kind=lib 中 cat==='addr' 的对象 key。
async function loadAddrOpts() {
  try {
    const r = await fetch('/ctl/api/coll?kind=lib');
    if (!r.ok) return;
    const docs = await r.json();
    const opts = docs.filter((d: any) => d.cat === 'addr').map((d: any) => d.key ?? ('addr/' + d.name));
    if (opts.length) addrOpts.value = opts;
  } catch { /* 保留静态兜底 */ }
}

onMounted(() => { loadRules(); loadAddrOpts(); });

// 写入单条文档（POST，后端自动写审计）。
async function persist(r: Waiver) {
  if (!live.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=waiver', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: r.key, doc: { ...r } })
    });
    return res.ok;
  } catch { return false; }
}

/* —— 新建 / 编辑 —— */
const show = ref(false);
const editing = ref(false);
const form = reactive<Waiver>({
  key: '', name: '', type: 'skipMfa',
  conditions: { trustedDevice: false, trustedNetwork: false, windowsDomain: false },
  networkRef: [], domainName: '', ticketValidityDays: 0, enabled: true
});

function resetForm() {
  Object.assign(form, {
    key: '', name: '', type: 'skipMfa',
    domainName: '', ticketValidityDays: 0, enabled: true
  });
  form.conditions = { trustedDevice: false, trustedNetwork: false, windowsDomain: false };
  form.networkRef = [];
}
function openCreate() { editing.value = false; resetForm(); show.value = true; }
function openEdit(r: Waiver) {
  editing.value = true;
  Object.assign(form, {
    key: r.key, name: r.name, type: r.type,
    domainName: r.domainName, ticketValidityDays: r.ticketValidityDays, enabled: r.enabled
  });
  form.conditions = { ...r.conditions };
  form.networkRef = [...r.networkRef];
  show.value = true;
}

async function submit() {
  if (!form.key) return Message.warning('请填写规则标识（key）');
  if (!form.name) return Message.warning('请填写规则名称');
  if (!editing.value && rules.value.some((x) => x.key === form.key)) return Message.warning(`规则标识「${form.key}」已存在`);

  const doc: Waiver = {
    key: form.key, name: form.name, type: form.type,
    conditions: { ...form.conditions },
    networkRef: form.conditions.trustedNetwork ? [...form.networkRef] : [],
    domainName: form.conditions.windowsDomain ? form.domainName : '',
    ticketValidityDays: form.type === 'quickLogin' ? form.ticketValidityDays : 0,
    enabled: form.enabled
  };

  if (editing.value) {
    const i = rules.value.findIndex((x) => x.key === doc.key);
    if (live.value && !(await persist(doc))) return Message.error('保存失败');
    if (i >= 0) rules.value[i] = doc;
    Message.success(`豁免规则「${doc.name}」已更新${live.value ? ' · 已持久化' : '（mock）'}`);
  } else {
    if (live.value && !(await persist(doc))) return Message.error('创建失败');
    rules.value.push(doc);
    Message.success(`豁免规则「${doc.name}」已创建${live.value ? ' · 已持久化' : '（mock）'}`);
  }
  show.value = false;
}

async function toggle(r: Waiver) {
  const ok = await persist(r);
  if (!ok && live.value) { r.enabled = !r.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`「${r.name}」已${r.enabled ? '启用（放宽生效）' : '停用（恢复严格）'}${live.value ? ' · 已持久化' : ''}`);
}

function del(r: Waiver) {
  Modal.warning({
    title: `删除豁免规则「${r.name}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: '删除后命中该规则的会话立即恢复严格执行（按认证策略最严走二次认证）。此操作进入审计链。',
    onOk: async () => {
      if (live.value) {
        try {
          const res = await fetch(`/ctl/api/coll?kind=waiver&key=${encodeURIComponent(r.key)}`, { method: 'DELETE' });
          if (!res.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      rules.value = rules.value.filter((x) => x.key !== r.key);
      Message.success(`豁免规则「${r.name}」已删除 · 已恢复严格`);
    }
  });
}
</script>

<style scoped>
:deep(.arco-table-tr) { cursor: default; }

/* 顶部安全提示条 */
.wv-tip { display: flex; align-items: flex-start; gap: 10px; background: var(--accent-soft); border: 1px solid var(--line); border-radius: var(--r-md); padding: 11px 14px; margin-bottom: 16px; font-size: 12.5px; color: var(--ink-2); line-height: 1.6; }
.wv-tip__ic { color: var(--accent-2); font-weight: 700; flex-shrink: 0; }
.wv-tip b { color: var(--accent-2); font-weight: 700; }

/* 空态 */
.wv-empty { padding: 30px 16px; text-align: center; }
.wv-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.wv-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 560px; margin-left: auto; margin-right: auto; }

/* 弹窗内条件组 */
.wv-conds { display: flex; flex-direction: column; width: 100%; border: 1px solid var(--line); border-radius: var(--r-md); overflow: hidden; }
.wv-cond { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px; }
.wv-cond + .wv-cond { border-top: 1px solid var(--line); }
.wv-cond__main b { display: block; font-size: 13px; color: var(--ink); font-weight: 600; }
.wv-cond__main span { display: block; font-size: 11px; color: var(--ink-3); margin-top: 1px; }

.wv-hint { font-size: 11px; color: var(--ink-3); margin-top: 6px; line-height: 1.5; }
.wv-modal-note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin-top: 4px; }
</style>
