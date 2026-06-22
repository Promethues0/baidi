<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">认证策略<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">登录认证门：按范围匹配主认证 / 二次认证（MFA）与自适应触发，产出本次会话的 auth_strength · 访问授权见〈统一策略〉</div>
      </div>
      <a-button type="primary" @click="openNew">新建策略</a-button>
    </div>

    <!-- 与统一策略的契约：本页签发 auth_strength，统一策略 auth:mfa 条件消费（生产者/消费者，非重复） -->
    <div style="display:flex;align-items:center;gap:12px;justify-content:space-between;background:var(--surface-2);border:1px solid var(--line);border-radius:var(--r-md);padding:10px 14px;margin-bottom:16px;font-size:12px;color:var(--ink-2);line-height:1.6">
      <span>本策略在<b>登录门</b>签发 <code class="data">auth_strength</code>；统一策略的 <code class="data">auth: mfa</code> 条件在<b>访问门</b>消费它——是生产者 / 消费者，不是重复配置。当前 <b>{{ mfaPolicyCount }}</b> 条统一策略引用该强度。</span>
      <router-link to="/policy" style="flex:none;color:var(--accent-2);text-decoration:none;font-weight:600">查看统一策略 →</router-link>
    </div>

    <!-- 策略列表 -->
    <div class="zl-card">
      <a-table
        v-if="policies.length"
        :data="policies"
        :pagination="false"
        :bordered="false"
        row-key="key"
        @row-click="(r:any)=>openEdit(r)">
        <template #columns>
          <a-table-column title="策略名" data-index="name">
            <template #cell="{ record }">
              <div class="pol-name">{{ record.name || record.key }}</div>
              <div class="pol-key data">{{ record.key }}</div>
            </template>
          </a-table-column>
          <a-table-column title="范围">
            <template #cell="{ record }">
              <span class="zl-badge zl-badge--accent" v-if="record.scope.kind === 'all'">全部主体</span>
              <span v-else>
                <span class="pol-scope-kind">{{ scopeKindLabel(record.scope.kind) }}</span>
                <span class="data pol-scope-val">{{ record.scope.value || '—' }}</span>
              </span>
            </template>
          </a-table-column>
          <a-table-column title="主认证 / MFA">
            <template #cell="{ record }">
              <span class="data pol-factors">{{ factorSummary(record) }}</span>
            </template>
          </a-table-column>
          <a-table-column title="强制 MFA" align="center" :width="110">
            <template #cell="{ record }">
              <span v-if="record.mfaRequired" class="zl-badge zl-badge--warn">强制</span>
              <span v-else-if="anyTrigger(record)" class="zl-badge zl-badge--idle">自适应</span>
              <span v-else class="zl-badge zl-badge--idle">不强制</span>
            </template>
          </a-table-column>
          <a-table-column title="启用" align="center" :width="90">
            <template #cell="{ record }">
              <a-switch v-model="record.enabled" size="small" :disabled="record.builtin" @click.stop @change="toggle(record)" />
            </template>
          </a-table-column>
          <a-table-column title="操作" align="center" :width="120">
            <template #cell="{ record }">
              <a-space>
                <a-button type="text" size="mini" @click.stop="openEdit(record)">编辑</a-button>
                <a-button v-if="!record.builtin" type="text" size="mini" status="danger" @click.stop="remove(record)">删除</a-button>
                <span v-else class="zl-badge zl-badge--warn" style="font-size:10.5px">内置门禁</span>
              </a-space>
            </template>
          </a-table-column>
        </template>
      </a-table>

      <!-- 空态 -->
      <div v-else class="pol-empty zl-card__pad">
        <div class="pol-empty__title">尚无认证策略</div>
        <div class="pol-empty__sub">新建策略可按用户组 / 组织 / 用户范围匹配主认证、二次认证与自适应触发。</div>
        <a-button type="primary" @click="openNew">新建策略</a-button>
      </div>
    </div>

    <!-- 编辑 / 新建 弹窗 -->
    <a-modal
      v-model:visible="modalOpen"
      :title="editing ? '编辑策略' : '新建策略'"
      :width="720"
      :ok-loading="saving"
      ok-text="保存"
      cancel-text="取消"
      @ok="save"
      @cancel="modalOpen = false">
      <a-form v-if="form" :model="form" layout="vertical" auto-label-width>
        <a-grid :cols="2" :col-gap="20">
          <a-grid-item>
            <a-form-item label="策略 ID（key）" field="key">
              <a-input v-model="form.key" :disabled="editing" placeholder="如 ap-finance" />
              <template #extra><span class="pol-extra">编辑时不可修改；新建必填，作为唯一标识</span></template>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="策略名" field="name">
              <a-input v-model="form.name" placeholder="如 财务中心强制 MFA" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="匹配范围">
          <a-space style="width:100%">
            <a-select v-model="form.scope.kind" style="width:160px">
              <a-option value="all">全部主体</a-option>
              <a-option value="group">用户组</a-option>
              <a-option value="org">组织</a-option>
              <a-option value="user">用户</a-option>
            </a-select>
            <a-input
              v-if="form.scope.kind !== 'all'"
              v-model="form.scope.value"
              style="width:340px"
              :placeholder="scopePlaceholder(form.scope.kind)" />
          </a-space>
        </a-form-item>

        <a-grid :cols="2" :col-gap="20">
          <a-grid-item>
            <a-form-item label="一级认证（主认证）">
              <a-checkbox-group v-model="form.primary">
                <a-checkbox v-for="o in primaryOpts" :key="o.value" :value="o.value">{{ o.label }}</a-checkbox>
              </a-checkbox-group>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="二级认证（MFA）">
              <a-checkbox-group v-model="form.secondary">
                <a-checkbox v-for="o in secondaryOpts" :key="o.value" :value="o.value">{{ o.label }}</a-checkbox>
              </a-checkbox-group>
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-grid :cols="3" :col-gap="20">
          <a-grid-item>
            <a-form-item label="强制 MFA">
              <a-switch v-model="form.mfaRequired" />
              <template #extra><span class="pol-extra">关 + 触发位全关 = 不强制（旧行为）</span></template>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="记住 MFA 设备">
              <a-input-number v-model="form.rememberDeviceDays" :min="0" :style="{ width: '160px' }">
                <template #suffix>天</template>
              </a-input-number>
              <template #extra><span class="pol-extra">0 = 每次都要</span></template>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="首次绑定宽限">
              <a-input-number v-model="form.bindGracePeriodDays" :min="0" :style="{ width: '160px' }">
                <template #suffix>天</template>
              </a-input-number>
              <template #extra><span class="pol-extra">0 = 立即强制</span></template>
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="自适应触发">
          <div class="pol-trig">
            <div class="pol-trig__item">
              <a-switch v-model="form.adaptiveTriggers.weakPassword" size="small" />
              <div><b>弱口令</b><span>命中弱口令库</span></div>
            </div>
            <div class="pol-trig__item">
              <a-switch v-model="form.adaptiveTriggers.abnormalTime" size="small" />
              <div><b>异常时段</b><span>非常用登录时段</span></div>
            </div>
            <div class="pol-trig__item">
              <a-switch v-model="form.adaptiveTriggers.geoAnomaly" size="small" />
              <div><b>异地登录</b><span>偏离常用地点</span></div>
            </div>
            <div class="pol-trig__item">
              <a-switch v-model="form.adaptiveTriggers.newDevice" size="small" />
              <div><b>新设备</b><span>首次出现的设备</span></div>
            </div>
          </div>
        </a-form-item>

        <a-grid :cols="2" :col-gap="20">
          <a-grid-item>
            <a-form-item label="触发后处置">
              <a-select v-model="form.enforceOnTrigger" style="width:220px">
                <a-option value="stepup">二次鉴权（step-up）</a-option>
                <a-option value="deny">拒绝登录</a-option>
                <a-option value="warn">告警放行</a-option>
              </a-select>
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="启用策略">
              <a-switch v-model="form.enabled" />
            </a-form-item>
          </a-grid-item>
        </a-grid>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { policyStore } from '@/policy-store';

type ScopeKind = 'all' | 'group' | 'org' | 'user';
type EnforceMode = 'stepup' | 'deny' | 'warn';
type Triggers = { weakPassword: boolean; abnormalTime: boolean; geoAnomaly: boolean; newDevice: boolean };
type Policy = {
  key: string;
  name: string;
  scope: { kind: ScopeKind; value: string };
  primary: string[];
  secondary: string[];
  mfaRequired: boolean;
  rememberDeviceDays: number;
  bindGracePeriodDays: number;
  adaptiveTriggers: Triggers;
  enforceOnTrigger: EnforceMode;
  enabled: boolean;
  builtin?: boolean; // 内置安全门禁（REQ-SEC-007），不可删除/停用
};

// 一级 / 二级认证可选项（与「认证方式与 MFA」页术语一致）。
const primaryOpts = [
  { label: '密码', value: 'pwd' },
  { label: '证书', value: 'cert' },
  { label: '联邦（OIDC）', value: 'oidc' },
  { label: '短信', value: 'sms' },
  { label: '域账号', value: 'ldap' }
];
const secondaryOpts = [
  { label: 'TOTP', value: 'totp' },
  { label: '短信', value: 'sms' },
  { label: '证书', value: 'cert' },
  { label: 'WebAuthn', value: 'webauthn' }
];

// 前端默认示例（加载后端后覆盖）。
const defaults: Policy[] = [
  {
    key: 'ap-admin-mfa', name: '管理员强制 MFA · 安全门禁(REQ-SEC-007)',
    scope: { kind: 'group', value: '管理员' },
    primary: ['pwd'], secondary: ['totp', 'webauthn'],
    mfaRequired: true, rememberDeviceDays: 0, bindGracePeriodDays: 0,
    adaptiveTriggers: { weakPassword: true, abnormalTime: true, geoAnomaly: true, newDevice: true },
    enforceOnTrigger: 'deny', enabled: true, builtin: true
  },
  {
    key: 'ap-default', name: '全部主体 · 默认',
    scope: { kind: 'all', value: '' },
    primary: ['pwd'], secondary: ['totp'],
    mfaRequired: false, rememberDeviceDays: 30, bindGracePeriodDays: 7,
    adaptiveTriggers: { weakPassword: true, abnormalTime: false, geoAnomaly: true, newDevice: true },
    enforceOnTrigger: 'stepup', enabled: true
  },
  {
    key: 'ap-finance', name: '财务中心 · 强制 MFA',
    scope: { kind: 'org', value: '/acme/财务中心' },
    primary: ['pwd', 'cert'], secondary: ['totp', 'webauthn'],
    mfaRequired: true, rememberDeviceDays: 0, bindGracePeriodDays: 0,
    adaptiveTriggers: { weakPassword: true, abnormalTime: true, geoAnomaly: true, newDevice: true },
    enforceOnTrigger: 'deny', enabled: true
  }
];

const policies = ref<Policy[]>(defaults.map((p) => clone(p)));
const live = ref(false);

// 反向引用：有多少条统一策略把本中心签发的 auth_strength 当作 auth:mfa 访问条件消费
const mfaPolicyCount = computed(() => policyStore.filter((p) => p.cond.mfa).length);

const modalOpen = ref(false);
const editing = ref(false);
const saving = ref(false);
const form = ref<Policy | null>(null);

function clone<T>(o: T): T { return JSON.parse(JSON.stringify(o)); }

function emptyPolicy(): Policy {
  return {
    key: '', name: '',
    scope: { kind: 'all', value: '' },
    primary: ['pwd'], secondary: [],
    mfaRequired: false, rememberDeviceDays: 30, bindGracePeriodDays: 7,
    adaptiveTriggers: { weakPassword: false, abnormalTime: false, geoAnomaly: false, newDevice: false },
    enforceOnTrigger: 'stepup', enabled: true
  };
}

// 展示辅助。
const scopeKindLabel = (k: ScopeKind) =>
  ({ all: '全部', group: '用户组', org: '组织', user: '用户' }[k] ?? k);
const scopePlaceholder = (k: ScopeKind) =>
  (({ group: '如 财务组', org: '如 /acme/财务中心', user: '如 alice@acme.com' } as Record<string, string>)[k] ?? '');
const anyTrigger = (p: Policy) => Object.values(p.adaptiveTriggers).some(Boolean);
function factorSummary(p: Policy) {
  const pri = p.primary.map(labelOf(primaryOpts)).join('+') || '—';
  const sec = p.secondary.map(labelOf(secondaryOpts)).join('+') || '无';
  return `${pri} / ${sec}`;
}
const labelOf = (opts: { label: string; value: string }[]) => (v: string) =>
  opts.find((o) => o.value === v)?.label ?? v;

// 策略来自控制面 /ctl/api/coll?kind=authpolicy（持久化）；成功覆盖前端默认，失败保留默认（mock 降级）。
async function load() {
  try {
    const r = await fetch('/ctl/api/coll?kind=authpolicy');
    if (!r.ok) return;
    const docs = await r.json();
    if (Array.isArray(docs) && docs.length) {
      policies.value = docs.map((d: any) => normalize(d));
      // 后端集中无内置门禁时补种子，保证 REQ-SEC-007 管理员强制 MFA 门禁在 live 态不丢失
      if (!policies.value.some((p) => p.builtin)) {
        const gate = defaults.find((p) => p.builtin);
        if (gate) policies.value.unshift(clone(gate));
      }
    }
    live.value = true;
  } catch { live.value = false; }
}
onMounted(load);

// 后端 doc 容错归一（缺字段补默认，向后兼容）。
function normalize(d: any): Policy {
  const base = emptyPolicy();
  return {
    key: d.key ?? d.k ?? '',
    name: d.name ?? '',
    scope: { kind: d.scope?.kind ?? 'all', value: d.scope?.value ?? '' },
    primary: Array.isArray(d.primary) ? d.primary : base.primary,
    secondary: Array.isArray(d.secondary) ? d.secondary : [],
    mfaRequired: d.mfaRequired === true,
    rememberDeviceDays: Number.isFinite(d.rememberDeviceDays) ? d.rememberDeviceDays : base.rememberDeviceDays,
    bindGracePeriodDays: Number.isFinite(d.bindGracePeriodDays) ? d.bindGracePeriodDays : base.bindGracePeriodDays,
    adaptiveTriggers: { ...base.adaptiveTriggers, ...(d.adaptiveTriggers ?? {}) },
    enforceOnTrigger: d.enforceOnTrigger ?? 'stepup',
    enabled: d.enabled !== false,
    builtin: d.builtin === true
  };
}

function openNew() {
  form.value = emptyPolicy();
  editing.value = false;
  modalOpen.value = true;
}
function openEdit(record: Policy) {
  form.value = clone(record);
  editing.value = true;
  modalOpen.value = true;
}

// 保存单条 doc：POST /ctl/api/coll?kind=authpolicy（后端自动写审计）。
async function save() {
  const f = form.value;
  if (!f) return;
  if (!f.key.trim()) { Message.error('策略 ID（key）必填'); return false; }
  if (f.scope.kind !== 'all' && !f.scope.value.trim()) { Message.error('该范围需填写匹配值'); return false; }

  saving.value = true;
  const ok = await persist(f);
  saving.value = false;
  if (!ok && live.value) { Message.error('保存失败'); return false; }

  // 本地表上替换或追加。
  const idx = policies.value.findIndex((p) => p.key === f.key);
  if (idx >= 0) policies.value[idx] = clone(f);
  else policies.value.push(clone(f));

  Message.success(`策略「${f.name || f.key}」已保存${live.value ? ' · 已持久化' : '（mock）'}`);
  modalOpen.value = false;
  return true;
}

async function persist(p: Policy) {
  if (!live.value) return true;
  try {
    const r = await fetch('/ctl/api/coll?kind=authpolicy', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: p.key, doc: p })
    });
    return r.ok;
  } catch { return false; }
}

// 行内启用开关：写后反馈，失败回滚。
async function toggle(p: Policy) {
  const ok = await persist(p);
  if (!ok && live.value) { p.enabled = !p.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`策略「${p.name || p.key}」已${p.enabled ? '启用' : '停用'}${live.value ? ' · 已持久化' : ''}`);
}

// 删除：DELETE /ctl/api/coll?kind=authpolicy&key=<key>。
function remove(p: Policy) {
  if (p.builtin) { Message.warning('内置安全门禁（REQ-SEC-007 管理员强制 MFA）不可删除'); return; }
  Modal.warning({
    title: '删除策略',
    content: `确认删除策略「${p.name || p.key}」？该操作会写入审计。`,
    okText: '删除', cancelText: '取消', hideCancel: false,
    onOk: async () => {
      if (live.value) {
        try {
          const r = await fetch(`/ctl/api/coll?kind=authpolicy&key=${encodeURIComponent(p.key)}`, { method: 'DELETE' });
          if (!r.ok) return Message.error('删除失败');
        } catch { return Message.error('删除失败'); }
      }
      policies.value = policies.value.filter((x) => x.key !== p.key);
      Message.success(`策略「${p.name || p.key}」已删除${live.value ? ' · 已持久化' : '（mock）'}`);
    }
  });
}
</script>

<style scoped>
/* 列表内文本 */
.pol-name { font-size: 13px; font-weight: 600; color: var(--ink); line-height: 1.2; }
.pol-key { font-size: 10.5px; color: var(--ink-3); margin-top: 2px; }
.pol-scope-kind { font-size: 11.5px; color: var(--ink-2); margin-right: 6px; }
.pol-scope-val { font-size: 12px; color: var(--ink); }
.pol-factors { font-size: 12px; color: var(--ink-2); }

/* 空态 */
.pol-empty { text-align: center; padding: 48px 24px; }
.pol-empty__title { font-size: 15px; font-weight: 700; color: var(--ink); }
.pol-empty__sub { font-size: 12.5px; color: var(--ink-3); margin: 8px 0 18px; line-height: 1.6; }

/* 弹窗内 extra 提示 */
.pol-extra { font-size: 10.5px; color: var(--ink-3); }

/* 自适应触发 4 列 */
.pol-trig { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px 24px; width: 100%; }
.pol-trig__item { display: flex; align-items: center; gap: 10px; }
.pol-trig__item b { display: block; font-size: 13px; color: var(--ink); font-weight: 650; }
.pol-trig__item span { display: block; font-size: 11px; color: var(--ink-3); margin-top: 1px; }
</style>
