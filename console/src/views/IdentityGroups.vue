<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">用户组（动态组）<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">动态组是 ABAC 的载体 · CEL 表达式与策略条件共用一套引擎（ZL-FR-106）</div>
      </div>
      <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>新建用户组</a-button>
    </div>

    <div class="zl-grid" style="grid-template-columns: 1.4fr 1fr;">
      <div class="zl-card">
        <a-table :data="groups" :pagination="false" :bordered="false" row-key="name"
                 :row-class="(r:any)=> r.name===sel?.name ? 'row-on':''" @row-click="(r:any)=>sel=r">
          <template #columns>
            <a-table-column title="用户组" data-index="name">
              <template #cell="{ record }"><span style="font-weight:600;color:var(--ink)">{{ record.name }}</span></template>
            </a-table-column>
            <a-table-column title="类型" align="center" :width="86">
              <template #cell="{ record }">
                <span class="zl-badge" :class="record.type==='dynamic'?'zl-badge--accent':'zl-badge--idle'">{{ record.type==='dynamic'?'动态':'静态' }}</span>
              </template>
            </a-table-column>
            <a-table-column title="成员" align="right" :width="80">
              <template #cell="{ record }"><span class="data">{{ record.members }}</span></template>
            </a-table-column>
            <a-table-column title="被策略引用" align="right" :width="100">
              <template #cell="{ record }"><span class="data">{{ record.refs }}</span></template>
            </a-table-column>
          </template>
        </a-table>
      </div>

      <div class="zl-card zl-card__pad" v-if="sel">
        <div class="grp-head">
          <div class="zl-card__title" style="margin:0">{{ sel.name }}
            <span class="zl-badge" :class="sel.type==='dynamic'?'zl-badge--accent':'zl-badge--idle'" style="font-size:10.5px;margin-left:8px">{{ sel.type==='dynamic'?'动态组':'静态组' }}</span>
          </div>
          <a-space>
            <a-button size="mini" @click="openEdit">编辑</a-button>
            <a-button size="mini" status="danger" type="outline" @click="del">删除</a-button>
          </a-space>
        </div>

        <template v-if="sel.type === 'dynamic'">
          <div class="grp-label">CEL 表达式（成员实时求值）</div>
          <pre class="grp-cel data">{{ sel.rule }}</pre>
          <div class="grp-label">求值说明</div>
          <div class="grp-note">{{ sel.note }}</div>
          <div class="grp-label">成员抽样（{{ sel.members }} 人）</div>
          <div class="grp-sample">
            <a-tag v-for="m in sel.sample" :key="m" size="small" style="margin:0 6px 6px 0">{{ m }}</a-tag>
            <span v-if="!sel.sample.length" class="grp-dim">求值中…</span>
          </div>
        </template>

        <template v-else>
          <div class="grp-label">静态成员（手工维护 · {{ (sel.static||[]).length }} 人）</div>
          <div class="grp-static">
            <a-tag v-for="m in (sel.static||[])" :key="m" size="small" closable @close="removeMember(m)" style="margin:0 6px 6px 0">{{ m }}</a-tag>
            <span v-if="!(sel.static||[]).length" class="grp-dim">暂无成员</span>
          </div>
          <div class="grp-addrow">
            <a-select v-model="addPick" placeholder="选择用户加入" size="small" allow-search style="flex:1" :options="userOpts" />
            <a-button size="small" type="outline" :disabled="!addPick" @click="addMember">加入</a-button>
          </div>
          <div class="grp-note" style="margin-top:8px">{{ sel.note }}</div>
        </template>

        <div class="grp-label">被以下策略引用</div>
        <div class="grp-refs">
          <router-link v-for="p in sel.refPolicies" :key="p" to="/policy" class="grp-ref data">{{ p }}</router-link>
          <span v-if="!sel.refPolicies.length" class="grp-dim">暂无引用 · 可在策略中心新建条件引用本组</span>
        </div>
      </div>
    </div>

    <a-modal v-model:visible="show" :title="editing ? '编辑用户组' : '新建用户组'" width="520px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="form" layout="vertical">
        <a-form-item label="组名" required><a-input v-model="form.name" placeholder="例如：高敏资源-可访问" :disabled="editing" /></a-form-item>
        <a-form-item label="类型">
          <a-radio-group v-model="form.type" :disabled="editing">
            <a-radio value="dynamic">动态组（CEL）</a-radio>
            <a-radio value="static">静态组</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item v-if="form.type==='dynamic'" label="CEL 表达式">
          <a-textarea v-model="form.rule" :auto-size="{minRows:2}" placeholder='user.department == "研发" && user.mfa_enrolled' />
          <div style="font-size:11.5px;color:var(--ink-3);margin-top:6px">
            可用变量：user.department / user.org_path / user.mfa_enrolled / device.posture.* — 与策略条件同一函数库
          </div>
        </a-form-item>
        <a-form-item label="说明">
          <a-textarea v-model="form.note" :auto-size="{minRows:2}" placeholder="该组用途 / 维护约定" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { users as mockUsers } from '@/mock';

interface Group { name: string; type: 'dynamic' | 'static'; members: number; refs: number; rule?: string; note: string; sample: string[]; refPolicies: string[]; static?: string[]; }
const fallback: Group[] = [
  { name: '研发-动态', type: 'dynamic', members: 386, refs: 1, rule: 'user.org_path.startsWith("/acme/研发中心")\n  && user.mfa_enrolled', note: '组织树研发子树 + 已注册 MFA；入职当天自动入组，吊销 MFA 即时出组（≤10s 传播）。', sample: ['张伟', '陈静', '+384'], refPolicies: ['pol-rd-database'] },
  { name: '全体员工', type: 'dynamic', members: 1496, refs: 1, rule: 'user.source != "local-service"', note: '排除服务账号的全员组。', sample: ['张伟', '李娜', '王强', '+1493'], refPolicies: ['pol-oa-all'] },
  { name: 'BYOD', type: 'dynamic', members: 217, refs: 1, rule: 'device.ownership == "personal"', note: '设备归属为个人的会话自动落入本组（设备维度谓词，DP-12 同 App 差异化管控）。', sample: ['陈静(Pad-1180)', '+216'], refPolicies: ['pol-finance-deny-byod'] },
  { name: '运维', type: 'static', members: 24, refs: 1, note: '手工维护的特权组；变更需双人复核（审计链记录 actor + approver）。', sample: [], refPolicies: ['pol-ops-ssh'], static: ['王强', '李运维', '赵巡检'] },
  { name: '财务', type: 'static', members: 41, refs: 1, note: '财务中心全员 + 外聘审计 2 人。', sample: [], refPolicies: ['pol-finance-fin'], static: ['李娜', '外聘审计 A', '外聘审计 B'] }
];

/* 用户组来自控制面 /ctl/api/coll?kind=group（持久化），不可达时降级 mock */
const groups = ref<Group[]>([...fallback]);
const live = ref(false);
const sel = ref<Group | null>(groups.value[0]);
async function loadGroups() {
  try {
    const r = await fetch('/ctl/api/coll?kind=group');
    if (!r.ok) return;
    const docs = await r.json();
    groups.value = docs.map((g: any) => ({ refs: 1, members: 0, sample: [], refPolicies: [], note: '', ...g }));
    live.value = true;
    if (groups.value.length) sel.value = groups.value[0];
  } catch { live.value = false; }
}
onMounted(loadGroups);

const userOpts = computed(() => mockUsers
  .filter((u) => !(sel.value?.static || []).includes(u.name))
  .map((u) => ({ label: `${u.name}（${u.account}）`, value: u.name })));

/* —— 新建 / 编辑 —— */
const show = ref(false);
const editing = ref(false);
const form = reactive({ name: '', type: 'dynamic', rule: '', note: '' });
function openCreate() { editing.value = false; Object.assign(form, { name: '', type: 'dynamic', rule: '', note: '' }); show.value = true; }
function openEdit() {
  if (!sel.value) return;
  editing.value = true;
  Object.assign(form, { name: sel.value.name, type: sel.value.type, rule: sel.value.rule ?? '', note: sel.value.note ?? '' });
  show.value = true;
}
async function submit() {
  if (!form.name) return Message.warning('请填写组名');
  if (editing.value && sel.value) {
    sel.value.rule = form.type === 'dynamic' ? form.rule : undefined;
    sel.value.note = form.note;
    await persist(sel.value);
    Message.success(`用户组「${form.name}」已更新${live.value ? ' · 已持久化' : ''}`);
    show.value = false;
    return;
  }
  const g: Group = { name: form.name, type: form.type as any, members: 0, refs: 0, rule: form.rule || undefined, note: form.note || (form.type === 'dynamic' ? '新建动态组：下一轮求值周期（≤60s）内完成首次成员计算。' : '新建静态组：暂无成员。'), sample: [], refPolicies: [], static: form.type === 'static' ? [] : undefined };
  if (live.value && !(await persist(g))) return Message.error('创建失败');
  if (!live.value) groups.value.push(g);
  else await loadGroups();
  sel.value = groups.value.find((x) => x.name === g.name) ?? g;
  Message.success(`用户组「${form.name}」已创建${live.value ? ' · 已持久化' : ''}`);
  show.value = false;
}

async function persist(g: Group) {
  if (!live.value) return true;
  try {
    const r = await fetch('/ctl/api/coll?kind=group', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: g.name, doc: g }) });
    return r.ok;
  } catch { return false; }
}

/* —— 静态成员管理 —— */
const addPick = ref<string>();
async function addMember() {
  if (!sel.value || !addPick.value) return;
  (sel.value.static ??= []).push(addPick.value);
  sel.value.members = sel.value.static.length;
  await persist(sel.value);
  Message.success(`已将「${addPick.value}」加入${sel.value.name}`);
  addPick.value = undefined;
}
async function removeMember(m: string) {
  if (!sel.value) return;
  sel.value.static = (sel.value.static || []).filter((x) => x !== m);
  sel.value.members = sel.value.static.length;
  await persist(sel.value);
  Message.info(`已移除「${m}」`);
}

/* —— 删除 —— */
function del() {
  if (!sel.value) return;
  const g = sel.value;
  if (g.refs > 0) {
    Modal.warning({ title: '无法删除', content: `用户组「${g.name}」被 ${g.refs} 条策略引用，请先在策略中心解除引用再删除（防止策略悬空）。`, okText: '我知道了' });
    return;
  }
  Modal.warning({
    title: `删除用户组「${g.name}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: '删除后该组不再参与任何求值。此操作进入审计链。',
    onOk: async () => {
      if (live.value) {
        try {
          const r = await fetch(`/ctl/api/coll?kind=group&key=${encodeURIComponent(g.name)}`, { method: 'DELETE' });
          if (!r.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      groups.value = groups.value.filter((x) => x.name !== g.name);
      sel.value = groups.value[0] ?? null;
      Message.success(`用户组「${g.name}」已删除`);
    }
  });
}
</script>

<style scoped>
:deep(.row-on) { background: var(--accent-soft) !important; }
:deep(.arco-table-tr) { cursor: pointer; }
.grp-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 6px; }
.grp-label { font-size: 11.5px; font-weight: 600; color: var(--ink-3); margin: 14px 0 6px; }
.grp-cel { margin: 0; background: var(--surface-2); border: 1px solid var(--line); border-radius: var(--r-md); padding: 10px 12px; font-size: 12px; color: var(--accent-2); white-space: pre-wrap; }
.grp-note { font-size: 12.5px; color: var(--ink-2); line-height: 1.6; }
.grp-sample, .grp-static { display: flex; flex-wrap: wrap; }
.grp-addrow { display: flex; gap: 8px; align-items: center; margin-top: 8px; }
.grp-refs { display: flex; flex-direction: column; gap: 4px; }
.grp-ref { font-size: 12px; color: var(--accent-2); text-decoration: none; }
.grp-ref:hover { text-decoration: underline; }
.grp-dim { font-size: 12px; color: var(--ink-3); }
</style>
