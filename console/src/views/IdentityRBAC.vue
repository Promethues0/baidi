<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">细粒度 RBAC<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">在三员（系统 / 安全 / 审计管理员）之上叠加细粒度权限点与数据范围 · 权限沿管理组上级链取交集</div>
      </div>
      <a-button v-if="tab !== 'overview'" type="primary" @click="openCreate">
        <template #icon><icon-plus /></template>{{ tab === 'group' ? '新建管理组' : '新建账号绑定' }}
      </a-button>
    </div>

    <!-- 说明文案：未绑定管理组的账号退回三员角色（向后兼容） -->
    <div class="rb-tip">
      <span class="rb-tip__ic">ⓘ</span>
      <span>未绑定管理组的管理账号<b>退回三员角色</b>（向后兼容）。绑定管理组后，账号的有效权限 = 本组权限点 ∩ 上级链各组权限点（<b>沿上级链取交集</b>）；数据范围未开「全范围」时受组织树限制。</span>
    </div>

    <a-tabs v-model:active-key="tab" type="rounded">
      <!-- Tab1：管理组 -->
      <a-tab-pane key="group" title="管理组">
        <div class="zl-card">
          <a-table :data="groups" :pagination="false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="管理组名称" data-index="name" :width="200">
                <template #cell="{ record }">
                  <span style="font-weight:600;color:var(--ink)">{{ record.name }}</span>
                  <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
                </template>
              </a-table-column>
              <a-table-column title="上级组" :width="160">
                <template #cell="{ record }">
                  <span style="font-size:12px;color:var(--ink-2)">{{ record.parent ? groupName(record.parent) : '—（顶级）' }}</span>
                </template>
              </a-table-column>
              <a-table-column title="权限点" align="center" :width="100">
                <template #cell="{ record }">
                  <span class="data" style="font-weight:650;color:var(--accent-2)">{{ record.perms.length }}</span>
                  <span style="font-size:11px;color:var(--ink-3)"> 项</span>
                </template>
              </a-table-column>
              <a-table-column title="数据范围" align="center" :width="120">
                <template #cell="{ record }">
                  <span class="zl-badge" :class="record.scopeAll ? 'zl-badge--accent' : 'zl-badge--idle'">{{ record.scopeAll ? '全范围' : '受限' }}</span>
                  <div v-if="!record.scopeAll && record.dataScope?.Orgs?.length" class="data" style="font-size:10.5px;color:var(--ink-3);margin-top:2px">{{ record.dataScope.Orgs.length }} 个组织</div>
                </template>
              </a-table-column>
              <a-table-column title="启用" align="center" :width="80">
                <template #cell="{ record }">
                  <a-switch v-model="record.enabled" size="small" @change="toggleGroup(record)" />
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
              <div class="rb-empty">
                <div class="rb-empty__big">未配置管理组 · 全部账号退回三员角色（旧行为）</div>
                <div class="rb-empty__sub">没有管理组时，管理账号按系统 / 安全 / 审计三员既有职责工作。需要细粒度授权（按权限点 + 数据范围）时再新建管理组。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>

      <!-- Tab2：账号绑定 -->
      <a-tab-pane key="binding" title="账号绑定">
        <div class="zl-card">
          <a-table :data="bindings" :pagination="false" :bordered="false" row-key="key">
            <template #columns>
              <a-table-column title="管理账号" data-index="account" :width="240">
                <template #cell="{ record }">
                  <span class="data" style="font-weight:600;color:var(--ink)">{{ record.account }}</span>
                  <div class="data" style="font-size:11px;color:var(--ink-3);margin-top:2px">{{ record.key }}</div>
                </template>
              </a-table-column>
              <a-table-column title="绑定管理组">
                <template #cell="{ record }">
                  <span v-if="record.group" class="zl-badge zl-badge--accent">{{ groupName(record.group) }}</span>
                  <span v-else style="font-size:12px;color:var(--ink-3)">未绑定 · 退回三员</span>
                </template>
              </a-table-column>
              <a-table-column title="启用" align="center" :width="80">
                <template #cell="{ record }">
                  <a-switch v-model="record.enabled" size="small" @change="toggleBinding(record)" />
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
              <div class="rb-empty">
                <div class="rb-empty__big">未配置账号绑定 · 全部账号退回三员角色（旧行为）</div>
                <div class="rb-empty__sub">绑定把管理账号与管理组关联起来；未绑定的账号继续按三员既有职责工作（向后兼容）。</div>
              </div>
            </template>
          </a-table>
        </div>
      </a-tab-pane>

      <!-- Tab3：权限速览 -->
      <a-tab-pane key="overview" title="权限速览">
        <div class="rb-tip" style="margin-bottom:16px">
          <span class="rb-tip__ic">ⓘ</span>
          <span>权限点字典全集（按模块分组）{{ live ? '来自控制面 /ctl/api/admin/perms' : '为前端默认 mock' }}。授予管理组的权限点不能超出此字典；未绑定管理组的账号<b>退回三员角色</b>（向后兼容）。</span>
        </div>
        <div class="zl-grid rb-modules">
          <div v-for="m in moduleGroups" :key="m.key" class="zl-card zl-card__pad">
            <div class="zl-card__title">{{ m.label }}
              <span class="rb-mod__count">{{ m.perms.length }} 项</span>
            </div>
            <div class="rb-mod__sub">{{ m.desc }}</div>
            <div class="rb-perms">
              <div v-for="p in m.perms" :key="p.value" class="rb-perm">
                <span class="rb-perm__code data">{{ p.value }}</span>
                <span class="rb-perm__label">{{ p.label }}</span>
              </div>
            </div>
          </div>
        </div>
        <div v-if="!dict.length" class="rb-empty" style="margin-top:16px">
          <div class="rb-empty__big">权限点字典为空</div>
          <div class="rb-empty__sub">控制面未返回任何权限点；当前不可对管理组授予细粒度权限，所有账号退回三员角色。</div>
        </div>
      </a-tab-pane>
    </a-tabs>

    <!-- 管理组 编辑 / 新建 -->
    <a-modal v-if="tab === 'group'" v-model:visible="show" :title="editing ? '编辑管理组' : '新建管理组'" width="640px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="gForm" layout="vertical">
        <a-grid :cols="2" :col-gap="16">
          <a-grid-item>
            <a-form-item label="管理组标识（key）" required>
              <a-input v-model="gForm.key" placeholder="例如：sec-ops-east" :disabled="editing" />
            </a-form-item>
          </a-grid-item>
          <a-grid-item>
            <a-form-item label="管理组名称" required>
              <a-input v-model="gForm.name" placeholder="例如：华东安全运维组" />
            </a-form-item>
          </a-grid-item>
        </a-grid>

        <a-form-item label="上级组（parent）">
          <a-select v-model="gForm.parent" placeholder="不选 = 顶级组" allow-clear>
            <a-option v-for="g in parentCandidates" :key="g.key" :value="g.key">{{ g.name }}</a-option>
          </a-select>
          <div class="rb-hint">有效权限沿上级链取交集：本组权限点不会超出上级组实际拥有的权限。不选即为顶级组。</div>
        </a-form-item>

        <a-form-item label="权限点（perms）">
          <a-checkbox-group v-model="gForm.perms" class="rb-cbgroup">
            <a-checkbox v-for="p in dict" :key="p.value" :value="p.value">
              <span class="rb-cb__label">{{ p.label }}</span>
              <span class="rb-cb__code data">{{ p.value }}</span>
            </a-checkbox>
          </a-checkbox-group>
          <div v-if="!dict.length" class="rb-hint">权限点字典为空，无法授予细粒度权限。</div>
          <div class="rb-hint">已选 {{ gForm.perms.length }} / {{ dict.length }} 项；最终生效以上级链交集为准。</div>
        </a-form-item>

        <a-form-item label="数据范围（scopeAll）">
          <a-switch v-model="gForm.scopeAll" />
          <span class="rb-hint" style="margin-left:10px">开启 = 全范围（可管理全部组织）；关闭 = 受限于下方指定组织树。</span>
        </a-form-item>

        <a-form-item v-if="!gForm.scopeAll" label="受限组织（dataScope.Orgs）">
          <a-input-tag v-model="gForm.dataScope.Orgs" placeholder="输入组织名 / 组织 ID 回车添加" allow-clear />
          <div class="rb-hint">仅可管理列出的组织及其子树；留空 = 无任何数据范围（不能管理任何组织）。</div>
        </a-form-item>

        <a-form-item label="启用本管理组">
          <a-switch v-model="gForm.enabled" />
          <span class="rb-hint" style="margin-left:10px">关闭 = 该组及其绑定账号的细粒度权限不生效（账号退回三员角色）。</span>
        </a-form-item>
      </a-form>
      <div class="rb-modal-note">提示：管理组调整 ≤60s 生效 · 写审计。权限点不能超出字典；删除或停用上级组会影响整条下级链的交集结果。</div>
    </a-modal>

    <!-- 账号绑定 编辑 / 新建 -->
    <a-modal v-else-if="tab === 'binding'" v-model:visible="show" :title="editing ? '编辑账号绑定' : '新建账号绑定'" width="520px" @ok="submit" :ok-text="editing ? '保存' : '创建'">
      <a-form :model="bForm" layout="vertical">
        <a-form-item label="绑定标识（key）" required>
          <a-input v-model="bForm.key" placeholder="例如：bind-wang-lei" :disabled="editing" />
        </a-form-item>
        <a-form-item label="管理账号（account）" required>
          <a-input v-model="bForm.account" placeholder="例如：wang.lei@corp" />
        </a-form-item>
        <a-form-item label="绑定管理组（group）">
          <a-select v-model="bForm.group" placeholder="不选 = 退回三员角色" allow-clear>
            <a-option v-for="g in groups" :key="g.key" :value="g.key">{{ g.name }}</a-option>
          </a-select>
          <div class="rb-hint">绑定后账号按所选管理组的权限点 + 数据范围授权；不选即退回三员角色（向后兼容）。</div>
        </a-form-item>
        <a-form-item label="启用本绑定">
          <a-switch v-model="bForm.enabled" />
          <span class="rb-hint" style="margin-left:10px">关闭 = 绑定不生效，账号退回三员角色。</span>
        </a-form-item>
      </a-form>
      <div class="rb-modal-note">提示：账号绑定调整 ≤60s 生效 · 写审计。同一账号建议仅保留一条有效绑定。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';

/* —— 类型 —— */
// 权限点字典项（来自 /ctl/api/admin/perms 的 dictionary）。
interface PermItem { value: string; label: string }
// 管理组文档（kind=admingroup，每条一文档）。
interface AdminGroup {
  key: string;
  name: string;
  parent: string;            // 上级组 key；'' = 顶级
  perms: string[];           // 授予的权限点（须在字典内）
  scopeAll: boolean;         // true = 全数据范围
  dataScope: { Orgs: string[] };
  enabled: boolean;
}
// 账号绑定文档（kind=adminbinding，每条一文档）。
interface AdminBinding {
  key: string;
  account: string;
  group: string;             // 绑定管理组 key；'' = 退回三员
  enabled: boolean;
}

/* —— 权限点中文标注（字典缺 label 时回落到此表，再回落 value 本身） —— */
const PERM_LABELS: Record<string, string> = {
  'system.read': '系统读', 'system.write': '系统写',
  'business.read': '业务读', 'business.write': '业务写',
  'monitor.read': '监控读', 'monitor.dashboard': '监控大屏',
  'audit.read': '审计读', 'audit.export': '审计导出',
  'approval.decide': '审批决策', 'approval.read': '审批查看',
  'identity.manage': '身份管理', 'policy.manage': '策略管理',
  'device.manage': '终端设备管理', 'gateway.manage': '网关管理'
};
const permLabel = (value: string, raw?: string) => raw || PERM_LABELS[value] || value;

/* —— 权限点模块分组（速览页按 system/business/monitor/audit 等模块分桶） —— */
const MODULES: { key: string; label: string; desc: string }[] = [
  { key: 'system', label: '系统管理', desc: '系统配置、网关与基础设施相关权限点（系统管理员域）' },
  { key: 'business', label: '业务管理', desc: '身份、策略、设备等业务对象的读写权限点（安全管理员域）' },
  { key: 'monitor', label: '监控运行', desc: '监控大屏与运行态只读权限点' },
  { key: 'audit', label: '审计合规', desc: '审计读取、导出与审批决策权限点（审计管理员域）' },
  { key: 'other', label: '其它', desc: '未归入上述模块的权限点' }
];
// 权限点所属模块：按 value 的前缀（点号前）映射。
function moduleOf(value: string): string {
  const prefix = value.split('.')[0];
  if (['system', 'gateway'].includes(prefix)) return 'system';
  if (['business', 'identity', 'policy', 'device'].includes(prefix)) return 'business';
  if (prefix === 'monitor') return 'monitor';
  if (['audit', 'approval'].includes(prefix)) return 'audit';
  return 'other';
}

/* —— 前端默认（mock，加载后端后覆盖；与后端 seed 同形） —— */
// 权限点字典 mock（覆盖三员域典型权限点）。
const dictFallback: PermItem[] = [
  { value: 'system.read', label: '系统读' }, { value: 'system.write', label: '系统写' },
  { value: 'gateway.manage', label: '网关管理' },
  { value: 'business.read', label: '业务读' }, { value: 'business.write', label: '业务写' },
  { value: 'identity.manage', label: '身份管理' }, { value: 'policy.manage', label: '策略管理' },
  { value: 'device.manage', label: '终端设备管理' },
  { value: 'monitor.read', label: '监控读' }, { value: 'monitor.dashboard', label: '监控大屏' },
  { value: 'audit.read', label: '审计读' }, { value: 'audit.export', label: '审计导出' },
  { value: 'approval.decide', label: '审批决策' }
];
const groupFallback: AdminGroup[] = [
  { key: 'sec-admin', name: '安全管理组', parent: '', perms: ['business.read', 'business.write', 'identity.manage', 'policy.manage', 'device.manage', 'monitor.read'], scopeAll: true, dataScope: { Orgs: [] }, enabled: true },
  { key: 'sec-ops-east', name: '华东安全运维组', parent: 'sec-admin', perms: ['business.read', 'device.manage', 'monitor.read'], scopeAll: false, dataScope: { Orgs: ['华东大区', '上海研发中心'] }, enabled: true },
  { key: 'audit-admin', name: '审计管理组', parent: '', perms: ['audit.read', 'audit.export', 'approval.decide'], scopeAll: true, dataScope: { Orgs: [] }, enabled: true }
];
const bindingFallback: AdminBinding[] = [
  { key: 'bind-zhang-wei', account: 'zhang.wei@corp', group: 'sec-admin', enabled: true },
  { key: 'bind-wang-lei', account: 'wang.lei@corp', group: 'sec-ops-east', enabled: true },
  { key: 'bind-li-fang', account: 'li.fang@corp', group: 'audit-admin', enabled: true }
];

const dict = ref<PermItem[]>(dictFallback.map((p) => ({ ...p })));
const groups = ref<AdminGroup[]>(groupFallback.map((g) => ({ ...g, perms: [...g.perms], dataScope: { Orgs: [...g.dataScope.Orgs] } })));
const bindings = ref<AdminBinding[]>(bindingFallback.map((b) => ({ key: b.key, account: b.account, group: b.group, enabled: b.enabled })));

const tab = ref<'group' | 'binding' | 'overview'>('group');
const liveGroup = ref(false);
const liveBinding = ref(false);
const livePerms = ref(false);
// 页头徽标：任一来源持久化即视为 live。
const live = computed(() => liveGroup.value || liveBinding.value || livePerms.value);

/* —— 速览页：字典按模块分组，仅渲染有权限点的模块 —— */
const moduleGroups = computed(() => {
  return MODULES
    .map((m) => ({ ...m, perms: dict.value.filter((p) => moduleOf(p.value) === m.key) }))
    .filter((m) => m.perms.length > 0);
});
// 组名查找（上级组 / 绑定组展示）。
const groupName = (k: string) => groups.value.find((g) => g.key === k)?.name ?? k;
// 上级组候选：排除自身（编辑时不能选自己为上级）。
const parentCandidates = computed(() => groups.value.filter((g) => g.key !== gForm.key));

/* —— 加载（三来源各自探活；失败保留前端默认 mock 降级） —— */
async function loadPerms() {
  try {
    const r = await fetch('/ctl/api/admin/perms');
    if (!r.ok) return;
    const data = await r.json();
    const raw = Array.isArray(data?.dictionary) ? data.dictionary : [];
    dict.value = raw.map((d: any) =>
      typeof d === 'string'
        ? { value: d, label: permLabel(d) }
        : { value: d.value ?? d.key ?? '', label: permLabel(d.value ?? d.key ?? '', d.label) }
    ).filter((p: PermItem) => p.value);
    livePerms.value = true;
  } catch { livePerms.value = false; }
}
async function loadGroups() {
  try {
    const r = await fetch('/ctl/api/coll?kind=admingroup');
    if (!r.ok) return;
    const docs = await r.json();
    groups.value = docs.map((d: any) => ({
      key: d.key ?? d.k,
      name: d.name ?? '',
      parent: typeof d.parent === 'string' ? d.parent : '',
      perms: Array.isArray(d.perms) ? d.perms : [],
      scopeAll: typeof d.scopeAll === 'boolean' ? d.scopeAll : false,
      dataScope: { Orgs: Array.isArray(d.dataScope?.Orgs) ? d.dataScope.Orgs : [] },
      enabled: typeof d.enabled === 'boolean' ? d.enabled : true
    }));
    liveGroup.value = true;
  } catch { liveGroup.value = false; }
}
async function loadBindings() {
  try {
    const r = await fetch('/ctl/api/coll?kind=adminbinding');
    if (!r.ok) return;
    const docs = await r.json();
    bindings.value = docs.map((d: any) => ({
      key: d.key ?? d.k,
      account: d.account ?? '',
      group: typeof d.group === 'string' ? d.group : '',
      enabled: typeof d.enabled === 'boolean' ? d.enabled : true
    }));
    liveBinding.value = true;
  } catch { liveBinding.value = false; }
}
onMounted(() => { loadPerms(); loadGroups(); loadBindings(); });

/* —— 持久化（POST 单条文档，后端写审计） —— */
async function persistGroup(g: AdminGroup) {
  if (!liveGroup.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=admingroup', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: g.key, doc: { ...g, perms: [...g.perms], dataScope: { Orgs: [...g.dataScope.Orgs] } } })
    });
    return res.ok;
  } catch { return false; }
}
async function persistBinding(b: AdminBinding) {
  if (!liveBinding.value) return true;
  try {
    const res = await fetch('/ctl/api/coll?kind=adminbinding', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: b.key, doc: { ...b } })
    });
    return res.ok;
  } catch { return false; }
}

/* —— 行内启用开关：即时 toggle，写失败回滚 —— */
async function toggleGroup(g: AdminGroup) {
  const ok = await persistGroup(g);
  if (!ok && liveGroup.value) { g.enabled = !g.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`管理组「${g.name}」已${g.enabled ? '启用' : '停用'}${liveGroup.value ? ' · 已持久化' : ''}`);
}
async function toggleBinding(b: AdminBinding) {
  const ok = await persistBinding(b);
  if (!ok && liveBinding.value) { b.enabled = !b.enabled; return Message.error('操作失败，已回滚'); }
  Message.info(`账号「${b.account}」绑定已${b.enabled ? '启用' : '停用'}${liveBinding.value ? ' · 已持久化' : ''}`);
}

/* —— 新建 / 编辑 —— */
const show = ref(false);
const editing = ref(false);
const gForm = reactive<AdminGroup>({ key: '', name: '', parent: '', perms: [], scopeAll: false, dataScope: { Orgs: [] }, enabled: true });
const bForm = reactive<AdminBinding>({ key: '', account: '', group: '', enabled: true });

function resetForms() {
  Object.assign(gForm, { key: '', name: '', parent: '', scopeAll: false, enabled: true });
  gForm.perms = [];
  gForm.dataScope = { Orgs: [] };
  Object.assign(bForm, { key: '', account: '', group: '', enabled: true });
}
function openCreate() { editing.value = false; resetForms(); show.value = true; }
function openEdit(r: any) {
  editing.value = true;
  if (tab.value === 'group') {
    // 克隆，避免引用污染列表行。
    const clone: AdminGroup = JSON.parse(JSON.stringify(r));
    Object.assign(gForm, clone);
    gForm.perms = [...(clone.perms ?? [])];
    gForm.dataScope = { Orgs: [...(clone.dataScope?.Orgs ?? [])] };
  } else {
    Object.assign(bForm, JSON.parse(JSON.stringify(r)));
  }
  show.value = true;
}

async function submit() {
  if (tab.value === 'group') {
    if (!gForm.key) return Message.warning('请填写管理组标识（key）');
    if (!gForm.name) return Message.warning('请填写管理组名称');
    if (!editing.value && groups.value.some((x) => x.key === gForm.key)) return Message.warning(`管理组标识「${gForm.key}」已存在`);
    const doc: AdminGroup = { key: gForm.key, name: gForm.name, parent: gForm.parent || '', perms: [...gForm.perms], scopeAll: gForm.scopeAll, dataScope: { Orgs: gForm.scopeAll ? [] : [...gForm.dataScope.Orgs] }, enabled: gForm.enabled };
    if (editing.value) {
      const i = groups.value.findIndex((x) => x.key === doc.key);
      if (liveGroup.value && !(await persistGroup(doc))) return Message.error('保存失败');
      if (i >= 0) groups.value[i] = doc;
      Message.success(`管理组「${doc.name}」已更新${liveGroup.value ? ' · 已持久化' : '（mock）'}`);
    } else {
      if (liveGroup.value && !(await persistGroup(doc))) return Message.error('创建失败');
      groups.value.push(doc);
      Message.success(`管理组「${doc.name}」已创建${liveGroup.value ? ' · 已持久化' : '（mock）'}`);
    }
  } else {
    if (!bForm.key) return Message.warning('请填写绑定标识（key）');
    if (!bForm.account) return Message.warning('请填写管理账号（account）');
    if (!editing.value && bindings.value.some((x) => x.key === bForm.key)) return Message.warning(`绑定标识「${bForm.key}」已存在`);
    const doc: AdminBinding = { key: bForm.key, account: bForm.account, group: bForm.group || '', enabled: bForm.enabled };
    if (editing.value) {
      const i = bindings.value.findIndex((x) => x.key === doc.key);
      if (liveBinding.value && !(await persistBinding(doc))) return Message.error('保存失败');
      if (i >= 0) bindings.value[i] = doc;
      Message.success(`账号「${doc.account}」绑定已更新${liveBinding.value ? ' · 已持久化' : '（mock）'}`);
    } else {
      if (liveBinding.value && !(await persistBinding(doc))) return Message.error('创建失败');
      bindings.value.push(doc);
      Message.success(`账号「${doc.account}」绑定已创建${liveBinding.value ? ' · 已持久化' : '（mock）'}`);
    }
  }
  show.value = false;
}

/* —— 删除（二次确认 + DELETE） —— */
function del(r: any) {
  const isGroup = tab.value === 'group';
  const noun = isGroup ? '管理组' : '账号绑定';
  const label = isGroup ? r.name : r.account;
  Modal.warning({
    title: `删除${noun}「${label}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: isGroup
      ? '删除后该组的细粒度权限失效，其下级组的上级链交集会随之变化，绑定到该组的账号将退回三员角色。此操作进入审计链。'
      : '删除后该账号不再绑定管理组，退回三员角色（向后兼容）。此操作进入审计链。',
    onOk: async () => {
      const kind = isGroup ? 'admingroup' : 'adminbinding';
      const isLive = isGroup ? liveGroup.value : liveBinding.value;
      if (isLive) {
        try {
          const res = await fetch(`/ctl/api/coll?kind=${kind}&key=${encodeURIComponent(r.key)}`, { method: 'DELETE' });
          if (!res.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      if (isGroup) groups.value = groups.value.filter((x) => x.key !== r.key);
      else bindings.value = bindings.value.filter((x) => x.key !== r.key);
      Message.success(`${noun}「${label}」已删除${isLive ? ' · 已持久化' : ''}`);
    }
  });
}
</script>

<style scoped>
:deep(.arco-table-tr) { cursor: default; }

/* 顶部说明条 */
.rb-tip { display: flex; align-items: flex-start; gap: 10px; background: var(--accent-soft); border: 1px solid var(--line); border-radius: var(--r-md); padding: 11px 14px; margin-bottom: 16px; font-size: 12.5px; color: var(--ink-2); line-height: 1.6; }
.rb-tip__ic { color: var(--accent-2); font-weight: 700; flex-shrink: 0; }
.rb-tip b { color: var(--accent-2); font-weight: 700; }

/* 空态 */
.rb-empty { padding: 30px 16px; text-align: center; }
.rb-empty__big { font-size: 14px; font-weight: 650; color: var(--ink-2); }
.rb-empty__sub { font-size: 12px; color: var(--ink-3); margin-top: 8px; line-height: 1.6; max-width: 600px; margin-left: auto; margin-right: auto; }

/* 速览：模块卡网格 */
.rb-modules { grid-template-columns: repeat(2, 1fr); align-items: start; }
.rb-mod__count { font-size: 11px; font-weight: 500; color: var(--ink-3); margin-left: 8px; }
.rb-mod__sub { font-size: 11.5px; color: var(--ink-3); margin: 4px 0 12px; line-height: 1.5; }
.rb-perms { display: flex; flex-direction: column; }
.rb-perm { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 0; }
.rb-perm + .rb-perm { border-top: 1px solid var(--line); }
.rb-perm__code { font-size: 12px; color: var(--accent-2); font-weight: 600; }
.rb-perm__label { font-size: 12.5px; color: var(--ink-2); }

/* 权限点多选 */
.rb-cbgroup { display: grid; grid-template-columns: repeat(2, 1fr); gap: 4px 16px; }
.rb-cb__label { font-size: 13px; color: var(--ink); }
.rb-cb__code { font-size: 11px; color: var(--ink-3); margin-left: 6px; }

.rb-hint { font-size: 11px; color: var(--ink-3); margin-top: 6px; line-height: 1.5; }
.rb-modal-note { font-size: 11.5px; color: var(--ink-3); line-height: 1.6; margin-top: 4px; }
</style>
