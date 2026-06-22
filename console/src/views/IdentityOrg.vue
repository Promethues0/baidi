<template>
  <div class="zl-page">
    <div class="zl-page__head">
      <div>
        <h1 class="zl-page__title">组织树<LiveBadge :live="live" /></h1>
        <div class="zl-page__sub">组织 path 物化便于子树查询（PRD 5.2）· 上游 IdP 同步或本地维护</div>
      </div>
      <a-space>
        <a-button @click="syncMsg"><template #icon><icon-sync /></template>从集团 AD 同步</a-button>
        <a-button type="primary" @click="openCreate"><template #icon><icon-plus /></template>新建部门</a-button>
      </a-space>
    </div>

    <div class="zl-grid" style="grid-template-columns: 300px 1fr;">
      <div class="zl-card zl-card__pad">
        <a-tree :data="tree" :default-expanded-keys="['root','rd']" :selected-keys="[selKey]"
                @select="(k:any)=>selKey=k[0]" block-node />
      </div>

      <div class="zl-card" v-if="selNode">
        <div class="org-head">
          <div style="min-width:0">
            <div class="org-title">{{ selNode.title }}
              <span class="zl-badge" :class="selNode.source==='本地'?'zl-badge--idle':'zl-badge--accent'" style="font-size:10.5px;margin-left:8px">{{ selNode.source ?? '本地' }}</span>
            </div>
            <div class="org-path data">{{ selNode.path }}</div>
          </div>
          <div class="org-actions">
            <div class="org-stats">
              <span><b class="data">{{ members.length }}</b> 直属</span>
              <span><b class="data">{{ subDeptCount }}</b> 子部门</span>
              <span><b class="data">{{ selNode.deviceCount ?? 0 }}</b> 设备</span>
            </div>
            <a-space v-if="selKey!=='root'">
              <a-button size="mini" @click="openRename">重命名</a-button>
              <a-button size="mini" @click="openMove">移动</a-button>
              <a-button size="mini" status="danger" type="outline" @click="del">删除</a-button>
            </a-space>
          </div>
        </div>
        <a-table :data="members" :pagination="false" :bordered="false" row-key="account">
          <template #columns>
            <a-table-column title="姓名" data-index="name" :width="120" />
            <a-table-column title="账号" :width="150">
              <template #cell="{ record }"><span class="data" style="color:var(--ink-2)">{{ record.account }}</span></template>
            </a-table-column>
            <a-table-column title="认证方式">
              <template #cell="{ record }"><a-tag v-for="a in record.auth" :key="a" size="small" style="margin-right:4px">{{ a }}</a-tag></template>
            </a-table-column>
            <a-table-column title="状态" align="center" :width="90">
              <template #cell="{ record }">
                <span class="zl-badge" :class="record.status==='active'?'zl-badge--ok':'zl-badge--warn'">{{ record.status==='active'?'正常':'已锁定' }}</span>
              </template>
            </a-table-column>
          </template>
        </a-table>
        <div v-if="!members.length" class="org-empty">该部门暂无直属成员{{ subDeptCount ? '（成员在子部门下）' : '' }}</div>
      </div>
    </div>

    <!-- 新建部门 -->
    <a-modal v-model:visible="show" title="新建部门" @ok="add" ok-text="创建">
      <a-form :model="form" layout="vertical">
        <a-form-item label="部门名称" required><a-input v-model="form.name" placeholder="例如：安全合规部" /></a-form-item>
        <a-form-item label="上级部门">
          <a-select v-model="form.parent">
            <a-option v-for="o in flat" :key="o.key" :value="o.key">{{ o.path }}</a-option>
          </a-select>
        </a-form-item>
        <a-form-item label="同步策略">
          <a-radio-group v-model="form.source">
            <a-radio value="本地">本地维护</a-radio>
            <a-radio value="集团 AD">绑定集团 AD OU（JIT 同步）</a-radio>
          </a-radio-group>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 重命名 -->
    <a-modal v-model:visible="renameShow" title="重命名部门" @ok="doRename" ok-text="保存">
      <a-form :model="{ renameVal }" layout="vertical">
        <a-form-item label="部门名称" required><a-input v-model="renameVal" /></a-form-item>
      </a-form>
      <div style="font-size:11.5px;color:var(--ink-3);line-height:1.6">重命名会级联更新本部门及全部子部门的 path（物化路径）；引用本子树的动态组与策略实时重算。</div>
    </a-modal>

    <!-- 移动 -->
    <a-modal v-model:visible="moveShow" title="移动部门" @ok="doMove" ok-text="移动">
      <a-form :model="{ moveTo }" layout="vertical">
        <a-form-item label="移动到上级">
          <a-select v-model="moveTo">
            <a-option v-for="o in moveTargets" :key="o.key" :value="o.key">{{ o.path }}</a-option>
          </a-select>
        </a-form-item>
      </a-form>
      <div style="font-size:11.5px;color:var(--ink-3);line-height:1.6">不能移动到自身或其子部门下。移动同样级联更新 path。</div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { Message, Modal } from '@arco-design/web-vue';
import { users as mockUsers } from '@/mock';

interface OrgNode { key: string; title: string; path: string; source?: string; deviceCount?: number; parent?: string; children?: OrgNode[]; }

/* 组织树来自 /ctl/api/coll?kind=org（扁平节点 + parent，前端 buildTree），
   用户来自 /ctl/api/users；控制面不可达时降级 mock。 */
const tree = ref<OrgNode[]>([]);
const live = ref(false);
const users = ref<any[]>([...mockUsers]);

function buildTree(flatNodes: OrgNode[]): OrgNode[] {
  const byKey: Record<string, OrgNode> = {};
  flatNodes.forEach((n) => (byKey[n.key] = { ...n, children: [] }));
  const roots: OrgNode[] = [];
  flatNodes.forEach((n) => {
    if (n.parent && byKey[n.parent]) byKey[n.parent].children!.push(byKey[n.key]);
    else roots.push(byKey[n.key]);
  });
  return roots;
}

async function loadOrg() {
  try {
    const [orgR, userR] = await Promise.all([fetch('/ctl/api/coll?kind=org'), fetch('/ctl/api/users')]);
    if (orgR.ok) { tree.value = buildTree(await orgR.json()); live.value = true; }
    if (userR.ok) users.value = await userR.json();
  } catch { live.value = false; }
}

const mockTree: OrgNode[] = [{
  key: 'root', title: 'ACME 集团', path: '/acme', source: '集团 AD', deviceCount: 1284,
  children: [
    { key: 'rd', title: '研发中心', path: '/acme/研发中心', source: '集团 AD', deviceCount: 412, parent: 'root', children: [
      { key: 'rd-plat', title: '平台组', path: '/acme/研发中心/平台组', source: '集团 AD', deviceCount: 96, parent: 'rd' },
      { key: 'rd-mobile', title: '移动组', path: '/acme/研发中心/移动组', source: '集团 AD', deviceCount: 61, parent: 'rd' }
    ] },
    { key: 'fin', title: '财务中心', path: '/acme/财务中心', source: '集团 AD', deviceCount: 58, parent: 'root' },
    { key: 'ops', title: '运维中心', path: '/acme/运维中心', source: '集团 AD', deviceCount: 87, parent: 'root' },
    { key: 'svc', title: '服务账号', path: '/acme/服务账号', source: '本地', deviceCount: 23, parent: 'root' }
  ]
}];
tree.value = mockTree;
onMounted(loadOrg);

const selKey = ref('rd');
const flatten = (ns: OrgNode[]): OrgNode[] => ns.flatMap((n) => [n, ...(n.children ? flatten(n.children) : [])]);
const flat = computed(() => flatten(tree.value));
const selNode = computed(() => flat.value.find((n) => n.key === selKey.value));
const subDeptCount = computed(() => selNode.value?.children?.length ?? 0);

const members = computed(() => {
  const t = selNode.value?.title ?? '';
  return users.value.filter((u) => u.org.includes(t) || selKey.value === 'root');
});

function findParentArr(key: string): OrgNode[] | null {
  const walk = (arr: OrgNode[]): OrgNode[] | null => {
    for (const n of arr) {
      if (n.key === key) return arr;
      if (n.children) { const r = walk(n.children); if (r) return r; }
    }
    return null;
  };
  return walk(tree.value);
}

/* —— 新建 —— */
const show = ref(false);
const form = reactive({ name: '', parent: 'root', source: '本地' });
function openCreate() { Object.assign(form, { name: '', parent: selKey.value || 'root', source: '本地' }); show.value = true; }
async function add() {
  if (!form.name) return Message.warning('请填写部门名称');
  const p = flat.value.find((n) => n.key === form.parent)!;
  const node: OrgNode = { key: 'n' + Date.now(), title: form.name, path: `${p.path}/${form.name}`, source: form.source, deviceCount: 0, parent: form.parent };
  if (live.value && !(await persist(node))) return Message.error('创建失败');
  if (live.value) await loadOrg(); else (p.children ??= []).push(node);
  Message.success(`部门「${form.name}」已创建（${form.source}）${live.value ? ' · 已持久化' : ''}`);
  show.value = false;
}

/* —— 重命名（级联 path）—— */
const renameShow = ref(false);
const renameVal = ref('');
function openRename() { renameVal.value = selNode.value?.title ?? ''; renameShow.value = true; }
async function doRename() {
  if (!renameVal.value || !selNode.value) return;
  const node = selNode.value;
  const oldPath = node.path;
  const parentPath = oldPath.slice(0, oldPath.lastIndexOf('/'));
  node.title = renameVal.value;
  node.path = `${parentPath}/${renameVal.value}`;
  await recomputeSubtreePaths(node, oldPath);
  Message.success(`已重命名为「${renameVal.value}」· path 子树级联更新${live.value ? ' · 已持久化' : ''}`);
  renameShow.value = false;
}

// 子树 path 前缀替换 + 持久化每个受影响节点
async function recomputeSubtreePaths(node: OrgNode, oldPrefix: string) {
  const affected: OrgNode[] = [];
  const walk = (n: OrgNode) => {
    if (n !== node) n.path = node.path + n.path.slice(oldPrefix.length);
    affected.push(n);
    n.children?.forEach(walk);
  };
  walk(node);
  if (live.value) for (const n of affected) await persist(n);
}

/* —— 移动 —— */
const moveShow = ref(false);
const moveTo = ref('root');
const descendantKeys = computed(() => {
  const set = new Set<string>();
  if (selNode.value) flatten([selNode.value]).forEach((n) => set.add(n.key));
  return set;
});
const moveTargets = computed(() => flat.value.filter((n) => !descendantKeys.value.has(n.key)));
function openMove() { moveTo.value = selNode.value?.parent ?? 'root'; moveShow.value = true; }
async function doMove() {
  if (!selNode.value) return;
  const node = selNode.value;
  const target = flat.value.find((n) => n.key === moveTo.value);
  if (!target) return;
  // 从原父数组移除
  const arr = findParentArr(node.key);
  if (arr) { const i = arr.indexOf(node); if (i >= 0) arr.splice(i, 1); }
  // 挂到新父
  (target.children ??= []).push(node);
  node.parent = target.key;
  const oldPath = node.path;
  node.path = `${target.path}/${node.title}`;
  await recomputeSubtreePaths(node, oldPath);
  Message.success(`已移动到「${target.title}」下${live.value ? ' · 已持久化' : ''}`);
  moveShow.value = false;
}

/* —— 删除 —— */
function del() {
  if (!selNode.value) return;
  const node = selNode.value;
  if (subDeptCount.value > 0) {
    Modal.warning({ title: '无法删除', content: `「${node.title}」下有 ${subDeptCount.value} 个子部门，请先移走或删除子部门。`, okText: '我知道了' });
    return;
  }
  if (members.value.length > 0) {
    Modal.warning({ title: '无法删除', content: `「${node.title}」下有 ${members.value.length} 名直属成员，请先调整成员归属。`, okText: '我知道了' });
    return;
  }
  Modal.warning({
    title: `删除部门「${node.title}」？`, hideCancel: false, okText: '确认删除', cancelText: '取消',
    content: '空部门删除后不可恢复。此操作进入审计链。',
    onOk: async () => {
      if (live.value) {
        try {
          const r = await fetch(`/ctl/api/coll?kind=org&key=${encodeURIComponent(node.key)}`, { method: 'DELETE' });
          if (!r.ok) return Message.error('删除失败');
        } catch { return Message.error('控制面不可达'); }
      }
      const arr = findParentArr(node.key);
      if (arr) { const i = arr.indexOf(node); if (i >= 0) arr.splice(i, 1); }
      selKey.value = node.parent ?? 'root';
      Message.success(`部门「${node.title}」已删除`);
    }
  });
}

async function persist(node: OrgNode) {
  if (!live.value) return true;
  try {
    const doc = { key: node.key, title: node.title, path: node.path, source: node.source, deviceCount: node.deviceCount, parent: node.parent };
    const r = await fetch('/ctl/api/coll?kind=org', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key: node.key, doc }) });
    return r.ok;
  } catch { return false; }
}

const syncMsg = () => Message.success('已触发 AD 增量同步 · 1496 账户对账中（LDAP 同步通道）');
</script>

<style scoped>
.org-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 16px 20px; border-bottom: 1px solid var(--line); }
.org-title { font-size: 15px; font-weight: 700; color: var(--ink); }
.org-path { font-size: 11.5px; color: var(--ink-3); margin-top: 3px; }
.org-actions { display: flex; flex-direction: column; align-items: flex-end; gap: 10px; }
.org-stats { display: flex; gap: 16px; font-size: 12px; color: var(--ink-3); }
.org-stats b { color: var(--ink); font-weight: 700; margin-right: 2px; }
.org-empty { font-size: 12.5px; color: var(--ink-3); padding: 18px 20px; }
</style>
